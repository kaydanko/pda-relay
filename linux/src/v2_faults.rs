//! Stage 6 test-only fault hooks for `/v2/ws` (gap G2 of `docs/STAGE6_TWO_EMULATOR_SCENARIOS.md`).
//!
//! Compiled only with the `test-faults` cargo feature and served only by a debug-loopback relay
//! (`V2Config::debug_loopback`, which already requires `127.0.0.1`); a default build has none of this code.
//! The core is unchanged: faults act on the core's [Action]s in the transport's dispatch, under the same lock.
//! Every fault is one-shot, armed over HTTP from the operator's host:
//! - `POST /v2/test/arm/drop-receipt/{root}`: the next admitted RECEIPT-kind DELIVER to `root` is never written
//!   and its queue budget is released; its sender already got ACCEPTED, so the receipt is lost after
//!   admission (T07);
//! - `POST /v2/test/arm/hold-receipt/{root}`: the next admitted RECEIPT-kind DELIVER to `root` is held (its queue
//!   budget released) until `POST /v2/test/release`, which writes every held receipt whose root is connected
//!   then (a late receipt, T08);
//! - `POST /v2/test/arm/tamper-chat/{root}`: the next CHAT-kind DELIVER to `root` has its last ciphertext byte
//!   flipped, so the device signature no longer matches (T13 "corrupted");
//! - `POST /v2/test/arm/reflect-chat/{root}`: the next CHAT-kind packet from `root` is delivered as usual and
//!   a copy also goes back to its own sender, which is not the packet's recipient (T13 "wrong recipient");
//! - `POST /v2/test/inject/unknown-sender/{root}`: one synthetic CHAT now to the live `root`, bound to its
//!   exact epoch and activation digest, from a root nobody knows, with opaque ciphertext and a structurally
//!   canonical but meaningless signature (T13 "unknown sender"); 409 when `root` is not connected;
//! - `POST /v2/test/disarm` clears armed faults (held receipts stay until released); `GET /v2/test/counters` returns aggregate counts only.
//!
//! `{root}` is the 64-hex-digit root ID (the contact screen's root fingerprint without spaces). Counters
//! hold no root, packet ID, connection or content; only armed, unconsumed faults and held receipts do.

use std::{
    fmt::Write as _,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use pda_relay_protocol::{
    v2::{decode_envelope, decode_frame, encode_frame, Direction, FrameV2, PacketKind},
    v2_relay::{Action, Authenticator, Authority, ConnKey, Entropy, RelayCore},
};

use super::V2State;

/// Armed, unconsumed faults kept at most.
pub const MAX_ARMED: usize = 16;

/// R4 error names by code (index = code).
const ERROR_NAMES: [&str; 11] = [
    "", "MALFORMED", "AUTH_FAILED", "CHALLENGE_EXPIRED", "ROOT_ALREADY_CONNECTED", "RECIPIENT_OFFLINE",
    "BACKPRESSURE", "RATE_LIMIT", "AUTHORITY_MISMATCH", "POLICY_VIOLATION", "CAPACITY",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    DropReceiptTo([u8; 32]),
    HoldReceiptTo([u8; 32]),
    TamperChatTo([u8; 32]),
    ReflectChatFrom([u8; 32]),
}

/// Aggregate counts since the relay started.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counters {
    /// Strictly decodable client FORWARD frames received, by packet kind (before any core decision).
    pub forwards_chat: u64,
    pub forwards_receipt: u64,
    /// Admitted DELIVER frames handed to a recipient connection after faults, by kind.
    pub delivers_chat: u64,
    pub delivers_receipt: u64,
    pub accepted: u64,
    /// ERROR frames sent, by R4 code (index = code; 0 unused).
    pub errors: [u64; 11],
    pub dropped_receipts: u64,
    pub held_receipts: u64,
    pub released_receipts: u64,
    pub tampered_chats: u64,
    pub reflected_chats: u64,
    pub injected_unknown_sender: u64,
}

impl Counters {
    /// `name=value` lines, one per counter, in a fixed order.
    pub fn render(&self, armed: usize, held: usize) -> String {
        let mut text = String::new();
        for (name, value) in [
            ("forwards_chat", self.forwards_chat),
            ("forwards_receipt", self.forwards_receipt),
            ("delivers_chat", self.delivers_chat),
            ("delivers_receipt", self.delivers_receipt),
            ("accepted", self.accepted),
        ] {
            let _ = writeln!(text, "{name}={value}");
        }
        for (code, name) in ERROR_NAMES.iter().enumerate().skip(1) {
            let _ = writeln!(text, "error_{name}={}", self.errors[code]);
        }
        for (name, value) in [
            ("dropped_receipts", self.dropped_receipts),
            ("held_receipts", self.held_receipts),
            ("released_receipts", self.released_receipts),
            ("tampered_chats", self.tampered_chats),
            ("reflected_chats", self.reflected_chats),
            ("injected_unknown_sender", self.injected_unknown_sender),
            ("armed", armed as u64),
            ("held", held as u64),
        ] {
            let _ = writeln!(text, "{name}={value}");
        }
        text
    }
}

pub(super) struct FaultState {
    armed: Vec<Fault>,
    /// Held receipt DELIVER frames by recipient root, at most [MAX_ARMED].
    held: Vec<([u8; 32], Vec<u8>)>,
    counters: Counters,
    /// Per-process prefix so synthetic roots and packet IDs differ between relay runs.
    seed: [u8; 8],
    injected: u64,
}

impl FaultState {
    pub(super) fn new() -> Self {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        Self { armed: Vec::new(), held: Vec::new(), counters: Counters::default(), seed: (nanos as u64).to_be_bytes(), injected: 0 }
    }

    /// Counts one client message before the core sees it.
    pub(super) fn incoming(&mut self, bytes: &[u8]) {
        if let Ok(FrameV2::ClientForward { envelope }) = decode_frame(Direction::ClientToServer, bytes) {
            match envelope.header.kind {
                PacketKind::Chat => self.counters.forwards_chat += 1,
                PacketKind::Receipt => self.counters.forwards_receipt += 1,
                PacketKind::CommunitySync | PacketKind::CommunityCandidate | PacketKind::CommunityCandidateReceipt => {}
            }
        }
    }

    /// Applies armed faults to one batch of core actions and counts what leaves.
    pub(super) fn apply<A: Authenticator, E: Entropy>(&mut self, core: &mut RelayCore<A, E>, actions: Vec<Action>) -> Vec<Action> {
        let mut out = Vec::with_capacity(actions.len() + 1);
        for action in actions {
            match action {
                Action::Send { conn, frame } => {
                    match decode_frame(Direction::ServerToClient, &frame) {
                        Ok(FrameV2::ServerAccepted { .. }) => self.counters.accepted += 1,
                        Ok(FrameV2::ServerError { code, .. }) => self.counters.errors[code.code() as usize] += 1,
                        _ => {}
                    }
                    out.push(Action::Send { conn, frame });
                }
                Action::Deliver { conn, frame } => self.deliver(core, conn, frame, &mut out),
                close @ Action::Close { .. } => out.push(close),
            }
        }
        out
    }

    fn deliver<A: Authenticator, E: Entropy>(&mut self, core: &mut RelayCore<A, E>, conn: ConnKey, mut frame: Vec<u8>,
                                             out: &mut Vec<Action>) {
        let (header, last_ciphertext_byte) = match decode_frame(Direction::ServerToClient, &frame) {
            Ok(FrameV2::ServerDeliver { envelope }) => {
                let end = envelope.ciphertext.as_ptr() as usize - frame.as_ptr() as usize + envelope.ciphertext.len();
                (envelope.header, end - 1)
            }
            _ => {
                out.push(Action::Deliver { conn, frame });
                return;
            }
        };
        match header.kind {
            PacketKind::Receipt => {
                if self.take(Fault::DropReceiptTo(header.recipient_root)) {
                    self.counters.dropped_receipts += 1;
                    // Never written, so release the admitted queue budget here.
                    core.written(conn, frame.len());
                    return;
                }
                if self.take(Fault::HoldReceiptTo(header.recipient_root)) {
                    self.counters.held_receipts += 1;
                    core.written(conn, frame.len());
                    self.held.push((header.recipient_root, frame));
                    return;
                }
                self.counters.delivers_receipt += 1;
                out.push(Action::Deliver { conn, frame });
            }
            PacketKind::Chat => {
                if self.take(Fault::TamperChatTo(header.recipient_root)) {
                    frame[last_ciphertext_byte] ^= 0x01;
                    self.counters.tampered_chats += 1;
                }
                let reflect = self.take(Fault::ReflectChatFrom(header.sender_root));
                let copy = reflect.then(|| frame.clone());
                self.counters.delivers_chat += 1;
                out.push(Action::Deliver { conn, frame });
                if let (Some(copy), Some(sender)) = (copy, core.route(&header.sender_root)) {
                    // Uncounted in the sender's recipient queue: a one-shot test frame.
                    self.counters.reflected_chats += 1;
                    out.push(Action::Send { conn: sender, frame: copy });
                }
            }
            // No fault hooks for Community sync or candidates: delivered unchanged.
            PacketKind::CommunitySync | PacketKind::CommunityCandidate | PacketKind::CommunityCandidateReceipt =>
                out.push(Action::Deliver { conn, frame }),
        }
    }

    fn take(&mut self, fault: Fault) -> bool {
        match self.armed.iter().position(|armed| *armed == fault) {
            Some(index) => {
                self.armed.remove(index);
                true
            }
            None => false,
        }
    }

    /// A DELIVER of one synthetic CHAT from an unknown root, bound to `recipient`'s exact authority.
    fn unknown_sender_deliver(&mut self, recipient: &Authority) -> Vec<u8> {
        self.injected += 1;
        let mut sender_root = [0xEE; 32];
        sender_root[16..24].copy_from_slice(&self.seed);
        sender_root[24..].copy_from_slice(&self.injected.to_be_bytes());
        let mut packet_id = [0u8; 16];
        packet_id[..8].copy_from_slice(&self.seed);
        packet_id[8..].copy_from_slice(&self.injected.to_be_bytes());
        // H = [2, kind=CHAT, from, to, fromEpoch, toEpoch, fromDigest, toDigest, packetId] (224 bytes).
        let mut header = vec![0x89, 0x02, 0x01];
        for field in [&sender_root, &recipient.root, &[0xE1; 32], &recipient.epoch, &[0xE2; 32], &recipient.activation_digest] {
            header.extend_from_slice(&[0x58, 0x20]);
            header.extend_from_slice(field);
        }
        header.push(0x50);
        header.extend_from_slice(&packet_id);
        // E = [2, H, ciphertext(64 opaque bytes), 1, DER(r=1, s=1)].
        let mut envelope = vec![0x85, 0x02, 0x58, header.len() as u8];
        envelope.extend_from_slice(&header);
        envelope.extend_from_slice(&[0x58, 0x40]);
        envelope.extend_from_slice(&[0xC7; 64]);
        envelope.extend_from_slice(&[0x01, 0x48, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        let envelope = decode_envelope(&envelope).expect("synthetic envelope is canonical");
        encode_frame(Direction::ServerToClient, &FrameV2::ServerDeliver { envelope }).expect("canonical DELIVER")
    }
}

impl<A, E> V2State<A, E>
where
    A: Authenticator + Send + 'static,
    A::Grant: Send,
    E: Entropy + Send + 'static,
{
    /// Arms one one-shot fault; false when [MAX_ARMED] are already armed.
    pub fn arm_fault(&self, fault: Fault) -> bool {
        let mut inner = self.lock();
        let holds = inner.faults.armed.iter().filter(|f| matches!(f, Fault::HoldReceiptTo(_))).count();
        if inner.faults.armed.len() >= MAX_ARMED || (matches!(fault, Fault::HoldReceiptTo(_)) && holds + inner.faults.held.len() >= MAX_ARMED) {
            return false;
        }
        inner.faults.armed.push(fault);
        true
    }

    pub fn disarm_faults(&self) {
        self.lock().faults.armed.clear();
    }

    /// Current counters, the number of armed faults and the number of held receipts.
    pub fn fault_counters(&self) -> (Counters, usize, usize) {
        let inner = self.lock();
        (inner.faults.counters, inner.faults.armed.len(), inner.faults.held.len())
    }

    /// Writes every held receipt whose recipient root is connected now; returns (released, still held).
    pub fn release_held_receipts(&self) -> (usize, usize) {
        let mut inner = self.lock();
        let held = std::mem::take(&mut inner.faults.held);
        let mut actions = Vec::new();
        for (root, frame) in held {
            match inner.core.route(&root) {
                // Uncounted in the recipient queue: its budget was released when it was held.
                Some(conn) => actions.push(Action::Send { conn, frame }),
                None => inner.faults.held.push((root, frame)),
            }
        }
        let released = actions.len();
        inner.faults.counters.released_receipts += released as u64;
        inner.dispatch(actions);
        (released, inner.faults.held.len())
    }

    /// Sends one synthetic unknown-sender CHAT to the live `root`; false when it is not connected.
    pub fn inject_unknown_sender(&self, root: &[u8; 32]) -> bool {
        let mut inner = self.lock();
        let (Some(conn), Some(authority)) = (inner.core.route(root), inner.core.route_authority(root)) else {
            return false;
        };
        let frame = inner.faults.unknown_sender_deliver(&authority);
        inner.faults.counters.injected_unknown_sender += 1;
        inner.dispatch(vec![Action::Send { conn, frame }]);
        true
    }
}

/// The `/v2/test/*` control routes. Merge only for a debug-loopback relay.
pub fn faults_router<A, E>(state: Arc<V2State<A, E>>) -> Router
where
    A: Authenticator + Send + 'static,
    A::Grant: Send,
    E: Entropy + Send + 'static,
{
    Router::new()
        .route("/v2/test/arm/{fault}/{root}", post(arm::<A, E>))
        .route("/v2/test/inject/unknown-sender/{root}", post(inject::<A, E>))
        .route("/v2/test/disarm", post(disarm::<A, E>))
        .route("/v2/test/release", post(release::<A, E>))
        .route("/v2/test/counters", get(counters::<A, E>))
        .with_state(state)
}

/// Exactly 64 ASCII hex digits, either case.
pub fn parse_root(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut root = [0u8; 32];
    for (index, byte) in root.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(root)
}

async fn arm<A, E>(State(state): State<Arc<V2State<A, E>>>, Path((fault, root)): Path<(String, String)>) -> impl IntoResponse
where
    A: Authenticator + Send + 'static,
    A::Grant: Send,
    E: Entropy + Send + 'static,
{
    let Some(root) = parse_root(&root) else {
        return (StatusCode::BAD_REQUEST, "root must be 64 hex digits\n");
    };
    let fault = match fault.as_str() {
        "drop-receipt" => Fault::DropReceiptTo(root),
        "hold-receipt" => Fault::HoldReceiptTo(root),
        "tamper-chat" => Fault::TamperChatTo(root),
        "reflect-chat" => Fault::ReflectChatFrom(root),
        _ => return (StatusCode::NOT_FOUND, "unknown fault\n"),
    };
    if state.arm_fault(fault) {
        (StatusCode::ACCEPTED, "armed\n")
    } else {
        (StatusCode::TOO_MANY_REQUESTS, "too many armed faults\n")
    }
}

async fn inject<A, E>(State(state): State<Arc<V2State<A, E>>>, Path(root): Path<String>) -> impl IntoResponse
where
    A: Authenticator + Send + 'static,
    A::Grant: Send,
    E: Entropy + Send + 'static,
{
    let Some(root) = parse_root(&root) else {
        return (StatusCode::BAD_REQUEST, "root must be 64 hex digits\n");
    };
    if state.inject_unknown_sender(&root) {
        (StatusCode::OK, "injected\n")
    } else {
        (StatusCode::CONFLICT, "root not connected\n")
    }
}

async fn disarm<A, E>(State(state): State<Arc<V2State<A, E>>>) -> impl IntoResponse
where
    A: Authenticator + Send + 'static,
    A::Grant: Send,
    E: Entropy + Send + 'static,
{
    state.disarm_faults();
    (StatusCode::OK, "disarmed\n")
}

async fn release<A, E>(State(state): State<Arc<V2State<A, E>>>) -> impl IntoResponse
where
    A: Authenticator + Send + 'static,
    A::Grant: Send,
    E: Entropy + Send + 'static,
{
    let (released, held) = state.release_held_receipts();
    (StatusCode::OK, format!("released={released}\nheld={held}\n"))
}

async fn counters<A, E>(State(state): State<Arc<V2State<A, E>>>) -> impl IntoResponse
where
    A: Authenticator + Send + 'static,
    A::Grant: Send,
    E: Entropy + Send + 'static,
{
    let (counters, armed, held) = state.fault_counters();
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], counters.render(armed, held))
}
