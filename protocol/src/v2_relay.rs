//! Relay v2 runtime core (R4 "Relay finite runtime registry", contract lines 405-438), sans-IO.
//!
//! The transport owns sockets, TLS, tasks and the monotonic clock; it feeds [RelayCore::accept],
//! [RelayCore::on_frame], [RelayCore::written], [RelayCore::on_closed] and [RelayCore::tick] and performs the
//! returned [Action]s in order. Cryptography is injected through [Authenticator] (the reviewed p256 verifier of
//! package 2); randomness through [Entropy]. The core persists nothing and never inspects ciphertext.
//!
//! Rules implemented:
//! - phases NEW -> CHALLENGED -> AUTHENTICATED -> CLOSED; HELLO within 5 s of accept, PROOF within 10 s of the
//!   challenge (checked on every event, not only on tick; `elapsed >= window` is expired); one HELLO and one
//!   consumed challenge per connection; any other pre-authentication frame closes POLICY_VIOLATION;
//! - one live route per root, registered atomically on a verified proof; a newcomer for a live root closes
//!   ROOT_ALREADY_CONNECTED; removal only by the owning connection;
//! - forward header sender (root, epoch, activation digest) must equal the session authority
//!   (AUTHORITY_MISMATCH); offline recipient -> RECIPIENT_OFFLINE; full recipient queue (64 frames or 2 MiB)
//!   -> BACKPRESSURE without admission; ACCEPTED only after admission to that bounded volatile queue;
//! - limits: 512 connections, 128 outstanding challenges, 8 unauthenticated connections per source, handshake
//!   token bucket 30/min burst 8 per source, authenticated frame bucket 10/s burst 20 and byte bucket
//!   256 KiB/s burst 512 KiB; capacity refuses without evicting authenticated routes;
//! - heartbeat: server PING every 30 s, matching PONG within 10 s, one outstanding; unmatched PONG closes
//!   POLICY_VIOLATION; a client PING at most once per 30 s is answered;
//! - error frames carry no detail; codes 1-4 and 7-10 are followed by Close, 5/6 keep the connection.
//!
//! Local choices (not fixed by R4, documented for review): a missed HELLO deadline, a missed PONG deadline and
//! a self-addressed forward close POLICY_VIOLATION; a too-frequent client PING, the per-source
//! unauthenticated limit and the handshake bucket answer RATE_LIMIT; handshake buckets are kept for at most
//! `max_tracked_sources` addresses (fully refilled buckets are dropped losslessly, otherwise CAPACITY); clock
//! readings are clamped to be non-decreasing, so deadlines never move backwards.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::v2::{decode_frame, encode_frame, ActivationV2, Direction, ErrorCode, FrameV2, MAX_NONCE};

/// Transport-local connection handle (not the wire connection ID).
pub type ConnKey = u64;
/// Caller-derived key of the remote source address (availability control only, not identity).
pub type SourceKey = u64;

/// Root-verified public authority of one authenticated connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Authority {
    pub root: [u8; 32],
    pub epoch: [u8; 32],
    pub activation_digest: [u8; 32],
}

/// Package-2 seam: real root-signature and device-possession verification over exact R4 inputs.
pub trait Authenticator {
    /// Whatever the verifier needs later (e.g. the parsed device key) for one HELLO.
    type Grant;
    /// Verifies that `activation.root_id` is the ROOT-ID/V1 digest of `root_spki`, the root signature over the
    /// activation TBS and the device SPKI curve point; None means AUTH_FAILED.
    fn authorize(&self, root_spki: &[u8], activation: &ActivationV2<'_>) -> Option<Self::Grant>;
    fn authority(&self, grant: &Self::Grant) -> Authority;
    /// Fail closed for implementations without bootstrap verification.
    fn bootstrap(&self, _envelope: &crate::v2::PacketEnvelopeV2<'_>, _authority: &Authority) -> bool { false }
    /// Device-key verification of the possession transcript for exactly these values.
    fn possession(&self, grant: &Self::Grant, audience_utf8: &[u8], connection_id: &[u8; 16], server_nonce: &[u8; 32],
                  client_nonce: &[u8; 32], signature_der: &[u8]) -> bool;
}

/// CSPRNG for wire connection IDs, server nonces and ping nonces.
pub trait Entropy {
    fn fill(&mut self, out: &mut [u8]);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_connections: usize,
    pub max_pending_challenges: usize,
    pub max_unauthenticated_per_source: usize,
    pub max_tracked_sources: usize,
    pub handshake_burst: u64,
    pub handshakes_per_minute: u64,
    pub frame_burst: u64,
    pub frames_per_second: u64,
    pub byte_burst: u64,
    pub bytes_per_second: u64,
    pub queue_frames: usize,
    pub queue_bytes: usize,
    pub hello_millis: u64,
    pub proof_millis: u64,
    pub ping_interval_millis: u64,
    pub pong_wait_millis: u64,
    pub client_ping_interval_millis: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 512,
            max_pending_challenges: 128,
            max_unauthenticated_per_source: 8,
            max_tracked_sources: 4_096,
            handshake_burst: 8,
            handshakes_per_minute: 30,
            frame_burst: 20,
            frames_per_second: 10,
            byte_burst: 512 * 1024,
            bytes_per_second: 256 * 1024,
            queue_frames: 64,
            queue_bytes: 2 * 1024 * 1024,
            hello_millis: 5_000,
            proof_millis: 10_000,
            ping_interval_millis: 30_000,
            pong_wait_millis: 10_000,
            client_ping_interval_millis: 30_000,
        }
    }
}

/// What the transport must do, in order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// A control or error frame for `conn`; not counted in any recipient queue.
    Send { conn: ConnKey, frame: Vec<u8> },
    /// An admitted DELIVER counted in `conn`'s recipient queue: report it with [RelayCore::written] once written.
    Deliver { conn: ConnKey, frame: Vec<u8> },
    Close { conn: ConnKey },
}

/// Integer token bucket in micro-tokens; refill is continuous in milliseconds.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    capacity: u64,
    per_milli: u64,
    level: u64,
    last: u64,
}

impl Bucket {
    const SCALE: u64 = 1_000_000;

    fn new(burst: u64, per_period: u64, period_millis: u64, now: u64) -> Self {
        let capacity = burst.saturating_mul(Self::SCALE);
        Self { capacity, per_milli: per_period.saturating_mul(Self::SCALE) / period_millis.max(1), level: capacity, last: now }
    }

    fn refill(&mut self, now: u64) {
        let elapsed = now.saturating_sub(self.last);
        self.level = self.level.saturating_add(elapsed.saturating_mul(self.per_milli)).min(self.capacity);
        self.last = now;
    }

    fn full(&mut self, now: u64) -> bool {
        self.refill(now);
        self.level == self.capacity
    }

    fn take(&mut self, now: u64, amount: u64) -> bool {
        self.refill(now);
        let need = amount.saturating_mul(Self::SCALE);
        if self.level >= need {
            self.level -= need;
            true
        } else {
            false
        }
    }
}

enum Phase<G> {
    New,
    Challenged { grant: G, connection_id: [u8; 16], server_nonce: [u8; 32], client_nonce: [u8; 32], since: u64 },
    Authenticated { authority: Authority },
}

struct Conn<G> {
    source: SourceKey,
    opened_at: u64,
    phase: Phase<G>,
    queued_frames: usize,
    queued_bytes: usize,
    frames: Bucket,
    bytes: Bucket,
    last_server_ping: u64,
    outstanding_ping: Option<(u64, u64)>,
    last_client_ping: Option<u64>,
}

/// One relay's complete volatile state. Not thread-safe by itself: the transport serializes calls.
pub struct RelayCore<A: Authenticator, E: Entropy> {
    auth: A,
    entropy: E,
    audience: Vec<u8>,
    limits: Limits,
    conns: BTreeMap<ConnKey, Conn<A::Grant>>,
    routes: BTreeMap<[u8; 32], ConnKey>,
    directory: BTreeMap<[u8; 32], Vec<u8>>,
    handshakes: BTreeMap<SourceKey, Bucket>,
    last_now: u64,
}

impl<A: Authenticator, E: Entropy> RelayCore<A, E> {
    /// `audience_utf8` is this relay's exact configured audience (e.g. `wss://host:443/v2/ws|pda-relay.cbor.v2`).
    pub fn new(auth: A, entropy: E, audience_utf8: &[u8], limits: Limits) -> Option<Self> {
        if audience_utf8.is_empty() || audience_utf8.len() > 512 || core::str::from_utf8(audience_utf8).is_err() {
            return None;
        }
        Some(Self {
            auth,
            entropy,
            audience: audience_utf8.to_vec(),
            limits,
            conns: BTreeMap::new(),
            routes: BTreeMap::new(),
            directory: BTreeMap::new(),
            handshakes: BTreeMap::new(),
            last_now: 0,
        })
    }

    pub fn connection_count(&self) -> usize {
        self.conns.len()
    }

    /// The live connection currently owning the route for `root`, if any.
    pub fn route(&self, root: &[u8; 32]) -> Option<ConnKey> {
        self.routes.get(root).copied()
    }

    /// Stage 6 fault hooks only: the authority of the live route for `root`, if any.
    #[cfg(feature = "test-faults")]
    pub fn route_authority(&self, root: &[u8; 32]) -> Option<Authority> {
        match &self.conns.get(self.routes.get(root)?)?.phase {
            Phase::Authenticated { authority } => Some(*authority),
            _ => None,
        }
    }

    /// Admits a new transport connection (before any frame). Refusal sends one error and closes.
    pub fn accept(&mut self, conn: ConnKey, source: SourceKey, now: u64) -> Vec<Action> {
        let now = self.clock(now);
        let mut out = Vec::new();
        if self.conns.contains_key(&conn) {
            return out;
        }
        if self.conns.len() >= self.limits.max_connections {
            refuse(&mut out, conn, ErrorCode::Capacity);
            return out;
        }
        let unauthenticated = self.conns.values()
            .filter(|c| c.source == source && !matches!(c.phase, Phase::Authenticated { .. }))
            .count();
        let limits = self.limits;
        if !self.handshakes.contains_key(&source) && self.handshakes.len() >= limits.max_tracked_sources {
            // A fully refilled bucket is indistinguishable from a fresh one, so dropping it loses nothing.
            self.handshakes.retain(|_, bucket| !bucket.full(now));
            if self.handshakes.len() >= limits.max_tracked_sources {
                refuse(&mut out, conn, ErrorCode::Capacity);
                return out;
            }
        }
        let bucket = self.handshakes.entry(source)
            .or_insert_with(|| Bucket::new(limits.handshake_burst, limits.handshakes_per_minute, 60_000, now));
        if unauthenticated >= limits.max_unauthenticated_per_source || !bucket.take(now, 1) {
            refuse(&mut out, conn, ErrorCode::RateLimit);
            return out;
        }
        self.conns.insert(conn, Conn {
            source,
            opened_at: now,
            phase: Phase::New,
            queued_frames: 0,
            queued_bytes: 0,
            frames: Bucket::new(limits.frame_burst, limits.frames_per_second, 1_000, now),
            bytes: Bucket::new(limits.byte_burst, limits.bytes_per_second, 1_000, now),
            last_server_ping: now,
            outstanding_ping: None,
            last_client_ping: None,
        });
        out
    }

    /// One complete binary WebSocket message from `conn`.
    pub fn on_frame(&mut self, conn: ConnKey, bytes: &[u8], now: u64) -> Vec<Action> {
        let now = self.clock(now);
        let mut out = Vec::new();
        if !self.conns.contains_key(&conn) {
            return out;
        }
        if let Some(code) = self.expired(conn, now) {
            self.close(&mut out, conn, Some(code));
            return out;
        }
        let Ok(frame) = decode_frame(Direction::ClientToServer, bytes) else {
            self.close(&mut out, conn, Some(ErrorCode::Malformed));
            return out;
        };
        let authenticated = matches!(self.conns.get(&conn).map(|c| &c.phase), Some(Phase::Authenticated { .. }));
        if authenticated {
            let state = self.conns.get_mut(&conn).expect("present");
            if !state.frames.take(now, 1) || !state.bytes.take(now, bytes.len() as u64) {
                self.close(&mut out, conn, Some(ErrorCode::RateLimit));
                return out;
            }
        }
        match frame {
            FrameV2::ClientHello { root_spki, authorization, client_nonce } => self.hello(&mut out, conn, root_spki, &authorization, client_nonce, now),
            FrameV2::ClientProof { signature_der } => self.proof(&mut out, conn, signature_der, now),
            FrameV2::ClientForward { envelope } if authenticated => self.forward(&mut out, conn, &envelope),
            FrameV2::ClientDirectoryPublish { card } if authenticated => self.directory_publish(&mut out, conn, card),
            FrameV2::ClientDirectorySearch { query } if authenticated => self.directory_search(&mut out, conn, query),
            FrameV2::Ping { nonce } if authenticated => {
                let state = self.conns.get_mut(&conn).expect("present");
                let too_soon = state.last_client_ping
                    .is_some_and(|at| now.saturating_sub(at) < self.limits.client_ping_interval_millis);
                if too_soon {
                    self.close(&mut out, conn, Some(ErrorCode::RateLimit));
                } else {
                    state.last_client_ping = Some(now);
                    send(&mut out, conn, &FrameV2::Pong { nonce });
                }
            }
            FrameV2::Pong { nonce } if authenticated => {
                let state = self.conns.get_mut(&conn).expect("present");
                if state.outstanding_ping.map(|(expected, _)| expected) == Some(nonce) {
                    state.outstanding_ping = None;
                } else {
                    self.close(&mut out, conn, Some(ErrorCode::PolicyViolation));
                }
            }
            _ => self.close(&mut out, conn, Some(ErrorCode::PolicyViolation)),
        }
        out
    }

    /// The transport finished writing an [Action::Deliver] frame to `conn`: release its queue budget.
    pub fn written(&mut self, conn: ConnKey, frame_len: usize) {
        if let Some(state) = self.conns.get_mut(&conn) {
            state.queued_frames = state.queued_frames.saturating_sub(1);
            state.queued_bytes = state.queued_bytes.saturating_sub(frame_len);
        }
    }

    /// The socket is gone (either side). Removes the route only if this connection owns it.
    pub fn on_closed(&mut self, conn: ConnKey) {
        self.forget(conn);
    }

    /// Timer pass: HELLO/PROOF deadlines, server heartbeat and PONG deadlines.
    pub fn tick(&mut self, now: u64) -> Vec<Action> {
        let now = self.clock(now);
        let mut out = Vec::new();
        let keys: Vec<ConnKey> = self.conns.keys().copied().collect();
        for conn in keys {
            if let Some(code) = self.expired(conn, now) {
                self.close(&mut out, conn, Some(code));
                continue;
            }
            let interval = self.limits.ping_interval_millis;
            let due = matches!(self.conns.get(&conn), Some(state) if matches!(state.phase, Phase::Authenticated { .. })
                && state.outstanding_ping.is_none() && now.saturating_sub(state.last_server_ping) >= interval);
            if due {
                let mut raw = [0u8; 8];
                self.entropy.fill(&mut raw);
                let nonce = u64::from_be_bytes(raw) & MAX_NONCE;
                let state = self.conns.get_mut(&conn).expect("present");
                state.outstanding_ping = Some((nonce, now));
                state.last_server_ping = now;
                send(&mut out, conn, &FrameV2::Ping { nonce });
            }
        }
        out
    }

    fn hello(&mut self, out: &mut Vec<Action>, conn: ConnKey, root_spki: &[u8], activation: &ActivationV2<'_>,
             client_nonce: [u8; 32], now: u64) {
        if !matches!(self.conns.get(&conn).map(|c| &c.phase), Some(Phase::New)) {
            self.close(out, conn, Some(ErrorCode::PolicyViolation));
            return;
        }
        let pending = self.conns.values().filter(|c| matches!(c.phase, Phase::Challenged { .. })).count();
        if pending >= self.limits.max_pending_challenges {
            self.close(out, conn, Some(ErrorCode::Capacity));
            return;
        }
        let Some(grant) = self.auth.authorize(root_spki, activation) else {
            self.close(out, conn, Some(ErrorCode::AuthFailed));
            return;
        };
        let mut connection_id = [0u8; 16];
        let mut server_nonce = [0u8; 32];
        self.entropy.fill(&mut connection_id);
        self.entropy.fill(&mut server_nonce);
        let state = self.conns.get_mut(&conn).expect("present");
        state.phase = Phase::Challenged { grant, connection_id, server_nonce, client_nonce, since: now };
        send(out, conn, &FrameV2::ServerChallenge { connection_id, server_nonce });
    }

    fn proof(&mut self, out: &mut Vec<Action>, conn: ConnKey, signature_der: &[u8], now: u64) {
        let verified = match self.conns.get(&conn).map(|c| &c.phase) {
            Some(Phase::Challenged { grant, connection_id, server_nonce, client_nonce, .. }) => {
                if self.auth.possession(grant, &self.audience, connection_id, server_nonce, client_nonce, signature_der) {
                    Some((self.auth.authority(grant), *connection_id))
                } else {
                    None
                }
            }
            _ => {
                self.close(out, conn, Some(ErrorCode::PolicyViolation));
                return;
            }
        };
        let Some((authority, connection_id)) = verified else {
            self.close(out, conn, Some(ErrorCode::AuthFailed));
            return;
        };
        if self.routes.contains_key(&authority.root) {
            // The existing live route is never evicted by a newcomer.
            self.close(out, conn, Some(ErrorCode::RootAlreadyConnected));
            return;
        }
        self.routes.insert(authority.root, conn);
        let state = self.conns.get_mut(&conn).expect("present");
        state.phase = Phase::Authenticated { authority };
        state.last_server_ping = now;
        send(out, conn, &FrameV2::ServerRegistered { connection_id });
    }

    fn forward(&mut self, out: &mut Vec<Action>, conn: ConnKey, envelope: &crate::v2::PacketEnvelopeV2<'_>) {
        let authority = match self.conns.get(&conn).map(|c| &c.phase) {
            Some(Phase::Authenticated { authority }) => *authority,
            _ => return,
        };
        let header = &envelope.header;
        if header.sender_root != authority.root || header.sender_epoch != authority.epoch
            || header.sender_activation_digest != authority.activation_digest {
            self.close(out, conn, Some(ErrorCode::AuthorityMismatch));
            return;
        }
        if matches!(header.kind, crate::v2::PacketKind::ContactRequest | crate::v2::PacketKind::ContactRejection)
            && !self.auth.bootstrap(envelope, &authority) {
            self.close(out, conn, Some(ErrorCode::AuthFailed));
            return;
        }
        if header.recipient_root == authority.root {
            self.close(out, conn, Some(ErrorCode::PolicyViolation));
            return;
        }
        let packet_id = header.packet_id;
        let Some(recipient) = self.routes.get(&header.recipient_root).copied() else {
            send(out, conn, &FrameV2::ServerError { code: ErrorCode::RecipientOffline, related_packet_id: Some(packet_id) });
            return;
        };
        let Ok(deliver) = encode_frame(Direction::ServerToClient, &FrameV2::ServerDeliver { envelope: *envelope }) else {
            self.close(out, conn, Some(ErrorCode::Malformed));
            return;
        };
        let limits = self.limits;
        let target = self.conns.get_mut(&recipient).expect("routed connections are present");
        if target.queued_frames + 1 > limits.queue_frames || target.queued_bytes + deliver.len() > limits.queue_bytes {
            send(out, conn, &FrameV2::ServerError { code: ErrorCode::Backpressure, related_packet_id: Some(packet_id) });
            return;
        }
        target.queued_frames += 1;
        target.queued_bytes += deliver.len();
        out.push(Action::Deliver { conn: recipient, frame: deliver });
        send(out, conn, &FrameV2::ServerAccepted { packet_id });
    }

    fn directory_publish(&mut self, out: &mut Vec<Action>, conn: ConnKey, card: &[u8]) {
        let Some(Phase::Authenticated { authority }) = self.conns.get(&conn).map(|c| &c.phase) else { return };
        self.directory.insert(authority.root, card.to_vec());
        send(out, conn, &FrameV2::ServerDirectoryResult { results: &[] });
    }

    fn directory_search(&mut self, out: &mut Vec<Action>, conn: ConnKey, query: &[u8]) {
        let Some(found) = self.directory.values().find(|card| card.windows(query.len()).any(|window| window == query)) else {
            send(out, conn, &FrameV2::ServerDirectoryResult { results: &[] });
            return;
        };
        send(out, conn, &FrameV2::ServerDirectoryResult { results: found.as_slice() });
    }

    /// Deadline that has passed for `conn` at `now`, if any (`elapsed >= window` is expired).
    fn expired(&self, conn: ConnKey, now: u64) -> Option<ErrorCode> {
        let state = self.conns.get(&conn)?;
        match &state.phase {
            Phase::New if now.saturating_sub(state.opened_at) >= self.limits.hello_millis => Some(ErrorCode::PolicyViolation),
            Phase::Challenged { since, .. } if now.saturating_sub(*since) >= self.limits.proof_millis => Some(ErrorCode::ChallengeExpired),
            Phase::Authenticated { .. } => match state.outstanding_ping {
                Some((_, sent)) if now.saturating_sub(sent) >= self.limits.pong_wait_millis => Some(ErrorCode::PolicyViolation),
                _ => None,
            },
            _ => None,
        }
    }

    fn close(&mut self, out: &mut Vec<Action>, conn: ConnKey, code: Option<ErrorCode>) {
        if let Some(code) = code {
            send(out, conn, &FrameV2::ServerError { code, related_packet_id: None });
        }
        out.push(Action::Close { conn });
        self.forget(conn);
    }

    fn forget(&mut self, conn: ConnKey) {
        if let Some(state) = self.conns.remove(&conn) {
            if let Phase::Authenticated { authority } = state.phase {
                // Invariant: only the one authenticated owner maps its root; the comparison keeps removal
                // correct even if that invariant is ever broken.
                if self.routes.get(&authority.root) == Some(&conn) {
                    self.routes.remove(&authority.root);
                }
            }
        }
    }

    fn clock(&mut self, now: u64) -> u64 {
        self.last_now = self.last_now.max(now);
        self.last_now
    }
}

fn send(out: &mut Vec<Action>, conn: ConnKey, frame: &FrameV2<'_>) {
    if let Ok(bytes) = encode_frame(Direction::ServerToClient, frame) {
        out.push(Action::Send { conn, frame: bytes });
    }
}

fn refuse(out: &mut Vec<Action>, conn: ConnKey, code: ErrorCode) {
    send(out, conn, &FrameV2::ServerError { code, related_packet_id: None });
    out.push(Action::Close { conn });
}
