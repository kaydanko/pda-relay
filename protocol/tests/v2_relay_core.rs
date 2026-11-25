//! Relay v2 runtime core (R4 "Relay finite runtime registry") driven with real canonical frames from
//! `protocol/test-vectors/network-v2-signed-vectors.txt` and a fake [Authenticator]: the core is sans-IO and
//! crypto-free, so these tests pin phases, routes, deadlines, budgets, queues, heartbeat and error/close
//! semantics only. Real signature verification is package 2 and is NOT exercised here.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use pda_relay_protocol::v2::{
    decode_activation, decode_envelope, decode_frame, encode_frame, ActivationV2, Direction, ErrorCode, FrameV2,
};
use pda_relay_protocol::v2_relay::{Action, Authenticator, Authority, ConnKey, Entropy, Limits, RelayCore};

const SIGNED: &str = include_str!("../../test-vectors/network-v2-signed-vectors.txt");
const FRAMES: &str = include_str!("../../test-vectors/network-relay-v2-frames.txt");
const AUDIENCE: &[u8] = b"wss://relay.test:443/v2/ws|pda-relay.cbor.v2";

fn fixture(input: &'static str) -> BTreeMap<&'static str, Vec<u8>> {
    let mut values = BTreeMap::new();
    for line in input.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=').expect("fixture line");
        let bytes = (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("lowercase hex"))
            .collect();
        assert!(values.insert(name, bytes).is_none(), "duplicate {name}");
    }
    values
}

fn b32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32 bytes")
}

/// Everything a test needs from the vectors, plus the three structurally valid root SPKIs it maps.
struct Vectors {
    sender_spki: Vec<u8>,
    recipient_spki: Vec<u8>,
    third_spki: Vec<u8>,
    activation: Vec<u8>,
    client_nonce: [u8; 32],
    good_proof: Vec<u8>,
    bad_proof: Vec<u8>,
    packet: Vec<u8>,
    sender: Authority,
    recipient: Authority,
}

fn vectors() -> Vectors {
    let v = fixture(SIGNED);
    let f = fixture(FRAMES);
    let sender = Authority { root: b32(&v["ROOT_ID"]), epoch: b32(&v["EPOCH"]), activation_digest: b32(&v["ACTIVATION_DIGEST"]) };
    let recipient = Authority {
        root: b32(&v["RECIPIENT_ROOT"]),
        epoch: b32(&v["RECIPIENT_EPOCH"]),
        activation_digest: b32(&v["RECIPIENT_ACTIVATION_DIGEST"]),
    };
    // The packet vector is addressed from `sender` to `recipient`; the authority tests rely on it.
    let header = decode_envelope(&v["PACKET_ENVELOPE"]).expect("strict envelope").header;
    assert_eq!((header.sender_root, header.sender_epoch, header.sender_activation_digest),
               (sender.root, sender.epoch, sender.activation_digest));
    assert_eq!(header.recipient_root, recipient.root);
    Vectors {
        sender_spki: v["ROOT_SPKI"].clone(),
        recipient_spki: v["DEVICE_SPKI"].clone(),
        third_spki: f["G_SPKI"].clone(),
        activation: v["ACTIVATION_ENVELOPE"].clone(),
        client_nonce: b32(&v["CLIENT_NONCE"]),
        good_proof: v["POSSESSION_PROOF_DER"].clone(),
        bad_proof: v["REJECT_POSSESSION_ROOT_KEY_DER"].clone(),
        packet: v["PACKET_ENVELOPE"].clone(),
        sender,
        recipient,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PossessionCall {
    audience: Vec<u8>,
    connection_id: [u8; 16],
    server_nonce: [u8; 32],
    client_nonce: [u8; 32],
    signature: Vec<u8>,
}

#[derive(Default)]
struct Log {
    authorize: usize,
    possession: Vec<PossessionCall>,
}

/// Root SPKI -> authority table; possession succeeds only for the one accepted signature and audience.
struct FakeAuth {
    table: Vec<(Vec<u8>, Authority)>,
    good_proof: Vec<u8>,
    log: Rc<RefCell<Log>>,
}

impl Authenticator for FakeAuth {
    type Grant = Authority;

    fn authorize(&self, root_spki: &[u8], _activation: &ActivationV2<'_>) -> Option<Authority> {
        self.log.borrow_mut().authorize += 1;
        self.table.iter().find(|(spki, _)| spki == root_spki).map(|(_, authority)| *authority)
    }

    fn authority(&self, grant: &Authority) -> Authority {
        *grant
    }

    fn possession(&self, _grant: &Authority, audience_utf8: &[u8], connection_id: &[u8; 16], server_nonce: &[u8; 32],
                  client_nonce: &[u8; 32], signature_der: &[u8]) -> bool {
        self.log.borrow_mut().possession.push(PossessionCall {
            audience: audience_utf8.to_vec(),
            connection_id: *connection_id,
            server_nonce: *server_nonce,
            client_nonce: *client_nonce,
            signature: signature_der.to_vec(),
        });
        signature_der == self.good_proof && audience_utf8 == AUDIENCE
    }
}

/// Deterministic, never-repeating byte stream.
struct Counter(u8);

impl Entropy for Counter {
    fn fill(&mut self, out: &mut [u8]) {
        for byte in out {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
    }
}

struct Harness {
    v: Vectors,
    core: RelayCore<FakeAuth, Counter>,
    log: Rc<RefCell<Log>>,
}

/// An extra root SPKI -> authority row for the fake, derived from the vectors.
type ExtraRoot = (fn(&Vectors) -> Vec<u8>, fn(&Vectors) -> Authority);

fn harness_with(limits: Limits, extra: &[ExtraRoot]) -> Harness {
    let v = vectors();
    let log = Rc::new(RefCell::new(Log::default()));
    let mut table = vec![(v.sender_spki.clone(), v.sender), (v.recipient_spki.clone(), v.recipient)];
    for (spki, authority) in extra {
        table.push((spki(&v), authority(&v)));
    }
    let auth = FakeAuth { table, good_proof: v.good_proof.clone(), log: log.clone() };
    let core = RelayCore::new(auth, Counter(0), AUDIENCE, limits).expect("valid audience");
    Harness { v, core, log }
}

fn harness() -> Harness {
    harness_with(Limits::default(), &[])
}

fn hello(v: &Vectors, root_spki: &[u8]) -> Vec<u8> {
    let authorization = decode_activation(&v.activation).expect("strict activation");
    encode_frame(Direction::ClientToServer, &FrameV2::ClientHello { root_spki, authorization, client_nonce: v.client_nonce })
        .expect("canonical HELLO")
}

fn proof(signature_der: &[u8]) -> Vec<u8> {
    encode_frame(Direction::ClientToServer, &FrameV2::ClientProof { signature_der }).expect("canonical PROOF")
}

fn forward(envelope: &[u8]) -> Vec<u8> {
    let envelope = decode_envelope(envelope).expect("strict envelope");
    encode_frame(Direction::ClientToServer, &FrameV2::ClientForward { envelope }).expect("canonical FORWARD")
}

fn ping(nonce: u64) -> Vec<u8> {
    encode_frame(Direction::ClientToServer, &FrameV2::Ping { nonce }).unwrap()
}

fn pong(nonce: u64) -> Vec<u8> {
    encode_frame(Direction::ClientToServer, &FrameV2::Pong { nonce }).unwrap()
}

/// Compact, order-preserving description of actions: `2:DELIVER`, `1:ACCEPTED`, `1:ERROR9`, `1:CLOSE`.
fn show(actions: &[Action]) -> Vec<String> {
    actions
        .iter()
        .map(|action| match action {
            Action::Close { conn } => format!("{conn}:CLOSE"),
            Action::Send { conn, frame } | Action::Deliver { conn, frame } => {
                let decoded = decode_frame(Direction::ServerToClient, frame).expect("server frames are canonical");
                // Exactly the DELIVER frames, and nothing else, are counted in a recipient queue.
                assert_eq!(matches!(action, Action::Deliver { .. }), matches!(decoded, FrameV2::ServerDeliver { .. }));
                let name = match decoded {
                    FrameV2::ServerChallenge { .. } => "CHALLENGE".to_string(),
                    FrameV2::ServerRegistered { .. } => "REGISTERED".to_string(),
                    FrameV2::ServerDeliver { .. } => "DELIVER".to_string(),
                    FrameV2::ServerAccepted { .. } => "ACCEPTED".to_string(),
                    FrameV2::Ping { .. } => "PING".to_string(),
                    FrameV2::Pong { nonce } => format!("PONG{nonce}"),
                    FrameV2::ServerError { code, related_packet_id: None } => format!("ERROR{}", code.code()),
                    FrameV2::ServerError { code, related_packet_id: Some(_) } => format!("ERROR{}+ID", code.code()),
                    other => panic!("client frame emitted by server: {other:?}"),
                };
                format!("{conn}:{name}")
            }
        })
        .collect()
}

fn frame_of(actions: &[Action], index: usize) -> FrameV2<'_> {
    match &actions[index] {
        Action::Send { frame, .. } | Action::Deliver { frame, .. } => decode_frame(Direction::ServerToClient, frame).unwrap(),
        Action::Close { .. } => panic!("not a send"),
    }
}

fn closes(conn: ConnKey, code: ErrorCode) -> Vec<String> {
    vec![format!("{conn}:ERROR{}", code.code()), format!("{conn}:CLOSE")]
}

impl Harness {
    /// accept + HELLO + PROOF for `root_spki`; returns the wire connection ID.
    fn authenticate(&mut self, conn: ConnKey, source: u64, root_spki: &[u8], now: u64) -> [u8; 16] {
        assert!(self.core.accept(conn, source, now).is_empty());
        let challenged = self.core.on_frame(conn, &hello(&self.v, root_spki), now);
        assert_eq!(show(&challenged), vec![format!("{conn}:CHALLENGE")]);
        let FrameV2::ServerChallenge { connection_id, .. } = frame_of(&challenged, 0) else { unreachable!() };
        let proof = proof(&self.v.good_proof);
        let registered = self.core.on_frame(conn, &proof, now);
        assert_eq!(show(&registered), vec![format!("{conn}:REGISTERED")]);
        assert_eq!(frame_of(&registered, 0), FrameV2::ServerRegistered { connection_id });
        connection_id
    }
}

#[test]
fn handshake_binds_exact_possession_inputs_and_registers_the_route() {
    let mut h = harness();
    assert!(h.core.accept(1, 7, 0).is_empty());
    let challenged = h.core.on_frame(1, &hello(&h.v, &h.v.sender_spki.clone()), 100);
    assert_eq!(show(&challenged), ["1:CHALLENGE"]);
    let FrameV2::ServerChallenge { connection_id, server_nonce } = frame_of(&challenged, 0) else { unreachable!() };
    assert_eq!(connection_id, core::array::from_fn(|i| i as u8 + 1));
    assert_eq!(server_nonce, core::array::from_fn(|i| i as u8 + 17));
    assert_eq!(h.core.route(&h.v.sender.root), None, "no route before proof");

    let registered = h.core.on_frame(1, &proof(&h.v.good_proof.clone()), 200);
    assert_eq!(show(&registered), ["1:REGISTERED"]);
    assert_eq!(frame_of(&registered, 0), FrameV2::ServerRegistered { connection_id });
    assert_eq!(h.core.route(&h.v.sender.root), Some(1));
    let log = h.log.borrow();
    assert_eq!(log.authorize, 1);
    assert_eq!(log.possession, vec![PossessionCall {
        audience: AUDIENCE.to_vec(),
        connection_id,
        server_nonce,
        client_nonce: h.v.client_nonce,
        signature: h.v.good_proof.clone(),
    }]);
}

#[test]
fn only_hello_then_proof_are_legal_before_authentication() {
    let h = harness();
    let v = &h.v;
    let cases: [(&str, Vec<Vec<u8>>); 7] = [
        ("proof before hello", vec![proof(&v.good_proof)]),
        ("forward before hello", vec![forward(&v.packet)]),
        ("ping before hello", vec![ping(1)]),
        ("pong before hello", vec![pong(1)]),
        ("second hello", vec![hello(v, &v.sender_spki), hello(v, &v.sender_spki)]),
        ("forward while challenged", vec![hello(v, &v.sender_spki), forward(&v.packet)]),
        ("ping while challenged", vec![hello(v, &v.sender_spki), ping(1)]),
    ];
    for (name, frames) in cases {
        let mut h = harness();
        h.core.accept(1, 7, 0);
        let (last, setup) = frames.split_last().unwrap();
        for frame in setup {
            assert_eq!(show(&h.core.on_frame(1, frame, 0)), ["1:CHALLENGE"], "{name}");
        }
        assert_eq!(show(&h.core.on_frame(1, last, 0)), closes(1, ErrorCode::PolicyViolation), "{name}");
        assert_eq!(h.core.connection_count(), 0, "{name}");
        assert_eq!(h.core.route(&v.sender.root), None, "{name}");
    }

    // After authentication a HELLO or PROOF is a phase violation too, and closing drops the route.
    for frame in [hello(v, &v.sender_spki), proof(&v.good_proof)] {
        let mut h = harness();
        let spki = h.v.sender_spki.clone();
        h.authenticate(1, 7, &spki, 0);
        assert_eq!(show(&h.core.on_frame(1, &frame, 1)), closes(1, ErrorCode::PolicyViolation));
        assert_eq!(h.core.route(&h.v.sender.root), None);
    }
}

#[test]
fn malformed_or_wrong_direction_frames_close_malformed() {
    let mut h = harness();
    h.core.accept(1, 7, 0);
    assert_eq!(show(&h.core.on_frame(1, &[0xff], 0)), closes(1, ErrorCode::Malformed));

    let server_frame = encode_frame(Direction::ServerToClient, &FrameV2::ServerAccepted { packet_id: [1; 16] }).unwrap();
    let spki = h.v.sender_spki.clone();
    h.authenticate(2, 7, &spki, 0);
    assert_eq!(show(&h.core.on_frame(2, &server_frame, 0)), closes(2, ErrorCode::Malformed));
    assert_eq!(h.core.route(&h.v.sender.root), None);
    // Unknown connections are ignored rather than answered.
    assert!(h.core.on_frame(99, &server_frame, 0).is_empty());
}

#[test]
fn authentication_failures_close_auth_failed_without_a_route() {
    let mut h = harness();
    h.core.accept(1, 7, 0);
    let unknown = h.v.third_spki.clone();
    assert_eq!(show(&h.core.on_frame(1, &hello(&h.v, &unknown), 0)), closes(1, ErrorCode::AuthFailed));
    assert!(h.log.borrow().possession.is_empty(), "no challenge, no possession check");

    h.core.accept(2, 7, 0);
    let spki = h.v.sender_spki.clone();
    assert_eq!(show(&h.core.on_frame(2, &hello(&h.v, &spki), 0)), ["2:CHALLENGE"]);
    let bad = proof(&h.v.bad_proof.clone());
    assert_eq!(show(&h.core.on_frame(2, &bad, 0)), closes(2, ErrorCode::AuthFailed));
    assert_eq!(h.core.route(&h.v.sender.root), None);
    assert_eq!(h.core.connection_count(), 0);
}

#[test]
fn hello_and_proof_deadlines_expire_at_exactly_the_window() {
    let mut h = harness();
    let spki = h.v.sender_spki.clone();
    let frame = hello(&h.v, &spki);

    h.core.accept(1, 7, 1_000);
    h.core.accept(2, 7, 1_000);
    assert_eq!(show(&h.core.on_frame(1, &frame, 5_999)), ["1:CHALLENGE"], "4999 ms is in time");
    assert_eq!(show(&h.core.on_frame(2, &frame, 6_000)), closes(2, ErrorCode::PolicyViolation));

    // Challenged at 5999: proof at +10000 is late, also when only the timer notices it.
    let late = proof(&h.v.good_proof.clone());
    assert!(h.core.tick(15_998).is_empty());
    assert_eq!(show(&h.core.on_frame(1, &late, 15_999)), closes(1, ErrorCode::ChallengeExpired));

    h.core.accept(3, 8, 20_000);
    assert!(h.core.tick(24_999).is_empty());
    assert_eq!(show(&h.core.tick(25_000)), closes(3, ErrorCode::PolicyViolation));
    h.core.accept(4, 8, 25_000);
    h.core.on_frame(4, &frame, 25_000);
    assert_eq!(show(&h.core.tick(35_000)), closes(4, ErrorCode::ChallengeExpired));
    assert_eq!(h.core.connection_count(), 0);
}

#[test]
fn a_live_root_refuses_the_newcomer_and_only_its_owner_removes_the_route() {
    let mut h = harness();
    let spki = h.v.sender_spki.clone();
    h.authenticate(1, 7, &spki, 0);
    h.core.accept(2, 8, 0);
    h.core.on_frame(2, &hello(&h.v, &spki), 0);
    let good = proof(&h.v.good_proof.clone());
    assert_eq!(show(&h.core.on_frame(2, &good, 0)), closes(2, ErrorCode::RootAlreadyConnected));
    assert_eq!(h.core.route(&h.v.sender.root), Some(1), "existing route is not evicted");

    h.core.on_closed(2);
    assert_eq!(h.core.route(&h.v.sender.root), Some(1), "a stale close does not remove the owner's route");
    h.core.on_closed(1);
    assert_eq!(h.core.route(&h.v.sender.root), None);
    h.authenticate(3, 7, &spki, 1);
    assert_eq!(h.core.route(&h.v.sender.root), Some(3));
}

#[test]
fn forward_delivers_the_exact_envelope_before_accepted() {
    let mut h = harness();
    let (sender, recipient) = (h.v.sender_spki.clone(), h.v.recipient_spki.clone());
    h.authenticate(1, 7, &sender, 0);
    h.authenticate(2, 8, &recipient, 0);
    let actions = h.core.on_frame(1, &forward(&h.v.packet.clone()), 1);
    assert_eq!(show(&actions), ["2:DELIVER", "1:ACCEPTED"]);
    let FrameV2::ServerDeliver { envelope } = frame_of(&actions, 0) else { unreachable!() };
    assert_eq!(envelope.original, &h.v.packet[..]);
    assert_eq!(frame_of(&actions, 1), FrameV2::ServerAccepted { packet_id: envelope.header.packet_id });
    assert_eq!(h.core.connection_count(), 2);
}

#[test]
fn offline_recipient_is_per_packet_and_authority_mismatch_closes() {
    let mut h = harness();
    let sender = h.v.sender_spki.clone();
    h.authenticate(1, 7, &sender, 0);
    let packet = forward(&h.v.packet.clone());
    let actions = h.core.on_frame(1, &packet, 1);
    assert_eq!(show(&actions), ["1:ERROR5+ID"]);
    let packet_id = decode_envelope(&h.v.packet).unwrap().header.packet_id;
    assert_eq!(frame_of(&actions, 0), FrameV2::ServerError { code: ErrorCode::RecipientOffline, related_packet_id: Some(packet_id) });
    assert_eq!(h.core.route(&h.v.sender.root), Some(1), "connection stays");

    // Self-addressed: the same root on both sides of the header.
    let mut own = h.v.packet.clone();
    let at = own.windows(32).position(|w| w == h.v.recipient.root).unwrap();
    own[at..at + 32].copy_from_slice(&h.v.sender.root);
    assert_eq!(show(&h.core.on_frame(1, &forward(&own), 2)), closes(1, ErrorCode::PolicyViolation));

    // Sender root, epoch or activation digest differing from the session authority.
    let wrong_root: fn(&Vectors) -> Authority = |v| v.recipient;
    let wrong_epoch: fn(&Vectors) -> Authority = |v| Authority { epoch: v.recipient.epoch, ..v.sender };
    let wrong_digest: fn(&Vectors) -> Authority = |v| Authority { activation_digest: v.recipient.activation_digest, ..v.sender };
    for authority in [wrong_root, wrong_epoch, wrong_digest] {
        let mut h = harness_with(Limits::default(), &[(|v| v.third_spki.clone(), authority)]);
        let third = h.v.third_spki.clone();
        h.authenticate(1, 7, &third, 0);
        let recipient = h.v.recipient_spki.clone();
        if authority(&h.v).root != h.v.recipient.root {
            h.authenticate(2, 8, &recipient, 0);
        }
        assert_eq!(show(&h.core.on_frame(1, &forward(&h.v.packet.clone()), 1)), closes(1, ErrorCode::AuthorityMismatch));
        assert_eq!(h.core.route(&authority(&h.v).root), None, "the closed session's route is gone");
    }
}

#[test]
fn full_recipient_queue_answers_backpressure_until_written_releases_it() {
    let limits = Limits { queue_frames: 2, ..Limits::default() };
    let mut h = harness_with(limits, &[]);
    let (sender, recipient) = (h.v.sender_spki.clone(), h.v.recipient_spki.clone());
    h.authenticate(1, 7, &sender, 0);
    h.authenticate(2, 8, &recipient, 0);
    let packet = forward(&h.v.packet.clone());
    let first = h.core.on_frame(1, &packet, 1);
    assert_eq!(show(&first), ["2:DELIVER", "1:ACCEPTED"]);
    let Action::Deliver { frame: delivered, .. } = &first[0] else { unreachable!() };
    assert_eq!(show(&h.core.on_frame(1, &packet, 1)), ["2:DELIVER", "1:ACCEPTED"]);
    assert_eq!(show(&h.core.on_frame(1, &packet, 1)), ["1:ERROR6+ID"], "64-frame analogue: no admission");
    h.core.written(2, delivered.len());
    assert_eq!(show(&h.core.on_frame(1, &packet, 1)), ["2:DELIVER", "1:ACCEPTED"]);

    // The byte bound applies independently of the frame bound.
    let limits = Limits { queue_bytes: delivered.len() * 2 - 1, ..Limits::default() };
    let mut h = harness_with(limits, &[]);
    h.authenticate(1, 7, &sender, 0);
    h.authenticate(2, 8, &recipient, 0);
    assert_eq!(show(&h.core.on_frame(1, &packet, 1)), ["2:DELIVER", "1:ACCEPTED"]);
    assert_eq!(show(&h.core.on_frame(1, &packet, 1)), ["1:ERROR6+ID"]);
    assert_eq!(h.core.connection_count(), 2);
}

#[test]
fn authenticated_frame_and_byte_budgets_close_rate_limit() {
    let mut h = harness();
    let sender = h.v.sender_spki.clone();
    h.authenticate(1, 7, &sender, 0);
    let packet = forward(&h.v.packet.clone());
    for _ in 0..20 {
        assert_eq!(show(&h.core.on_frame(1, &packet, 10)), ["1:ERROR5+ID"], "burst of 20 frames");
    }
    assert_eq!(show(&h.core.on_frame(1, &packet, 109)), closes(1, ErrorCode::RateLimit), "0.99 token after 99 ms");

    let mut h = harness();
    h.authenticate(1, 7, &sender, 0);
    for _ in 0..20 {
        h.core.on_frame(1, &packet, 10);
    }
    assert_eq!(show(&h.core.on_frame(1, &packet, 110)), ["1:ERROR5+ID"], "one token refills in 100 ms");

    let limits = Limits { byte_burst: packet.len() as u64 * 2, bytes_per_second: packet.len() as u64, ..Limits::default() };
    let mut h = harness_with(limits, &[]);
    h.authenticate(1, 7, &sender, 0);
    assert_eq!(show(&h.core.on_frame(1, &packet, 0)), ["1:ERROR5+ID"]);
    assert_eq!(show(&h.core.on_frame(1, &packet, 0)), ["1:ERROR5+ID"]);
    assert_eq!(show(&h.core.on_frame(1, &packet, 0)), closes(1, ErrorCode::RateLimit));
}

#[test]
fn admission_limits_refuse_without_evicting() {
    let sender = vectors().sender_spki;
    let mut h = harness_with(Limits { max_connections: 2, ..Limits::default() }, &[]);
    h.authenticate(1, 7, &sender, 0);
    assert!(h.core.accept(2, 8, 0).is_empty());
    assert_eq!(show(&h.core.accept(3, 9, 0)), closes(3, ErrorCode::Capacity));
    assert_eq!((h.core.connection_count(), h.core.route(&h.v.sender.root)), (2, Some(1)));

    // 8 unauthenticated connections per source address; another address is unaffected.
    let mut h = harness();
    for conn in 0..8 {
        assert!(h.core.accept(conn, 7, 0).is_empty());
    }
    assert_eq!(show(&h.core.accept(8, 7, 0)), closes(8, ErrorCode::RateLimit));
    assert!(h.core.accept(9, 70, 0).is_empty());

    // Handshake bucket: burst 8, then one new handshake per 2 s per address.
    let mut h = harness();
    for conn in 0..8 {
        assert!(h.core.accept(conn, 7, 0).is_empty());
        h.core.on_closed(conn);
    }
    assert_eq!(show(&h.core.accept(8, 7, 1_999)), closes(8, ErrorCode::RateLimit));
    assert!(h.core.accept(9, 7, 2_000).is_empty());

    // 128-challenge analogue.
    let mut h = harness_with(Limits { max_pending_challenges: 1, ..Limits::default() }, &[]);
    let frame = hello(&h.v, &sender);
    h.core.accept(1, 7, 0);
    h.core.accept(2, 8, 0);
    assert_eq!(show(&h.core.on_frame(1, &frame, 0)), ["1:CHALLENGE"]);
    assert_eq!(show(&h.core.on_frame(2, &frame, 0)), closes(2, ErrorCode::Capacity));

    // Tracked source addresses are bounded; only fully refilled buckets are forgotten.
    let mut h = harness_with(Limits { max_tracked_sources: 1, ..Limits::default() }, &[]);
    assert!(h.core.accept(1, 7, 0).is_empty());
    h.core.on_closed(1);
    assert_eq!(show(&h.core.accept(2, 8, 1_999)), closes(2, ErrorCode::Capacity));
    assert!(h.core.accept(3, 8, 2_000).is_empty());
}

#[test]
fn server_heartbeat_requires_the_same_nonce_in_time() {
    let mut h = harness();
    let sender = h.v.sender_spki.clone();
    h.authenticate(1, 7, &sender, 1_000);
    assert!(h.core.tick(30_999).is_empty());
    let pinged = h.core.tick(31_000);
    assert_eq!(show(&pinged), ["1:PING"]);
    let FrameV2::Ping { nonce } = frame_of(&pinged, 0) else { unreachable!() };
    assert!(h.core.tick(40_999).is_empty(), "one outstanding ping only");
    assert!(h.core.on_frame(1, &pong(nonce), 40_999).is_empty());
    assert!(h.core.tick(60_999).is_empty());
    assert_eq!(show(&h.core.tick(61_000)), ["1:PING"]);
    assert_eq!(show(&h.core.tick(71_000)), closes(1, ErrorCode::PolicyViolation), "no pong within 10 s");

    let mut h = harness();
    h.authenticate(1, 7, &sender, 0);
    let FrameV2::Ping { nonce } = frame_of(&h.core.tick(30_000), 0) else { unreachable!() };
    assert_eq!(show(&h.core.on_frame(1, &pong(nonce ^ 1), 30_001)), closes(1, ErrorCode::PolicyViolation));

    let mut h = harness();
    h.authenticate(1, 7, &sender, 0);
    assert_eq!(show(&h.core.on_frame(1, &pong(5), 1)), closes(1, ErrorCode::PolicyViolation), "unsolicited pong");

    // Even when the pong window outlasts the ping interval, a second ping waits for the first pong.
    let mut h = harness_with(Limits { pong_wait_millis: 100_000, ..Limits::default() }, &[]);
    h.authenticate(1, 7, &sender, 0);
    let FrameV2::Ping { nonce } = frame_of(&h.core.tick(30_000), 0) else { unreachable!() };
    assert!(h.core.tick(60_000).is_empty(), "one outstanding server ping");
    assert!(h.core.on_frame(1, &pong(nonce), 60_001).is_empty());
    assert_eq!(show(&h.core.tick(60_002)), ["1:PING"], "overdue since 60 000, sent once the pong arrived");
}

#[test]
fn client_ping_is_answered_at_most_once_per_interval() {
    let mut h = harness();
    let sender = h.v.sender_spki.clone();
    h.authenticate(1, 7, &sender, 0);
    assert_eq!(show(&h.core.on_frame(1, &ping(42), 5)), ["1:PONG42"]);
    assert_eq!(show(&h.core.on_frame(1, &ping(43), 30_004)), closes(1, ErrorCode::RateLimit));

    let mut h = harness();
    h.authenticate(1, 7, &sender, 0);
    assert_eq!(show(&h.core.on_frame(1, &ping(1), 5)), ["1:PONG1"]);
    assert_eq!(show(&h.core.on_frame(1, &ping(2), 30_005)), ["1:PONG2"]);
}

#[test]
fn clock_is_monotonic_and_the_audience_is_validated() {
    let mut h = harness();
    h.core.accept(1, 7, 10_000);
    assert!(h.core.tick(3).is_empty(), "an earlier reading does not move time backwards");
    h.core.accept(2, 8, 0);
    assert_eq!(show(&h.core.tick(14_999)), Vec::<String>::new());
    assert_eq!(show(&h.core.tick(15_000)), [closes(1, ErrorCode::PolicyViolation), closes(2, ErrorCode::PolicyViolation)].concat());

    let v = vectors();
    for audience in [&b""[..], &[0xff, 0xfe][..], &[b'a'; 513][..]] {
        let auth = FakeAuth { table: vec![], good_proof: v.good_proof.clone(), log: Rc::default() };
        assert!(RelayCore::new(auth, Counter(0), audience, Limits::default()).is_none());
    }
}
