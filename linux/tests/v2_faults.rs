//! Stage 6 fault hooks (`--features test-faults` only) over real loopback WebSockets and HTTP, with the signed
//! vector packet and a fake [Authenticator] (as in `v2_transport.rs`), plus the real binary: hooks are served
//! for a debug-loopback relay and not for a production audience. Real signatures are NOT exercised here.
#![cfg(feature = "test-faults")]

use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader},
    net::SocketAddr,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use pda_relay::v2::{
    faults::{faults_router, parse_root, Fault, MAX_ARMED},
    v2_router, V2State,
};
use pda_relay::v2_config::{test_faults_enabled, V2Config};
use pda_relay_protocol::{
    v2::{decode_activation, decode_envelope, decode_frame, encode_frame, ActivationV2, Direction, ErrorCode, FrameV2, PacketKind, WS_SUBPROTOCOL},
    v2_relay::{Authenticator, Authority, Entropy, Limits},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
    MaybeTlsStream, WebSocketStream,
};

const SIGNED: &str = include_str!("../../test-vectors/network-v2-signed-vectors.txt");
const AUDIENCE: &[u8] = b"ws://127.0.0.1:47821/v2/ws|pda-relay.cbor.v2";
const WAIT: Duration = Duration::from_secs(5);
/// Offset of the kind byte in the vector envelope: `85 02 58 E0 | 89 02 <kind>`.
const KIND_OFFSET: usize = 6;

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

fn fixture() -> BTreeMap<&'static str, Vec<u8>> {
    SIGNED
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (name, value) = line.split_once('=').unwrap();
            (name, (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap()).collect())
        })
        .collect()
}

fn b32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct FakeAuth {
    table: Vec<(Vec<u8>, Authority)>,
    good_proof: Vec<u8>,
}

impl Authenticator for FakeAuth {
    type Grant = Authority;

    fn authorize(&self, root_spki: &[u8], _activation: &ActivationV2<'_>) -> Option<Authority> {
        self.table.iter().find(|(spki, _)| spki == root_spki).map(|(_, authority)| *authority)
    }

    fn authority(&self, grant: &Authority) -> Authority {
        *grant
    }

    fn possession(&self, _grant: &Authority, audience_utf8: &[u8], _connection_id: &[u8; 16], _server_nonce: &[u8; 32],
                  _client_nonce: &[u8; 32], signature_der: &[u8]) -> bool {
        signature_der == self.good_proof && audience_utf8 == AUDIENCE
    }
}

struct Counter(u8);

impl Entropy for Counter {
    fn fill(&mut self, out: &mut [u8]) {
        for byte in out {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
    }
}

struct Relay {
    f: BTreeMap<&'static str, Vec<u8>>,
    sender: Authority,
    recipient: Authority,
    chat: Vec<u8>,
    receipt: Vec<u8>,
    address: SocketAddr,
    state: Arc<V2State<FakeAuth, Counter>>,
    _stop: oneshot::Sender<()>,
}

async fn start(limits: Limits) -> Relay {
    let f = fixture();
    let sender = Authority { root: b32(&f["ROOT_ID"]), epoch: b32(&f["EPOCH"]), activation_digest: b32(&f["ACTIVATION_DIGEST"]) };
    let recipient = Authority {
        root: b32(&f["RECIPIENT_ROOT"]),
        epoch: b32(&f["RECIPIENT_EPOCH"]),
        activation_digest: b32(&f["RECIPIENT_ACTIVATION_DIGEST"]),
    };
    let chat = f["PACKET_ENVELOPE"].clone();
    assert_eq!(decode_envelope(&chat).unwrap().header.kind, PacketKind::Chat);
    let mut receipt = chat.clone();
    receipt[KIND_OFFSET] = 2;
    assert_eq!(decode_envelope(&receipt).unwrap().header.kind, PacketKind::Receipt);
    let auth = FakeAuth {
        table: vec![(f["ROOT_SPKI"].clone(), sender), (f["DEVICE_SPKI"].clone(), recipient)],
        good_proof: f["POSSESSION_PROOF_DER"].clone(),
    };
    let state = V2State::new(auth, Counter(0), AUDIENCE, limits).expect("valid audience");
    state.start_ticker(Duration::from_millis(50));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let router = v2_router(Arc::clone(&state)).merge(faults_router(Arc::clone(&state)));
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    Relay { f, sender, recipient, chat, receipt, address, state, _stop: stop }
}

fn quiet() -> Limits {
    Limits { ping_interval_millis: 600_000, pong_wait_millis: 600_000, hello_millis: 600_000, proof_millis: 600_000, ..Limits::default() }
}

async fn authenticate(relay: &Relay, spki_name: &str) -> Socket {
    let mut request = format!("ws://{}/v2/ws", relay.address).into_client_request().unwrap();
    request.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static(WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.unwrap();
    send(&mut socket, &FrameV2::ClientHello {
        root_spki: &relay.f[spki_name],
        authorization: decode_activation(&relay.f["ACTIVATION_ENVELOPE"]).unwrap(),
        client_nonce: b32(&relay.f["CLIENT_NONCE"]),
    }).await;
    expect(&mut socket, "CHALLENGE").await;
    send(&mut socket, &FrameV2::ClientProof { signature_der: &relay.f["POSSESSION_PROOF_DER"] }).await;
    expect(&mut socket, "REGISTERED").await;
    socket
}

async fn send(socket: &mut Socket, frame: &FrameV2<'_>) {
    socket.send(Message::Binary(encode_frame(Direction::ClientToServer, frame).unwrap().into())).await.unwrap();
}

async fn forward(socket: &mut Socket, packet: &[u8]) {
    send(socket, &FrameV2::ClientForward { envelope: decode_envelope(packet).unwrap() }).await;
}

async fn recv(socket: &mut Socket) -> Option<Vec<u8>> {
    loop {
        match timeout(WAIT, socket.next()).await.expect("server answered in time") {
            Some(Ok(Message::Binary(bytes))) => return Some(bytes.to_vec()),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            _ => return None,
        }
    }
}

/// Nothing arrives within a short window (the relay is quiet with these limits).
async fn silent(socket: &mut Socket) {
    assert!(timeout(Duration::from_millis(300), socket.next()).await.is_err(), "unexpected frame");
}

fn name(bytes: &[u8]) -> String {
    match decode_frame(Direction::ServerToClient, bytes).expect("canonical server frame") {
        FrameV2::ServerChallenge { .. } => "CHALLENGE".into(),
        FrameV2::ServerRegistered { .. } => "REGISTERED".into(),
        FrameV2::ServerDeliver { .. } => "DELIVER".into(),
        FrameV2::ServerAccepted { .. } => "ACCEPTED".into(),
        FrameV2::ServerError { code, .. } => format!("ERROR{}", code.code()),
        other => format!("{other:?}"),
    }
}

async fn expect(socket: &mut Socket, expected: &str) -> Vec<u8> {
    let bytes = recv(socket).await.unwrap_or_else(|| panic!("closed while expecting {expected}"));
    assert_eq!(name(&bytes), expected);
    bytes
}

fn delivered(bytes: &[u8]) -> Vec<u8> {
    let FrameV2::ServerDeliver { envelope } = decode_frame(Direction::ServerToClient, bytes).unwrap() else { panic!("not DELIVER") };
    envelope.original.to_vec()
}

/// Minimal HTTP/1.1 exchange: (status, body).
async fn http(address: SocketAddr, method: &str, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    timeout(WAIT, stream.read_to_string(&mut response)).await.unwrap().unwrap();
    let status = response[9..12].parse().unwrap();
    let body = response.split_once("\r\n\r\n").map(|(_, body)| body.to_string()).unwrap_or_default();
    (status, body)
}

fn counter(text: &str, key: &str) -> u64 {
    text.lines().find_map(|line| line.strip_prefix(&format!("{key}="))).unwrap_or_else(|| panic!("{key} in {text}")).parse().unwrap()
}

#[tokio::test]
async fn a_dropped_receipt_is_accepted_but_never_written_and_releases_its_queue_slot() {
    // One-frame queue: the second receipt is admitted only if the dropped one released its budget.
    let relay = start(Limits { queue_frames: 1, ..quiet() }).await;
    let mut sender = authenticate(&relay, "ROOT_SPKI").await;
    let mut recipient = authenticate(&relay, "DEVICE_SPKI").await;
    let (status, _) = http(relay.address, "POST", &format!("/v2/test/arm/drop-receipt/{}", hex(&relay.recipient.root))).await;
    assert_eq!(status, 202);

    // A CHAT does not consume the receipt fault.
    forward(&mut sender, &relay.chat).await;
    assert_eq!(delivered(&expect(&mut recipient, "DELIVER").await), relay.chat);
    expect(&mut sender, "ACCEPTED").await;

    forward(&mut sender, &relay.receipt).await;
    expect(&mut sender, "ACCEPTED").await;
    silent(&mut recipient).await;

    forward(&mut sender, &relay.receipt).await;
    expect(&mut sender, "ACCEPTED").await;
    assert_eq!(delivered(&expect(&mut recipient, "DELIVER").await), relay.receipt, "one-shot: the next receipt passes");

    let (_, text) = http(relay.address, "GET", "/v2/test/counters").await;
    for (key, value) in [("forwards_chat", 1), ("forwards_receipt", 2), ("delivers_chat", 1), ("delivers_receipt", 1),
                         ("accepted", 3), ("dropped_receipts", 1), ("armed", 0), ("error_BACKPRESSURE", 0)] {
        assert_eq!(counter(&text, key), value, "{key}");
    }
}

#[tokio::test]
async fn a_held_receipt_is_written_late_only_on_release_and_only_to_a_connected_root() {
    let relay = start(Limits { queue_frames: 1, ..quiet() }).await;
    let mut sender = authenticate(&relay, "ROOT_SPKI").await;
    let mut recipient = authenticate(&relay, "DEVICE_SPKI").await;
    let root = hex(&relay.recipient.root);
    assert_eq!(http(relay.address, "POST", &format!("/v2/test/arm/hold-receipt/{root}")).await.0, 202);
    forward(&mut sender, &relay.receipt).await;
    expect(&mut sender, "ACCEPTED").await;
    silent(&mut recipient).await;
    // The held frame released its queue slot: a one-frame queue still admits the next packet.
    forward(&mut sender, &relay.chat).await;
    expect(&mut sender, "ACCEPTED").await;
    assert_eq!(delivered(&expect(&mut recipient, "DELIVER").await), relay.chat);

    // Not connected at release time: it stays held.
    drop(recipient);
    until_offline(&relay).await;
    assert_eq!(http(relay.address, "POST", "/v2/test/release").await, (200, "released=0\nheld=1\n".into()));
    let mut recipient = authenticate(&relay, "DEVICE_SPKI").await;
    assert_eq!(http(relay.address, "POST", "/v2/test/release").await, (200, "released=1\nheld=0\n".into()));
    assert_eq!(delivered(&expect(&mut recipient, "DELIVER").await), relay.receipt, "the exact held receipt, late");
    let (_, text) = http(relay.address, "GET", "/v2/test/counters").await;
    for (key, value) in [("held_receipts", 1), ("released_receipts", 1), ("held", 0), ("delivers_receipt", 0), ("dropped_receipts", 0)] {
        assert_eq!(counter(&text, key), value, "{key}");
    }
}

#[tokio::test]
async fn armed_and_held_receipts_together_stay_bounded() {
    let relay = start(quiet()).await;
    let mut sender = authenticate(&relay, "ROOT_SPKI").await;
    let _recipient = authenticate(&relay, "DEVICE_SPKI").await;
    assert!(relay.state.arm_fault(Fault::HoldReceiptTo(relay.recipient.root)));
    forward(&mut sender, &relay.receipt).await;
    expect(&mut sender, "ACCEPTED").await;
    for _ in 1..MAX_ARMED {
        assert!(relay.state.arm_fault(Fault::HoldReceiptTo(relay.recipient.root)));
    }
    assert!(!relay.state.arm_fault(Fault::HoldReceiptTo(relay.recipient.root)), "held + armed holds is bounded");
    assert_eq!(relay.state.fault_counters().1 + relay.state.fault_counters().2, MAX_ARMED);
}

async fn until_offline(relay: &Relay) {
    timeout(WAIT, async {
        while relay.state.connection_count() != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("recipient gone in time");
}

#[tokio::test]
async fn a_tampered_chat_differs_only_in_its_last_ciphertext_byte() {
    let relay = start(quiet()).await;
    let mut sender = authenticate(&relay, "ROOT_SPKI").await;
    let mut recipient = authenticate(&relay, "DEVICE_SPKI").await;
    assert!(relay.state.arm_fault(Fault::TamperChatTo(relay.recipient.root)));
    forward(&mut sender, &relay.chat).await;
    let tampered = delivered(&expect(&mut recipient, "DELIVER").await);
    expect(&mut sender, "ACCEPTED").await;

    let original = decode_envelope(&relay.chat).unwrap();
    let changed = decode_envelope(&tampered).unwrap();
    assert_eq!(changed.header_bytes, original.header_bytes);
    assert_eq!(changed.signature_der, original.signature_der);
    let differing: Vec<usize> = (0..tampered.len()).filter(|&i| tampered[i] != relay.chat[i]).collect();
    let last = original.ciphertext.len() - 1;
    assert_eq!(differing.len(), 1);
    assert_eq!(changed.ciphertext[last], original.ciphertext[last] ^ 1);

    forward(&mut sender, &relay.chat).await;
    assert_eq!(delivered(&expect(&mut recipient, "DELIVER").await), relay.chat, "one-shot");
    assert_eq!(relay.state.fault_counters().0.tampered_chats, 1);
}

#[tokio::test]
async fn a_reflected_chat_also_reaches_its_own_sender() {
    let relay = start(quiet()).await;
    let mut sender = authenticate(&relay, "ROOT_SPKI").await;
    let mut recipient = authenticate(&relay, "DEVICE_SPKI").await;
    // Armed for the recipient's root, the sender's packets are not reflected.
    assert!(relay.state.arm_fault(Fault::ReflectChatFrom(relay.recipient.root)));
    forward(&mut sender, &relay.chat).await;
    expect(&mut recipient, "DELIVER").await;
    expect(&mut sender, "ACCEPTED").await;
    assert_eq!(relay.state.fault_counters().1, 1, "still armed");

    assert!(relay.state.arm_fault(Fault::ReflectChatFrom(relay.sender.root)));
    forward(&mut sender, &relay.chat).await;
    assert_eq!(delivered(&expect(&mut recipient, "DELIVER").await), relay.chat);
    let reflected = delivered(&expect(&mut sender, "DELIVER").await);
    assert_eq!(reflected, relay.chat);
    assert_ne!(decode_envelope(&reflected).unwrap().header.recipient_root, relay.sender.root, "not addressed to its sender");
    expect(&mut sender, "ACCEPTED").await;

    forward(&mut sender, &relay.chat).await;
    expect(&mut recipient, "DELIVER").await;
    expect(&mut sender, "ACCEPTED").await;
    let (counters, armed, _) = relay.state.fault_counters();
    assert_eq!((counters.reflected_chats, armed), (1, 1));
}

#[tokio::test]
async fn an_unknown_sender_chat_is_injected_with_the_recipients_exact_binding() {
    let relay = start(quiet()).await;
    let path = format!("/v2/test/inject/unknown-sender/{}", hex(&relay.recipient.root));
    assert_eq!(http(relay.address, "POST", &path).await.0, 409, "offline root");
    let mut recipient = authenticate(&relay, "DEVICE_SPKI").await;
    assert_eq!(http(relay.address, "POST", &path).await, (200, "injected\n".into()));
    let first = delivered(&expect(&mut recipient, "DELIVER").await);
    assert_eq!(http(relay.address, "POST", &path).await.0, 200);
    let second = delivered(&expect(&mut recipient, "DELIVER").await);

    for packet in [&first, &second] {
        let envelope = decode_envelope(packet).expect("strictly valid envelope");
        let h = envelope.header;
        assert_eq!(h.kind, PacketKind::Chat);
        assert_eq!((h.recipient_root, h.recipient_epoch, h.recipient_activation_digest),
                   (relay.recipient.root, relay.recipient.epoch, relay.recipient.activation_digest));
        assert!(h.sender_root != relay.sender.root && h.sender_root != relay.recipient.root);
    }
    let (a, b) = (decode_envelope(&first).unwrap().header, decode_envelope(&second).unwrap().header);
    assert_ne!(a.packet_id, b.packet_id);
    assert_ne!(a.sender_root, b.sender_root);
    assert_eq!(relay.state.fault_counters().0.injected_unknown_sender, 2);
    // The recipient connection stays usable.
    let mut sender = authenticate(&relay, "ROOT_SPKI").await;
    forward(&mut sender, &relay.chat).await;
    expect(&mut recipient, "DELIVER").await;
}

#[tokio::test]
async fn the_control_api_refuses_bad_input_bounds_arming_and_reports_no_identifiers() {
    let relay = start(quiet()).await;
    let root = hex(&relay.recipient.root);
    for path in [format!("/v2/test/arm/drop-receipt/{}", &root[..63]), format!("/v2/test/arm/drop-receipt/{root}0"),
                 format!("/v2/test/arm/drop-receipt/{}g", &root[..63]), "/v2/test/inject/unknown-sender/xyz".into()] {
        assert_eq!(http(relay.address, "POST", &path).await.0, 400, "{path}");
    }
    assert_eq!(http(relay.address, "POST", &format!("/v2/test/arm/drop-everything/{root}")).await.0, 404);
    assert_eq!(http(relay.address, "GET", &format!("/v2/test/arm/drop-receipt/{root}")).await.0, 405);
    let upper = root.to_uppercase();
    for _ in 0..MAX_ARMED {
        assert_eq!(http(relay.address, "POST", &format!("/v2/test/arm/tamper-chat/{upper}")).await.0, 202);
    }
    assert_eq!(http(relay.address, "POST", &format!("/v2/test/arm/tamper-chat/{root}")).await.0, 429);
    let (status, text) = http(relay.address, "GET", "/v2/test/counters").await;
    assert_eq!(status, 200);
    assert_eq!(counter(&text, "armed"), MAX_ARMED as u64);
    assert!(text.lines().all(|line| line.split_once('=').is_some_and(|(_, v)| v.bytes().all(|b| b.is_ascii_digit()))));
    assert!(!text.to_lowercase().contains(&root[..8]));
    assert_eq!(http(relay.address, "POST", "/v2/test/disarm").await.0, 200);
    assert_eq!(relay.state.fault_counters().1, 0);
    assert_eq!(parse_root(&upper), Some(relay.recipient.root));
}

#[test]
fn only_a_debug_loopback_configuration_enables_the_hooks() {
    let debug = V2Config { audience: "ws://127.0.0.1:47821/v2/ws|pda-relay.cbor.v2".into(), debug_loopback: true, trust_proxy: false };
    let production = V2Config { audience: "wss://relay.pda.test:443/v2/ws|pda-relay.cbor.v2".into(), debug_loopback: false, trust_proxy: false };
    assert!(test_faults_enabled(&debug));
    assert!(!test_faults_enabled(&production));
}

#[tokio::test]
async fn errors_are_counted_by_code() {
    let relay = start(quiet()).await;
    let mut sender = authenticate(&relay, "ROOT_SPKI").await;
    forward(&mut sender, &relay.chat).await;
    expect(&mut sender, "ERROR5").await;
    send(&mut sender, &FrameV2::ClientProof { signature_der: &relay.f["POSSESSION_PROOF_DER"] }).await;
    expect(&mut sender, "ERROR9").await;
    let (counters, _, _) = relay.state.fault_counters();
    assert_eq!(counters.errors[ErrorCode::RecipientOffline.code() as usize], 1);
    assert_eq!(counters.errors[ErrorCode::PolicyViolation.code() as usize], 1);
    assert_eq!(counters.forwards_chat, 1);
    assert_eq!(counters.accepted, 0);
}

type StdoutLines = std::io::Lines<BufReader<std::process::ChildStdout>>;

/// Kills the relay when dropped, including when an assertion fails first.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The binary with `env`, or None only when it reports its listen address already in use. The returned stdout
/// lines must stay alive with the child: a closed pipe would make its later stdout writes fail.
fn spawn_binary(env: &[(&str, &str)]) -> Option<(Running, SocketAddr, Vec<String>, StdoutLines)> {
    let sandbox = std::env::temp_dir();
    let mut command = Command::new(env!("CARGO_BIN_EXE_pda-relay"));
    command.current_dir(&sandbox).env_clear().stdout(Stdio::piped()).stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    // Killed on drop from the start, also when an assertion below fails.
    let mut child = Running(command.spawn().unwrap());
    let mut lines = BufReader::new(child.0.stdout.take().unwrap()).lines();
    let Some(first) = lines.next() else {
        let mut stderr = String::new();
        std::io::Read::read_to_string(&mut child.0.stderr.take().unwrap(), &mut stderr).unwrap();
        let status = child.0.wait().unwrap();
        if stderr.contains("AddrInUse") {
            return None;
        }
        panic!("relay exited before listening ({status}): {stderr}");
    };
    let address = first.unwrap().strip_prefix("PDA_RELAY_LISTENING=").unwrap().parse().unwrap();
    let mut rest = vec![lines.next().unwrap().unwrap()];
    if env.iter().any(|(name, value)| *name == "PDA_RELAY_V2_DEBUG_LOOPBACK" && *value == "1") {
        rest.push(lines.next().unwrap().unwrap());
    }
    Some((child, address, rest, lines))
}

/// A debug-loopback relay on a fresh port; only a port taken between choosing and binding is retried.
fn spawn_debug_loopback() -> (Running, SocketAddr, Vec<String>, StdoutLines) {
    for _ in 0..5 {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let listen = format!("127.0.0.1:{port}");
        let audience = format!("ws://127.0.0.1:{port}/v2/ws|pda-relay.cbor.v2");
        if let Some(relay) = spawn_binary(&[
            ("PDA_RELAY_LISTEN", &listen), ("PDA_RELAY_V2_AUDIENCE", &audience), ("PDA_RELAY_V2_DEBUG_LOOPBACK", "1")]) {
            return relay;
        }
    }
    panic!("no free loopback port after 5 attempts");
}

#[tokio::test]
async fn the_binary_serves_the_hooks_only_for_a_debug_loopback_relay() {
    let (debug, address, lines, _debug_stdout) = spawn_debug_loopback();
    assert_eq!(lines, ["PDA_RELAY_V2=enabled", "PDA_RELAY_V2_TEST_FAULTS=enabled"]);
    let (status, text) = http(address, "GET", "/v2/test/counters").await;
    assert_eq!((status, counter(&text, "armed")), (200, 0));
    drop(debug);

    let (production, address, lines, _production_stdout) = spawn_binary(&[
        ("PDA_RELAY_LISTEN", "127.0.0.1:0"), ("PDA_RELAY_V2_AUDIENCE", "wss://relay.pda.test:443/v2/ws|pda-relay.cbor.v2")]).expect("port 0 is never taken");
    assert_eq!(lines, ["PDA_RELAY_V2=enabled"]);
    assert_eq!(http(address, "GET", "/v2/test/counters").await.0, 404);
    let root = "ab".repeat(32);
    assert_eq!(http(address, "POST", &format!("/v2/test/arm/drop-receipt/{root}")).await.0, 404);
    drop(production);
}
