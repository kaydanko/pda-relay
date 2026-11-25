//! `/v2/ws` transport over real loopback WebSockets, with real canonical frames from
//! `protocol/test-vectors/network-v2-signed-vectors.txt` and a fake [Authenticator]. Exercises what the sans-IO
//! core tests cannot: subprotocol gate, socket-to-core wiring, cross-connection DELIVER, budget release after
//! the socket write, timer-driven deadlines and heartbeat, close semantics and route cleanup on disconnect.
//! Real signature verification (package 2) is NOT exercised here.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use pda_relay::v2::{client_address, source_key, v2_router, UrandomEntropy, V2State};
use pda_relay_protocol::{
    v2::{decode_activation, decode_envelope, decode_frame, encode_frame, ActivationV2, Direction, ErrorCode, FrameV2, MAX_FRAME_BYTES, WS_SUBPROTOCOL},
    v2_auth::P256Authenticator,
    v2_relay::{Authenticator, Authority, Entropy, Limits},
};
use tokio::{net::TcpListener, sync::oneshot, time::timeout};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
    MaybeTlsStream, WebSocketStream,
};

const SIGNED: &str = include_str!("../../test-vectors/network-v2-signed-vectors.txt");
const AUDIENCE: &[u8] = b"ws://127.0.0.1:47821/v2/ws|pda-relay.cbor.v2";
const WAIT: Duration = Duration::from_secs(5);

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

fn fixture() -> BTreeMap<&'static str, Vec<u8>> {
    let mut values = BTreeMap::new();
    for line in SIGNED.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=').expect("fixture line");
        let bytes = (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap()).collect();
        assert!(values.insert(name, bytes).is_none(), "duplicate {name}");
    }
    values
}

fn b32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().unwrap()
}

struct Vectors {
    sender_spki: Vec<u8>,
    recipient_spki: Vec<u8>,
    activation: Vec<u8>,
    client_nonce: [u8; 32],
    good_proof: Vec<u8>,
    packet: Vec<u8>,
    sender: Authority,
    recipient: Authority,
}

fn vectors() -> Vectors {
    let v = fixture();
    Vectors {
        sender_spki: v["ROOT_SPKI"].clone(),
        recipient_spki: v["DEVICE_SPKI"].clone(),
        activation: v["ACTIVATION_ENVELOPE"].clone(),
        client_nonce: b32(&v["CLIENT_NONCE"]),
        good_proof: v["POSSESSION_PROOF_DER"].clone(),
        packet: v["PACKET_ENVELOPE"].clone(),
        sender: Authority { root: b32(&v["ROOT_ID"]), epoch: b32(&v["EPOCH"]), activation_digest: b32(&v["ACTIVATION_DIGEST"]) },
        recipient: Authority {
            root: b32(&v["RECIPIENT_ROOT"]),
            epoch: b32(&v["RECIPIENT_EPOCH"]),
            activation_digest: b32(&v["RECIPIENT_ACTIVATION_DIGEST"]),
        },
    }
}

/// Root SPKI -> authority; possession succeeds only for the vector proof and the configured audience.
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
    v: Vectors,
    address: SocketAddr,
    state: Arc<V2State<FakeAuth, Counter>>,
    _stop: oneshot::Sender<()>,
}

async fn start(limits: Limits, tick: Duration) -> Relay {
    let v = vectors();
    let auth = FakeAuth {
        table: vec![(v.sender_spki.clone(), v.sender), (v.recipient_spki.clone(), v.recipient)],
        good_proof: v.good_proof.clone(),
    };
    let state = V2State::new(auth, Counter(0), AUDIENCE, limits).expect("valid audience");
    state.start_ticker(tick);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let router = v2_router(Arc::clone(&state));
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    Relay { v, address, state, _stop: stop }
}

async fn connect(address: SocketAddr) -> Socket {
    let mut request = format!("ws://{address}/v2/ws").into_client_request().unwrap();
    request.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static(WS_SUBPROTOCOL));
    let (socket, response) = connect_async(request).await.unwrap();
    assert_eq!(response.headers().get("Sec-WebSocket-Protocol").unwrap(), WS_SUBPROTOCOL);
    socket
}

async fn send(socket: &mut Socket, frame: &FrameV2<'_>) {
    let bytes = encode_frame(Direction::ClientToServer, frame).unwrap();
    socket.send(Message::Binary(bytes.into())).await.unwrap();
}

/// Next server frame as raw bytes, or None once the server closed the connection.
async fn recv(socket: &mut Socket) -> Option<Vec<u8>> {
    loop {
        match timeout(WAIT, socket.next()).await.expect("server answered in time") {
            Some(Ok(Message::Binary(bytes))) => return Some(bytes.to_vec()),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return None,
            Some(Ok(other)) => panic!("unexpected message {other:?}"),
        }
    }
}

fn name(bytes: &[u8]) -> String {
    match decode_frame(Direction::ServerToClient, bytes).expect("canonical server frame") {
        FrameV2::ServerChallenge { .. } => "CHALLENGE".into(),
        FrameV2::ServerRegistered { .. } => "REGISTERED".into(),
        FrameV2::ServerDeliver { .. } => "DELIVER".into(),
        FrameV2::ServerAccepted { .. } => "ACCEPTED".into(),
        FrameV2::Ping { .. } => "PING".into(),
        FrameV2::Pong { nonce } => format!("PONG{nonce}"),
        FrameV2::ServerError { code, related_packet_id: None } => format!("ERROR{}", code.code()),
        FrameV2::ServerError { code, related_packet_id: Some(_) } => format!("ERROR{}+ID", code.code()),
        other => panic!("client frame from server: {other:?}"),
    }
}

async fn expect(socket: &mut Socket, expected: &str) -> Vec<u8> {
    let bytes = recv(socket).await.unwrap_or_else(|| panic!("closed while expecting {expected}"));
    assert_eq!(name(&bytes), expected);
    bytes
}

async fn expect_error_then_close(socket: &mut Socket, code: ErrorCode) {
    expect(socket, &format!("ERROR{}", code.code())).await;
    assert_eq!(recv(socket).await, None, "connection closes after the error");
}

async fn authenticate(relay: &Relay, spki: &[u8]) -> Socket {
    let mut socket = connect(relay.address).await;
    let authorization = decode_activation(&relay.v.activation).unwrap();
    send(&mut socket, &FrameV2::ClientHello { root_spki: spki, authorization, client_nonce: relay.v.client_nonce }).await;
    expect(&mut socket, "CHALLENGE").await;
    send(&mut socket, &FrameV2::ClientProof { signature_der: &relay.v.good_proof }).await;
    expect(&mut socket, "REGISTERED").await;
    socket
}

async fn forward(socket: &mut Socket, packet: &[u8]) {
    send(socket, &FrameV2::ClientForward { envelope: decode_envelope(packet).unwrap() }).await;
}

async fn until(mut condition: impl FnMut() -> bool) {
    timeout(WAIT, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("condition reached in time");
}

fn quiet() -> Limits {
    // Long timers so only the scenario under test drives the clock.
    Limits { ping_interval_millis: 600_000, pong_wait_millis: 600_000, hello_millis: 600_000, proof_millis: 600_000, ..Limits::default() }
}

#[tokio::test]
async fn the_v2_subprotocol_is_required() {
    let relay = start(quiet(), Duration::from_millis(50)).await;
    let request = format!("ws://{}/v2/ws", relay.address).into_client_request().unwrap();
    match connect_async(request).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => assert_eq!(response.status(), 426),
        other => panic!("expected HTTP 426, got {:?}", other.map(|(_, response)| response.status())),
    }
    assert_eq!(relay.state.connection_count(), 0);
}

#[tokio::test]
async fn forward_reaches_the_recipient_socket_and_the_sender_gets_accepted() {
    let relay = start(quiet(), Duration::from_millis(50)).await;
    let mut sender = authenticate(&relay, &relay.v.sender_spki).await;
    let mut recipient = authenticate(&relay, &relay.v.recipient_spki).await;
    forward(&mut sender, &relay.v.packet).await;
    let delivered = expect(&mut recipient, "DELIVER").await;
    let FrameV2::ServerDeliver { envelope } = decode_frame(Direction::ServerToClient, &delivered).unwrap() else { unreachable!() };
    assert_eq!(envelope.original, &relay.v.packet[..], "ciphertext envelope relayed byte for byte");
    let accepted = expect(&mut sender, "ACCEPTED").await;
    assert_eq!(decode_frame(Direction::ServerToClient, &accepted).unwrap(),
               FrameV2::ServerAccepted { packet_id: envelope.header.packet_id });
}

#[tokio::test]
async fn delivered_frames_release_the_recipient_queue_after_the_socket_write() {
    let relay = start(Limits { queue_frames: 1, ..quiet() }, Duration::from_millis(50)).await;
    let mut sender = authenticate(&relay, &relay.v.sender_spki).await;
    let mut recipient = authenticate(&relay, &relay.v.recipient_spki).await;
    for round in 0..3 {
        // With a one-frame queue, every round after the first is admitted only once `written` released the
        // previous DELIVER; until then the relay answers BACKPRESSURE and the sender retries.
        let mut admitted = false;
        for _ in 0..200 {
            forward(&mut sender, &relay.v.packet).await;
            match name(&recv(&mut sender).await.unwrap()).as_str() {
                "ACCEPTED" => { admitted = true; break; }
                "ERROR6+ID" => tokio::time::sleep(Duration::from_millis(5)).await,
                other => panic!("round {round}: unexpected {other}"),
            }
        }
        assert!(admitted, "round {round} admitted after release");
        expect(&mut recipient, "DELIVER").await;
    }
}

#[tokio::test]
async fn text_frames_close_malformed() {
    let relay = start(quiet(), Duration::from_millis(50)).await;
    let mut socket = connect(relay.address).await;
    socket.send(Message::Text("hello".into())).await.unwrap();
    expect_error_then_close(&mut socket, ErrorCode::Malformed).await;
    until(|| relay.state.connection_count() == 0).await;
}

#[tokio::test]
async fn the_timer_closes_a_silent_connection_at_the_hello_deadline() {
    let relay = start(Limits { hello_millis: 150, ..quiet() }, Duration::from_millis(20)).await;
    let mut socket = connect(relay.address).await;
    until(|| relay.state.connection_count() == 1).await;
    expect_error_then_close(&mut socket, ErrorCode::PolicyViolation).await;
    until(|| relay.state.connection_count() == 0).await;
}

#[tokio::test]
async fn a_live_root_refuses_the_newcomer_and_keeps_serving_the_owner() {
    let relay = start(quiet(), Duration::from_millis(50)).await;
    let mut owner = authenticate(&relay, &relay.v.sender_spki).await;
    let mut newcomer = connect(relay.address).await;
    let authorization = decode_activation(&relay.v.activation).unwrap();
    send(&mut newcomer, &FrameV2::ClientHello { root_spki: &relay.v.sender_spki, authorization, client_nonce: relay.v.client_nonce }).await;
    expect(&mut newcomer, "CHALLENGE").await;
    send(&mut newcomer, &FrameV2::ClientProof { signature_der: &relay.v.good_proof }).await;
    expect_error_then_close(&mut newcomer, ErrorCode::RootAlreadyConnected).await;
    forward(&mut owner, &relay.v.packet).await;
    expect(&mut owner, "ERROR5+ID").await;
    forward(&mut owner, &relay.v.packet).await;
    expect(&mut owner, "ERROR5+ID").await;
}

#[tokio::test]
async fn a_disconnected_recipient_is_offline_for_later_forwards() {
    let relay = start(quiet(), Duration::from_millis(50)).await;
    let mut sender = authenticate(&relay, &relay.v.sender_spki).await;
    let mut recipient = authenticate(&relay, &relay.v.recipient_spki).await;
    recipient.close(None).await.unwrap();
    drop(recipient);
    until(|| relay.state.connection_count() == 1).await;
    forward(&mut sender, &relay.v.packet).await;
    expect(&mut sender, "ERROR5+ID").await;
}

#[tokio::test]
async fn the_server_heartbeat_runs_over_the_socket() {
    let relay = start(Limits { ping_interval_millis: 200, pong_wait_millis: 200, ..quiet() }, Duration::from_millis(20)).await;
    let mut socket = authenticate(&relay, &relay.v.sender_spki).await;
    let ping = expect(&mut socket, "PING").await;
    let FrameV2::Ping { nonce } = decode_frame(Direction::ServerToClient, &ping).unwrap() else { unreachable!() };
    send(&mut socket, &FrameV2::Pong { nonce }).await;
    // The next ping is left unanswered: the pong deadline closes the connection.
    expect(&mut socket, "PING").await;
    expect_error_then_close(&mut socket, ErrorCode::PolicyViolation).await;
    until(|| relay.state.connection_count() == 0).await;
}

/// Hands out the given bytes in order, then zeros.
struct Scripted(Vec<u8>);

impl Entropy for Scripted {
    fn fill(&mut self, out: &mut [u8]) {
        for byte in out {
            *byte = if self.0.is_empty() { 0 } else { self.0.remove(0) };
        }
    }
}

#[tokio::test]
async fn the_production_verifier_registers_the_vector_identity_over_a_socket() {
    // Real root signature and device possession (package 2): the scripted entropy reproduces the vector
    // connection ID and server nonce, so the OpenSSL-made proof is valid for exactly this exchange.
    let f = fixture();
    let script = [f["CONNECTION_ID"].clone(), f["SERVER_NONCE"].clone()].concat();
    let state = V2State::new(P256Authenticator, Scripted(script), &f["AUDIENCE_UTF8"], quiet()).unwrap();
    state.start_ticker(Duration::from_millis(50));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = v2_router(Arc::clone(&state));
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    let mut socket = connect(address).await;
    send(&mut socket, &FrameV2::ClientHello {
        root_spki: &f["ROOT_SPKI"],
        authorization: decode_activation(&f["ACTIVATION_ENVELOPE"]).unwrap(),
        client_nonce: b32(&f["CLIENT_NONCE"]),
    }).await;
    let challenge = expect(&mut socket, "CHALLENGE").await;
    assert_eq!(decode_frame(Direction::ServerToClient, &challenge).unwrap(), FrameV2::ServerChallenge {
        connection_id: f["CONNECTION_ID"].as_slice().try_into().unwrap(),
        server_nonce: b32(&f["SERVER_NONCE"]),
    });
    send(&mut socket, &FrameV2::ClientProof { signature_der: &f["POSSESSION_PROOF_DER"] }).await;
    expect(&mut socket, "REGISTERED").await;

    // A second connection replaying the same proof gets a fresh challenge it cannot answer.
    let mut replay = connect(address).await;
    send(&mut replay, &FrameV2::ClientHello {
        root_spki: &f["ROOT_SPKI"],
        authorization: decode_activation(&f["ACTIVATION_ENVELOPE"]).unwrap(),
        client_nonce: b32(&f["CLIENT_NONCE"]),
    }).await;
    expect(&mut replay, "CHALLENGE").await;
    send(&mut replay, &FrameV2::ClientProof { signature_der: &f["POSSESSION_PROOF_DER"] }).await;
    expect_error_then_close(&mut replay, ErrorCode::AuthFailed).await;
}

#[test]
fn source_keys_group_ipv6_by_slash_64_and_never_collide_with_ipv4() {
    let v4 = |a, b, c, d| source_key(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
    assert_ne!(v4(10, 0, 0, 1), v4(10, 0, 0, 2));
    let net = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1);
    let same_64 = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0xffff, 1, 2, 3);
    let other_64 = Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1);
    assert_eq!(source_key(IpAddr::V6(net)), source_key(IpAddr::V6(same_64)));
    assert_ne!(source_key(IpAddr::V6(net)), source_key(IpAddr::V6(other_64)));
    assert_eq!(source_key(IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped())), v4(10, 0, 0, 1));
    // An IPv6 /64 whose top 64 bits equal a small number still cannot equal an IPv4 key.
    assert_ne!(source_key(IpAddr::V6(Ipv6Addr::new(0, 0, 0x0a00, 1, 0, 0, 0, 0))), v4(10, 0, 0, 1));
}

#[test]
fn urandom_entropy_fills_unpredictable_bytes() {
    let mut entropy = UrandomEntropy::open().expect("/dev/urandom");
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    entropy.fill(&mut a);
    entropy.fill(&mut b);
    assert_ne!(a, [0u8; 32]);
    assert_ne!(a, b);
}

/// Waits for `condition` while answering the server's pings on `socket`, so the waiting itself never makes
/// this connection miss a PONG deadline.
async fn serve_until(socket: &mut Socket, what: &str, mut condition: impl FnMut() -> bool) {
    timeout(WAIT, async {
        while !condition() {
            if let Ok(Some(Ok(Message::Binary(bytes)))) = timeout(Duration::from_millis(10), socket.next()).await {
                assert_eq!(name(&bytes), "PING", "only heartbeats while waiting");
                pong(socket, &bytes).await;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}: not reached in time"));
}

async fn pong(socket: &mut Socket, ping: &[u8]) {
    let FrameV2::Ping { nonce } = decode_frame(Direction::ServerToClient, ping).unwrap() else { unreachable!() };
    send(socket, &FrameV2::Pong { nonce }).await;
}

/// Like [authenticate], over a TCP socket with a small receive buffer so the relay's writes to it block soon
/// once the test stops reading.
async fn authenticate_small_buffer(relay: &Relay, spki: &[u8]) -> Socket {
    let tcp = tokio::net::TcpSocket::new_v4().unwrap();
    tcp.set_recv_buffer_size(4096).unwrap();
    let stream = tcp.connect(relay.address).await.unwrap();
    let mut request = format!("ws://{}/v2/ws", relay.address).into_client_request().unwrap();
    request.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static(WS_SUBPROTOCOL));
    let (mut socket, _) = tokio_tungstenite::client_async(request, MaybeTlsStream::Plain(stream)).await.unwrap();
    let authorization = decode_activation(&relay.v.activation).unwrap();
    send(&mut socket, &FrameV2::ClientHello { root_spki: spki, authorization, client_nonce: relay.v.client_nonce }).await;
    expect(&mut socket, "CHALLENGE").await;
    send(&mut socket, &FrameV2::ClientProof { signature_der: &relay.v.good_proof }).await;
    expect(&mut socket, "REGISTERED").await;
    socket
}

#[tokio::test]
async fn a_recipient_that_stops_reading_loses_its_route_and_its_socket_task() {
    // Generous sender budgets so the recipient's socket buffers fill quickly; short heartbeat so the silent
    // recipient misses its PONG deadline.
    let limits = Limits { frame_burst: 100_000, frames_per_second: 100_000, byte_burst: 1 << 30, bytes_per_second: 1 << 30,
                          ping_interval_millis: 300, pong_wait_millis: 300, ..quiet() };
    let relay = start(limits, Duration::from_millis(20)).await;
    let mut sender = authenticate(&relay, &relay.v.sender_spki).await;
    let recipient = authenticate_small_buffer(&relay, &relay.v.recipient_spki).await;
    assert_eq!(relay.state.socket_tasks(), 2);

    // The recipient never reads again. Forward until the relay refuses with BACKPRESSURE: its bounded queue is
    // full of DELIVERs it cannot write.
    let mut backpressure = false;
    'sending: for _ in 0..20_000 {
        forward(&mut sender, &relay.v.packet).await;
        loop {
            let reply = recv(&mut sender).await.expect("the sender keeps being served");
            match name(&reply).as_str() {
                "ACCEPTED" => break,
                "ERROR6+ID" => { backpressure = true; break 'sending; }
                "ERROR5+ID" => break 'sending, // the recipient was already closed by its missed PONG
                "PING" => pong(&mut sender, &reply).await,
                other => panic!("unexpected {other}"),
            }
        }
    }
    assert!(backpressure, "a non-reading recipient must end in BACKPRESSURE, not unbounded memory");

    // Its missed PONG closes it in the core: the route is freed although its socket cannot be written.
    serve_until(&mut sender, "the silent recipient is closed", || relay.state.connection_count() == 1).await;
    forward(&mut sender, &relay.v.packet).await;
    loop {
        let reply = recv(&mut sender).await.unwrap();
        match name(&reply).as_str() {
            "ERROR5+ID" => break,
            "PING" => pong(&mut sender, &reply).await,
            other => panic!("expected RECIPIENT_OFFLINE, got {other}"),
        }
    }
    // The blocked socket task must end too, instead of waiting forever on a write the peer never reads.
    serve_until(&mut sender, "the silent recipient's socket task ends", || relay.state.socket_tasks() == 1).await;
    assert_eq!(relay.state.connection_count(), 1, "the sender was served throughout");
    drop(recipient);
}

#[tokio::test]
async fn a_message_over_the_frame_limit_ends_only_that_connection_without_a_v2_frame() {
    let relay = start(quiet(), Duration::from_millis(50)).await;
    let mut recipient = authenticate(&relay, &relay.v.recipient_spki).await;

    // Exactly at the limit: still a WebSocket message, so the strict codec answers MALFORMED and closes.
    let mut at_limit = authenticate(&relay, &relay.v.sender_spki).await;
    at_limit.send(Message::Binary(vec![0x80; MAX_FRAME_BYTES].into())).await.unwrap();
    expect_error_then_close(&mut at_limit, ErrorCode::Malformed).await;
    until(|| relay.state.connection_count() == 1).await;

    // One byte over: the WebSocket layer refuses it (R4 allows this), the relay sends no v2 frame, and the
    // connection and its route are gone.
    let mut over = authenticate(&relay, &relay.v.sender_spki).await;
    let _ = over.send(Message::Binary(vec![0x80; MAX_FRAME_BYTES + 1].into())).await;
    loop {
        match timeout(WAIT, over.next()).await.expect("the relay ends the connection in time") {
            Some(Ok(Message::Binary(bytes))) => panic!("no v2 frame after an oversized message, got {}", name(&bytes)),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
            Some(Ok(other)) => panic!("unexpected {other:?}"),
        }
    }
    until(|| relay.state.connection_count() == 1 && relay.state.socket_tasks() == 1).await;

    // Only that connection: the recipient still receives, and the sender's root can register again.
    let mut sender = authenticate(&relay, &relay.v.sender_spki).await;
    forward(&mut sender, &relay.v.packet).await;
    expect(&mut recipient, "DELIVER").await;
    expect(&mut sender, "ACCEPTED").await;
}

fn forwarded(values: &[&str]) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    for value in values {
        headers.append("x-forwarded-for", axum::http::HeaderValue::from_str(value).unwrap());
    }
    headers
}

#[test]
fn the_client_address_is_the_peer_unless_a_same_host_proxy_is_trusted() {
    let peer: IpAddr = "198.51.100.7".parse().unwrap();
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(client_address(false, peer, &forwarded(&["203.0.113.5"])), Some(peer), "not trusted: the header is ignored");
    assert_eq!(client_address(true, loopback, &forwarded(&["203.0.113.5"])), Some("203.0.113.5".parse().unwrap()));
    assert_eq!(client_address(true, loopback, &forwarded(&[" 2001:db8::1 "])), Some("2001:db8::1".parse().unwrap()));
    let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    assert!(client_address(true, mapped, &forwarded(&["203.0.113.5"])).is_some(), "IPv4-mapped loopback peer");
    assert!(client_address(true, "::1".parse().unwrap(), &forwarded(&["203.0.113.5"])).is_some());
    for refused in [&[][..], &["203.0.113.5, 198.51.100.9"][..], &["203.0.113.5", "198.51.100.9"][..], &["unknown"][..], &[""][..]] {
        assert_eq!(client_address(true, loopback, &forwarded(refused)), None, "{refused:?}");
    }
    assert_eq!(client_address(true, peer, &forwarded(&["203.0.113.5"])), None, "only the same-host proxy may forward");
}

async fn connect_forwarded(address: SocketAddr, value: Option<&str>) -> Result<Socket, tokio_tungstenite::tungstenite::Error> {
    let mut request = format!("ws://{address}/v2/ws").into_client_request().unwrap();
    request.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static(WS_SUBPROTOCOL));
    if let Some(value) = value {
        request.headers_mut().insert("X-Forwarded-For", HeaderValue::from_str(value).unwrap());
    }
    connect_async(request).await.map(|(socket, _)| socket)
}

#[tokio::test]
async fn behind_a_trusted_proxy_each_forwarded_client_has_its_own_limits() {
    // One unauthenticated connection per source: a second one from the same client is refused.
    let relay = start(Limits { max_unauthenticated_per_source: 1, ..quiet() }, Duration::from_millis(50)).await;
    relay.state.trust_forwarded_for();
    let _first = connect_forwarded(relay.address, Some("203.0.113.5")).await.expect("first client");
    let mut same = connect_forwarded(relay.address, Some("203.0.113.5")).await.expect("upgrade");
    expect_error_then_close(&mut same, ErrorCode::RateLimit).await;
    let _other = connect_forwarded(relay.address, Some("198.51.100.9")).await.expect("another client is independent");
    until(|| relay.state.connection_count() == 2).await;
    match connect_forwarded(relay.address, None).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => assert_eq!(response.status(), 400),
        other => panic!("expected HTTP 400 without X-Forwarded-For, got {:?}", other.map(|_| ())),
    }
    match connect_forwarded(relay.address, Some("203.0.113.5, 198.51.100.9")).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => assert_eq!(response.status(), 400),
        other => panic!("expected HTTP 400 for an appended chain, got {:?}", other.map(|_| ())),
    }
}

