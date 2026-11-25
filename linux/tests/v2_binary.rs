//! The real `pda-relay` binary with explicit `/v2/ws` configuration (env only, isolated sandbox):
//! production and debug-loopback audiences, v2 disabled by default, invalid configuration refused before
//! binding, and v1 unaffected. The production verifier answers a genuine HELLO with a CHALLENGE; the vector
//! proof (made for another connection ID and nonce) is refused, as it must be with OS entropy.

use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Lines, Read},
    net::{SocketAddr, TcpListener},
    process::{Child, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};

use futures_util::{SinkExt, StreamExt};
use pda_relay_protocol::{
    decode_server_frame, encode_client_frame,
    v2::{decode_activation, decode_frame, encode_frame, Direction, ErrorCode, FrameV2, WS_SUBPROTOCOL},
    ClientFrame, Limits, ServerFrame, WS_SUBPROTOCOL as V1_SUBPROTOCOL,
};
use tempfile::TempDir;
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
    MaybeTlsStream, WebSocketStream,
};

const SIGNED: &str = include_str!("../../test-vectors/network-v2-signed-vectors.txt");
const PRODUCTION: &str = "wss://relay.pda.test:443/v2/ws|pda-relay.cbor.v2";
const WAIT: Duration = Duration::from_secs(5);

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

fn command(sandbox: &TempDir, env: &[(&str, &str)]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pda-relay"));
    command
        .current_dir(sandbox.path())
        .env_clear()
        .env("HOME", sandbox.path())
        .env("TMPDIR", sandbox.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    command
}

struct Relay {
    child: Child,
    address: SocketAddr,
    v2: bool,
    /// Kept open for the relay's lifetime: a closed pipe would make its later stdout writes fail.
    _stdout: Lines<BufReader<ChildStdout>>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(sandbox: &TempDir, env: &[(&str, &str)]) -> Relay {
    try_start(sandbox, env).expect("the requested port was taken")
}

/// None only when the binary reports that its listen address is already in use; any other early exit panics
/// with the child's stderr.
fn try_start(sandbox: &TempDir, env: &[(&str, &str)]) -> Option<Relay> {
    let mut child = command(sandbox, env).spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let Some(first) = lines.next() else {
        let mut stderr = String::new();
        child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
        let status = child.wait().unwrap();
        if stderr.contains("AddrInUse") {
            return None;
        }
        panic!("relay exited before listening ({status}): {stderr}");
    };
    let v2 = env.iter().any(|(name, _)| *name == "PDA_RELAY_V2_AUDIENCE");
    // From here on the relay is killed on drop, also when an assertion below fails.
    let mut relay = Relay { child, address: ([0, 0, 0, 0], 0).into(), v2, _stdout: lines };
    relay.address = first.unwrap().strip_prefix("PDA_RELAY_LISTENING=").expect("listening line").parse().unwrap();
    // The v2 lines, when present, are printed immediately after the listening line and before serving.
    if v2 {
        assert_eq!(relay._stdout.next().unwrap().unwrap(), "PDA_RELAY_V2=enabled");
        let debug = env.contains(&("PDA_RELAY_V2_DEBUG_LOOPBACK", "1"));
        if cfg!(feature = "test-faults") && debug {
            assert_eq!(relay._stdout.next().unwrap().unwrap(), "PDA_RELAY_V2_TEST_FAULTS=enabled");
        }
    }
    Some(relay)
}

fn free_loopback_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A debug-loopback relay on a fresh loopback port. The port is free when chosen but could be taken before the
/// relay binds it (other processes use ephemeral ports too), so only that exact failure is retried.
fn start_debug_loopback(sandbox: &TempDir) -> (Relay, u16) {
    for _ in 0..5 {
        let port = free_loopback_port();
        let listen = format!("127.0.0.1:{port}");
        let audience = format!("ws://127.0.0.1:{port}/v2/ws|pda-relay.cbor.v2");
        let env = [("PDA_RELAY_LISTEN", listen.as_str()), ("PDA_RELAY_V2_AUDIENCE", audience.as_str()),
                   ("PDA_RELAY_V2_DEBUG_LOOPBACK", "1")];
        if let Some(relay) = try_start(sandbox, &env) {
            return (relay, port);
        }
    }
    panic!("no free loopback port after 5 attempts");
}

async fn connect_v2(address: SocketAddr) -> Result<Socket, tokio_tungstenite::tungstenite::Error> {
    let mut request = format!("ws://{address}/v2/ws").into_client_request().unwrap();
    request.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static(WS_SUBPROTOCOL));
    connect_async(request).await.map(|(socket, _)| socket)
}

async fn next_frame(socket: &mut Socket) -> Option<Vec<u8>> {
    loop {
        match timeout(WAIT, socket.next()).await.expect("answer in time") {
            Some(Ok(Message::Binary(bytes))) => return Some(bytes.to_vec()),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            _ => return None,
        }
    }
}

/// Genuine HELLO -> CHALLENGE from the production verifier, then the (foreign) vector proof -> AUTH_FAILED.
async fn v2_handshake_is_served_by_the_production_verifier(address: SocketAddr) {
    let f = fixture();
    let mut socket = connect_v2(address).await.expect("v2 route served");
    let hello = encode_frame(Direction::ClientToServer, &FrameV2::ClientHello {
        root_spki: &f["ROOT_SPKI"],
        authorization: decode_activation(&f["ACTIVATION_ENVELOPE"]).unwrap(),
        client_nonce: f["CLIENT_NONCE"].as_slice().try_into().unwrap(),
    }).unwrap();
    socket.send(Message::Binary(hello.into())).await.unwrap();
    let challenge = next_frame(&mut socket).await.expect("challenge");
    let FrameV2::ServerChallenge { connection_id, .. } = decode_frame(Direction::ServerToClient, &challenge).unwrap() else {
        panic!("expected CHALLENGE");
    };
    assert_ne!(connection_id[..], f["CONNECTION_ID"][..], "fresh OS-random connection ID");
    let proof = encode_frame(Direction::ClientToServer, &FrameV2::ClientProof { signature_der: &f["POSSESSION_PROOF_DER"] }).unwrap();
    socket.send(Message::Binary(proof.into())).await.unwrap();
    let error = next_frame(&mut socket).await.expect("error frame");
    assert_eq!(decode_frame(Direction::ServerToClient, &error).unwrap(),
               FrameV2::ServerError { code: ErrorCode::AuthFailed, related_packet_id: None });
    assert_eq!(next_frame(&mut socket).await, None, "closed after AUTH_FAILED");
}

async fn v1_still_works(address: SocketAddr) {
    let mut request = format!("ws://{address}/v1/ws").into_client_request().unwrap();
    request.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static(V1_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.unwrap();
    let hello = encode_client_frame(&ClientFrame::Hello { min_version: 1, max_version: 1, pda_id: [7; 32] }).unwrap();
    socket.send(Message::Binary(hello.into())).await.unwrap();
    let reply = next_frame(&mut socket).await.unwrap();
    assert!(matches!(decode_server_frame(&reply, Limits::default()).unwrap(), ServerFrame::HelloOk { selected_version: 1 }));
}

#[tokio::test]
async fn a_production_audience_serves_v2_next_to_v1() {
    let sandbox = TempDir::new().unwrap();
    let relay = start(&sandbox, &[("PDA_RELAY_LISTEN", "127.0.0.1:0"), ("PDA_RELAY_V2_AUDIENCE", PRODUCTION)]);
    assert!(relay.v2);
    v2_handshake_is_served_by_the_production_verifier(relay.address).await;
    v1_still_works(relay.address).await;
}

#[tokio::test]
async fn the_debug_loopback_audience_serves_v2_on_its_own_port() {
    let sandbox = TempDir::new().unwrap();
    let (relay, port) = start_debug_loopback(&sandbox);
    assert_eq!(relay.address.port(), port);
    v2_handshake_is_served_by_the_production_verifier(relay.address).await;
}

#[tokio::test]
async fn without_an_audience_v2_is_not_served() {
    let sandbox = TempDir::new().unwrap();
    let relay = start(&sandbox, &[("PDA_RELAY_LISTEN", "127.0.0.1:0")]);
    match connect_v2(relay.address).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => assert_eq!(response.status(), 404),
        other => panic!("expected HTTP 404, got {:?}", other.map(|_| ())),
    }
    v1_still_works(relay.address).await;
}

#[test]
fn invalid_v2_configuration_stops_the_binary_before_it_listens() {
    let sandbox = TempDir::new().unwrap();
    let port = free_loopback_port().to_string();
    let debug_audience = format!("ws://127.0.0.1:{port}/v2/ws|pda-relay.cbor.v2");
    let debug_listen = format!("127.0.0.1:{port}");
    let cases: [&[(&str, &str)]; 9] = [
        &[("PDA_RELAY_V2_AUDIENCE", "wss://relay.pda.test/v2/ws|pda-relay.cbor.v2")],
        &[("PDA_RELAY_V2_AUDIENCE", &debug_audience), ("PDA_RELAY_LISTEN", "127.0.0.1:0")],
        &[("PDA_RELAY_V2_AUDIENCE", &debug_audience), ("PDA_RELAY_V2_DEBUG_LOOPBACK", "1"), ("PDA_RELAY_LISTEN", "0.0.0.0:0")],
        &[("PDA_RELAY_V2_AUDIENCE", PRODUCTION), ("PDA_RELAY_V2_DEBUG_LOOPBACK", "yes")],
        // Otherwise valid debug loopback, but the flag is not exactly "1".
        &[("PDA_RELAY_V2_AUDIENCE", &debug_audience), ("PDA_RELAY_V2_DEBUG_LOOPBACK", "yes"), ("PDA_RELAY_LISTEN", &debug_listen)],
        &[("PDA_RELAY_V2_AUDIENCE", "")],
        // Trusting a proxy needs a loopback listener, and never applies to debug loopback.
        &[("PDA_RELAY_V2_AUDIENCE", PRODUCTION), ("PDA_RELAY_V2_TRUST_PROXY", "1"), ("PDA_RELAY_LISTEN", "0.0.0.0:0")],
        &[("PDA_RELAY_V2_AUDIENCE", PRODUCTION), ("PDA_RELAY_V2_TRUST_PROXY", "yes"), ("PDA_RELAY_LISTEN", "127.0.0.1:0")],
        &[("PDA_RELAY_V2_AUDIENCE", &debug_audience), ("PDA_RELAY_V2_DEBUG_LOOPBACK", "1"), ("PDA_RELAY_LISTEN", &debug_listen),
          ("PDA_RELAY_V2_TRUST_PROXY", "1")],
    ];
    for env in cases {
        let mut child = command(&sandbox, env).spawn().unwrap();
        let deadline = Instant::now() + WAIT;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                // Never leave a listening relay behind when this assertion fails.
                let _ = child.kill();
                let _ = child.wait();
                panic!("{env:?}: relay kept running");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(!status.success(), "{env:?}: exit status {status}");
        let mut out = String::new();
        std::io::Read::read_to_string(&mut child.stdout.take().unwrap(), &mut out).unwrap();
        assert!(!out.contains("PDA_RELAY_LISTENING="), "{env:?}: listened before refusing");
    }
}

/// A default build has no Stage 6 fault hooks, not even for a debug-loopback relay (`v2_faults.rs` covers
/// the `test-faults` build).
#[cfg(not(feature = "test-faults"))]
#[test]
fn a_default_build_serves_no_fault_hooks() {
    use std::io::Write;
    let sandbox = TempDir::new().unwrap();
    let (relay, _) = start_debug_loopback(&sandbox);
    for (method, path) in [("GET", "/v2/test/counters".to_string()), ("POST", format!("/v2/test/arm/drop-receipt/{}", "ab".repeat(32)))] {
        let mut stream = std::net::TcpStream::connect(relay.address).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 404"), "{path}: {response}");
    }
}

#[tokio::test]
async fn a_relay_behind_a_same_host_proxy_requires_the_forwarded_client_address() {
    let sandbox = TempDir::new().unwrap();
    let mut relay = start(&sandbox, &[("PDA_RELAY_LISTEN", "127.0.0.1:0"), ("PDA_RELAY_V2_AUDIENCE", PRODUCTION),
                                      ("PDA_RELAY_V2_TRUST_PROXY", "1")]);
    assert_eq!(relay._stdout.next().unwrap().unwrap(), "PDA_RELAY_V2_TRUST_PROXY=enabled");
    match connect_v2(relay.address).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => assert_eq!(response.status(), 400),
        other => panic!("expected HTTP 400 without X-Forwarded-For, got {:?}", other.map(|_| ())),
    }
    let mut request = format!("ws://{}/v2/ws", relay.address).into_client_request().unwrap();
    request.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static(WS_SUBPROTOCOL));
    request.headers_mut().insert("X-Forwarded-For", HeaderValue::from_static("203.0.113.5"));
    assert!(connect_async(request).await.is_ok(), "the proxy's forwarded client is served");
}

