use futures_util::{SinkExt, StreamExt};
use pda_relay_protocol::{
    decode_server_frame, encode_client_frame, ClientFrame, ErrorCode, Limits, ServerFrame,
    WS_SUBPROTOCOL,
};
use std::{
    fs,
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};
use tempfile::TempDir;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
    MaybeTlsStream, WebSocketStream,
};

type ClientSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct RelayProcess {
    child: Child,
    address: SocketAddr,
}

impl RelayProcess {
    fn start(sandbox: &TempDir) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pda-relay"))
            .current_dir(sandbox.path())
            .env_clear()
            .env("HOME", sandbox.path())
            .env("XDG_CONFIG_HOME", sandbox.path())
            .env("XDG_STATE_HOME", sandbox.path())
            .env("XDG_CACHE_HOME", sandbox.path())
            .env("TMPDIR", sandbox.path())
            .env("PDA_RELAY_LISTEN", "127.0.0.1:0")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        let line = lines
            .next()
            .expect("relay startup line")
            .expect("read startup line");
        let address = line
            .strip_prefix("PDA_RELAY_LISTENING=")
            .expect("startup address prefix")
            .parse()
            .unwrap();
        Self { child, address }
    }

    fn stop(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

async fn connect(address: SocketAddr, pda_id: [u8; 32]) -> ClientSocket {
    let mut request = format!("ws://{address}/v1/ws")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(WS_SUBPROTOCOL),
    );
    let (mut socket, _) = connect_async(request).await.unwrap();
    send(
        &mut socket,
        &ClientFrame::Hello {
            min_version: 1,
            max_version: 1,
            pda_id,
        },
    )
    .await;
    assert!(matches!(
        receive(&mut socket).await,
        ServerFrame::HelloOk {
            selected_version: 1
        }
    ));
    socket
}

async fn send(socket: &mut ClientSocket, frame: &ClientFrame<'_>) {
    socket
        .send(Message::Binary(encode_client_frame(frame).unwrap().into()))
        .await
        .unwrap();
}

async fn receive(socket: &mut ClientSocket) -> ServerFrame<'static> {
    loop {
        match socket.next().await.unwrap().unwrap() {
            Message::Binary(bytes) => match decode_server_frame(&bytes, Limits::default()).unwrap()
            {
                ServerFrame::HelloOk { selected_version } => {
                    return ServerFrame::HelloOk { selected_version }
                }
                ServerFrame::Deliver {
                    packet_id,
                    from,
                    opaque_payload,
                } => {
                    return ServerFrame::Deliver {
                        packet_id,
                        from,
                        opaque_payload: Box::leak(opaque_payload.to_vec().into_boxed_slice()),
                    }
                }
                ServerFrame::DeliveryAck {
                    acked_packet_id,
                    from,
                } => {
                    return ServerFrame::DeliveryAck {
                        acked_packet_id,
                        from,
                    }
                }
                ServerFrame::Error {
                    code,
                    related_packet_id,
                } => {
                    return ServerFrame::Error {
                        code,
                        related_packet_id,
                    }
                }
                ServerFrame::Ping { nonce } => {
                    send(socket, &ClientFrame::Pong { nonce }).await;
                }
                ServerFrame::Pong { nonce } => return ServerFrame::Pong { nonce },
            },
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
            other => panic!("unexpected websocket message: {other:?}"),
        }
    }
}

fn regular_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(regular_files(&path));
        } else if path.is_file() {
            files.push(path);
        }
    }
    files
}

#[tokio::test]
async fn restart_discards_routes_and_writes_no_packet_data() {
    let sandbox = TempDir::new().unwrap();
    let pda_a = [0x61; 32];
    let pda_b = [0x62; 32];
    let packet_id = [0x71; 16];
    let canary = b"E2EE_CANARY_COORDINATES_50.4501_30.5234";

    let first = RelayProcess::start(&sandbox);
    let mut a = connect(first.address, pda_a).await;
    let mut b = connect(first.address, pda_b).await;
    send(
        &mut a,
        &ClientFrame::Forward {
            packet_id,
            to: pda_b,
            opaque_payload: canary,
        },
    )
    .await;
    assert_eq!(
        receive(&mut b).await,
        ServerFrame::Deliver {
            packet_id,
            from: pda_a,
            opaque_payload: canary
        }
    );
    send(
        &mut b,
        &ClientFrame::Ack {
            acked_packet_id: packet_id,
            to: pda_a,
        },
    )
    .await;
    assert_eq!(
        receive(&mut a).await,
        ServerFrame::DeliveryAck {
            acked_packet_id: packet_id,
            from: pda_b
        }
    );
    drop((a, b));
    first.stop();

    let files = regular_files(sandbox.path());
    assert!(
        files.is_empty(),
        "relay created persistent files: {files:?}"
    );

    let second = RelayProcess::start(&sandbox);
    let mut reconnected_a = connect(second.address, pda_a).await;
    send(
        &mut reconnected_a,
        &ClientFrame::Forward {
            packet_id,
            to: pda_b,
            opaque_payload: canary,
        },
    )
    .await;
    assert_eq!(
        receive(&mut reconnected_a).await,
        ServerFrame::Error {
            code: ErrorCode::RecipientOffline,
            related_packet_id: Some(packet_id)
        }
    );
    drop(reconnected_a);
    second.stop();

    for path in regular_files(sandbox.path()) {
        let bytes = fs::read(&path).unwrap();
        assert!(
            !bytes.windows(canary.len()).any(|window| window == canary),
            "canary persisted in {path:?}"
        );
    }
}
