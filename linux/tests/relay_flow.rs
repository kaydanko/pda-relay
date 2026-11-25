use futures_util::{SinkExt, StreamExt};
use pda_relay::{app, config::Config, AppState};
use pda_relay_protocol::{
    decode_server_frame, encode_client_frame, ClientFrame, ErrorCode, Limits, ServerFrame,
    WS_SUBPROTOCOL,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::oneshot};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
    MaybeTlsStream, WebSocketStream,
};

type ClientSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn start_relay() -> (SocketAddr, oneshot::Sender<()>) {
    let config = Config {
        heartbeat_interval: Duration::from_secs(60),
        heartbeat_timeout: Duration::from_secs(120),
        ..Config::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        axum::serve(listener, app(Arc::new(AppState::new(config))))
            .with_graceful_shutdown(async {
                let _ = stop_rx.await;
            })
            .await
            .unwrap();
    });
    (address, stop_tx)
}

async fn connect(address: SocketAddr, pda_id: [u8; 32]) -> ClientSocket {
    let mut request = format!("ws://{address}/v1/ws")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(WS_SUBPROTOCOL),
    );
    let (mut socket, response) = connect_async(request).await.unwrap();
    assert_eq!(
        response.headers().get("Sec-WebSocket-Protocol").unwrap(),
        WS_SUBPROTOCOL
    );
    send_client(
        &mut socket,
        &ClientFrame::Hello {
            min_version: 1,
            max_version: 1,
            pda_id,
        },
    )
    .await;
    assert_eq!(
        recv_server(&mut socket).await,
        ServerFrame::HelloOk {
            selected_version: 1
        }
    );
    socket
}

async fn send_client(socket: &mut ClientSocket, frame: &ClientFrame<'_>) {
    let bytes = encode_client_frame(frame).unwrap();
    socket.send(Message::Binary(bytes.into())).await.unwrap();
}

async fn recv_server(socket: &mut ClientSocket) -> ServerFrame<'static> {
    loop {
        match socket.next().await.unwrap().unwrap() {
            Message::Binary(bytes) => {
                let decoded = decode_server_frame(&bytes, Limits::default()).unwrap();
                return match decoded {
                    ServerFrame::HelloOk { selected_version } => {
                        ServerFrame::HelloOk { selected_version }
                    }
                    ServerFrame::Ping { nonce } => ServerFrame::Ping { nonce },
                    ServerFrame::Pong { nonce } => ServerFrame::Pong { nonce },
                    ServerFrame::Deliver {
                        packet_id,
                        from,
                        opaque_payload,
                    } => ServerFrame::Deliver {
                        packet_id,
                        from,
                        opaque_payload: Box::leak(opaque_payload.to_vec().into_boxed_slice()),
                    },
                    ServerFrame::DeliveryAck {
                        acked_packet_id,
                        from,
                    } => ServerFrame::DeliveryAck {
                        acked_packet_id,
                        from,
                    },
                    ServerFrame::Error {
                        code,
                        related_packet_id,
                    } => ServerFrame::Error {
                        code,
                        related_packet_id,
                    },
                };
            }
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
            other => panic!("unexpected websocket message: {other:?}"),
        }
    }
}

#[tokio::test]
async fn forwards_synthetic_phase1_plaintext_and_routes_recipient_ack() {
    let (address, stop) = start_relay().await;
    let pda_a = [0xa1; 32];
    let pda_b = [0xb2; 32];
    let packet_id = [0x31; 16];
    let synthetic_plaintext = b"synthetic Phase 1 plaintext test bytes";
    let mut a = connect(address, pda_a).await;
    let mut b = connect(address, pda_b).await;

    send_client(
        &mut a,
        &ClientFrame::Forward {
            packet_id,
            to: pda_b,
            opaque_payload: synthetic_plaintext,
        },
    )
    .await;
    assert_eq!(
        recv_server(&mut b).await,
        ServerFrame::Deliver {
            packet_id,
            from: pda_a,
            opaque_payload: synthetic_plaintext
        }
    );

    send_client(
        &mut b,
        &ClientFrame::Ack {
            acked_packet_id: packet_id,
            to: pda_a,
        },
    )
    .await;
    assert_eq!(
        recv_server(&mut a).await,
        ServerFrame::DeliveryAck {
            acked_packet_id: packet_id,
            from: pda_b
        }
    );

    a.close(None).await.unwrap();
    b.close(None).await.unwrap();
    let _ = stop.send(());
}

#[tokio::test]
async fn reports_offline_recipient_without_queueing() {
    let (address, stop) = start_relay().await;
    let pda_a = [0xa1; 32];
    let pda_b = [0xb2; 32];
    let packet_id = [0x41; 16];
    let mut a = connect(address, pda_a).await;

    send_client(
        &mut a,
        &ClientFrame::Forward {
            packet_id,
            to: pda_b,
            opaque_payload: b"synthetic offline plaintext test bytes",
        },
    )
    .await;
    assert_eq!(
        recv_server(&mut a).await,
        ServerFrame::Error {
            code: ErrorCode::RecipientOffline,
            related_packet_id: Some(packet_id)
        }
    );

    a.close(None).await.unwrap();
    let _ = stop.send(());
}

#[tokio::test]
async fn rejects_text_as_an_application_frame() {
    let (address, stop) = start_relay().await;
    let mut socket = connect(address, [3; 32]).await;
    socket.send(Message::Text("not CBOR".into())).await.unwrap();
    assert_eq!(
        recv_server(&mut socket).await,
        ServerFrame::Error {
            code: ErrorCode::MalformedFrame,
            related_packet_id: None
        }
    );
    let _ = stop.send(());
}
