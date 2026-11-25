pub mod config;
pub mod routes;
/// Relay v2 `/v2/ws` transport around the sans-IO protocol core.
pub mod v2;
/// Explicit `/v2/ws` audience configuration and production wiring (enabled only by `PDA_RELAY_V2_AUDIENCE`).
pub mod v2_config;

use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use config::Config;
use pda_relay_protocol::{
    decode_client_frame, encode_server_frame, ClientFrame, ErrorCode, PacketId, PdaId,
    ProtocolError, ServerFrame, PROTOCOL_V1, WS_SUBPROTOCOL,
};
use routes::{RegisterError, RouteEntry, RouteTable};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, info, warn};

#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub routes: RouteTable,
    connections: Arc<Semaphore>,
    next_connection_id: AtomicU64,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let max_connections = config.max_connections;
        Self {
            config,
            routes: RouteTable::new(),
            connections: Arc::new(Semaphore::new(max_connections)),
            next_connection_id: AtomicU64::new(1),
        }
    }
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/ws", any(websocket_handler))
        .with_state(state)
}

async fn websocket_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !offers_subprotocol(&headers) {
        return (
            StatusCode::UPGRADE_REQUIRED,
            "Sec-WebSocket-Protocol: pda-relay.cbor.v1 is required",
        )
            .into_response();
    }
    let permit = match Arc::clone(&state.connections).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "connection limit reached").into_response()
        }
    };
    let max_frame_bytes = state.config.max_frame_bytes;
    ws.protocols([WS_SUBPROTOCOL])
        .max_message_size(max_frame_bytes)
        .max_frame_size(max_frame_bytes)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            run_session(socket, state).await;
        })
}

fn offers_subprotocol(headers: &HeaderMap) -> bool {
    headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|item| item.trim() == WS_SUBPROTOCOL))
}

async fn run_session(mut socket: WebSocket, state: Arc<AppState>) {
    let connection_id = state.next_connection_id.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(state.config.outbound_queue_messages);

    let hello = tokio::time::timeout(state.config.hello_timeout, socket.recv()).await;
    let pda_id = match hello {
        Ok(Some(Ok(Message::Binary(bytes)))) => {
            match decode_client_frame(&bytes, state.config.protocol_limits()) {
                Ok(ClientFrame::Hello {
                    min_version,
                    max_version,
                    pda_id,
                }) if min_version <= PROTOCOL_V1 && PROTOCOL_V1 <= max_version => pda_id,
                Ok(ClientFrame::Hello { .. }) => {
                    send_error(&mut socket, ErrorCode::VersionUnsupported, None).await;
                    close_policy(&mut socket, "unsupported protocol version").await;
                    return;
                }
                Ok(_) => {
                    send_error(&mut socket, ErrorCode::HelloRequired, None).await;
                    close_policy(&mut socket, "HELLO must be the first application frame").await;
                    return;
                }
                Err(ProtocolError::FrameTooLarge | ProtocolError::PayloadTooLarge) => {
                    send_error(&mut socket, ErrorCode::PacketTooLarge, None).await;
                    close_size(&mut socket).await;
                    return;
                }
                Err(_) => {
                    send_error(&mut socket, ErrorCode::MalformedFrame, None).await;
                    close_policy(&mut socket, "malformed HELLO").await;
                    return;
                }
            }
        }
        Ok(Some(Ok(_))) => {
            send_error(&mut socket, ErrorCode::HelloRequired, None).await;
            close_policy(&mut socket, "binary HELLO required").await;
            return;
        }
        Ok(Some(Err(error))) => {
            debug!(%error, "websocket receive failed during HELLO");
            return;
        }
        Ok(None) => return,
        Err(_) => {
            close_policy(&mut socket, "HELLO timeout").await;
            return;
        }
    };

    if state
        .routes
        .register(pda_id, RouteEntry { connection_id, tx })
        .await
        == Err(RegisterError::RouteInUse)
    {
        send_error(&mut socket, ErrorCode::RouteInUse, None).await;
        close_policy(&mut socket, "PDA route already in use").await;
        return;
    }
    if send_frame(
        &mut socket,
        &ServerFrame::HelloOk {
            selected_version: PROTOCOL_V1,
        },
    )
    .await
    .is_err()
    {
        state.routes.remove_if_current(&pda_id, connection_id).await;
        return;
    }

    info!(connection_id, "PDA route registered");
    let mut heartbeat = tokio::time::interval(state.config.heartbeat_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let mut outstanding_ping: Option<(u64, Instant)> = None;
    let mut next_nonce = connection_id;
    let mut malformed_count = 0_u32;
    let mut rate = RateLimiter::new(state.config.packets_per_second);

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Binary(bytes))) => {
                        if !rate.allow() {
                            send_error(&mut socket, ErrorCode::RateLimited, None).await;
                            close_policy(&mut socket, "rate limit exceeded").await;
                            break;
                        }
                        match decode_client_frame(&bytes, state.config.protocol_limits()) {
                            Ok(frame) => {
                                if handle_client_frame(frame, pda_id, &state, &mut socket, &mut outstanding_ping).await.is_err() {
                                    break;
                                }
                            }
                            Err(ProtocolError::FrameTooLarge | ProtocolError::PayloadTooLarge) => {
                                send_error(&mut socket, ErrorCode::PacketTooLarge, None).await;
                                close_size(&mut socket).await;
                                break;
                            }
                            Err(_) => {
                                malformed_count += 1;
                                warn!(connection_id, malformed_count, "malformed application frame");
                                send_error(&mut socket, ErrorCode::MalformedFrame, None).await;
                                if malformed_count >= state.config.malformed_frame_threshold {
                                    close_policy(&mut socket, "malformed frame threshold reached").await;
                                    break;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Text(_))) => {
                        malformed_count += 1;
                        send_error(&mut socket, ErrorCode::MalformedFrame, None).await;
                        if malformed_count >= state.config.malformed_frame_threshold {
                            close_policy(&mut socket, "binary application frames required").await;
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Err(error)) => {
                        debug!(%error, connection_id, "websocket receive failed");
                        break;
                    }
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(bytes) => {
                        if socket.send(Message::Binary(bytes.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            _ = heartbeat.tick() => {
                if outstanding_ping.is_some_and(|(_, sent)| sent.elapsed() >= state.config.heartbeat_timeout) {
                    close_policy(&mut socket, "heartbeat timeout").await;
                    break;
                }
                if outstanding_ping.is_none() {
                    next_nonce = next_nonce.wrapping_add(1);
                    if send_frame(&mut socket, &ServerFrame::Ping { nonce: next_nonce }).await.is_err() {
                        break;
                    }
                    outstanding_ping = Some((next_nonce, Instant::now()));
                }
            }
        }
    }

    state.routes.remove_if_current(&pda_id, connection_id).await;
    info!(connection_id, "PDA route removed");
}

async fn handle_client_frame(
    frame: ClientFrame<'_>,
    sender: PdaId,
    state: &AppState,
    socket: &mut WebSocket,
    outstanding_ping: &mut Option<(u64, Instant)>,
) -> Result<(), ()> {
    match frame {
        ClientFrame::Hello { .. } => send_error(socket, ErrorCode::HelloRequired, None).await,
        ClientFrame::Ping { nonce } => {
            let _ = send_frame(socket, &ServerFrame::Pong { nonce }).await;
        }
        ClientFrame::Pong { nonce } => {
            if outstanding_ping.is_some_and(|(expected, _)| expected == nonce) {
                *outstanding_ping = None;
            }
        }
        ClientFrame::Forward {
            packet_id,
            to,
            opaque_payload,
        } => {
            let encoded = encode_server_frame(&ServerFrame::Deliver {
                packet_id,
                from: sender,
                opaque_payload,
            })
            .map_err(|_| ())?;
            route_or_error(state, socket, to, packet_id, encoded).await;
        }
        ClientFrame::Ack {
            acked_packet_id,
            to,
        } => {
            let encoded = encode_server_frame(&ServerFrame::DeliveryAck {
                acked_packet_id,
                from: sender,
            })
            .map_err(|_| ())?;
            route_or_error(state, socket, to, acked_packet_id, encoded).await;
        }
    }
    Ok(())
}

async fn route_or_error(
    state: &AppState,
    socket: &mut WebSocket,
    to: PdaId,
    packet_id: PacketId,
    encoded: Vec<u8>,
) {
    let Some(route) = state.routes.lookup(&to).await else {
        send_error(socket, ErrorCode::RecipientOffline, Some(packet_id)).await;
        return;
    };
    match route.tx.try_send(encoded) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            send_error(socket, ErrorCode::Backpressure, Some(packet_id)).await
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            state
                .routes
                .remove_if_current(&to, route.connection_id)
                .await;
            send_error(socket, ErrorCode::RecipientOffline, Some(packet_id)).await;
        }
    }
}

async fn send_error(socket: &mut WebSocket, code: ErrorCode, related_packet_id: Option<PacketId>) {
    let _ = send_frame(
        socket,
        &ServerFrame::Error {
            code,
            related_packet_id,
        },
    )
    .await;
}

async fn send_frame(socket: &mut WebSocket, frame: &ServerFrame<'_>) -> Result<(), ()> {
    let bytes = encode_server_frame(frame).map_err(|_| ())?;
    socket
        .send(Message::Binary(bytes.into()))
        .await
        .map_err(|_| ())
}

async fn close_policy(socket: &mut WebSocket, reason: &'static str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: 1008,
            reason: reason.into(),
        })))
        .await;
}

async fn close_size(socket: &mut WebSocket) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: 1009,
            reason: "packet too large".into(),
        })))
        .await;
}

#[derive(Debug)]
struct RateLimiter {
    limit: u32,
    window_started: Instant,
    count: u32,
}

impl RateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            window_started: Instant::now(),
            count: 0,
        }
    }

    fn allow(&mut self) -> bool {
        if self.window_started.elapsed().as_secs() >= 1 {
            self.window_started = Instant::now();
            self.count = 0;
        }
        if self.count >= self.limit {
            return false;
        }
        self.count += 1;
        true
    }
}
