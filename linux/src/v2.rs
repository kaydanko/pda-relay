//! `/v2/ws` transport around the sans-IO [RelayCore] (R4 "Relay finite runtime registry").
//!
//! One process-wide core behind one mutex serializes every protocol decision; the mutex is never held across
//! an await. Each connection owns one task that reads its socket and writes its bounded outbound channel.
//! Actions are dispatched under the core lock with non-blocking `try_send`, so cross-connection order equals
//! core order. DELIVER budget is released with [RelayCore::written] only after the frame was written to the
//! socket. A full outbound channel (a peer that does not read its own control replies) kills only that
//! connection. Every socket write is bounded by the PONG window (`Limits::pong_wait_millis`) and abandoned when
//! the connection is killed, so a peer that stops reading cannot keep its socket task alive after the core has
//! dropped it. A timer task drives deadlines and heartbeat; every frame also checks them in the core.
//!
//! The router must be served with `into_make_service_with_connect_info::<SocketAddr>()`: the source address
//! feeds availability limits only (IPv4 per address, IPv6 per /64), never identity.
//! Nothing is persisted or logged per packet; frames are not inspected beyond the core's strict codec.

use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use pda_relay_protocol::{
    v2::{MAX_FRAME_BYTES, WS_PATH, WS_SUBPROTOCOL},
    v2_relay::{Action, Authenticator, ConnKey, Entropy, Limits, RelayCore, SourceKey},
};
use tokio::{
    sync::{mpsc, Notify},
    task::JoinHandle,
};

/// Stage 6 fault hooks (`test-faults` builds only; served only for a debug-loopback relay).
#[cfg(feature = "test-faults")]
#[path = "v2_faults.rs"]
pub mod faults;

/// Outbound slots beyond the recipient queue, for this connection's own control and error replies.
const CONTROL_SLACK: usize = 32;

/// OS CSPRNG from `/dev/urandom` (Linux reference relay; no new dependency). A read failure aborts the
/// process: continuing with predictable connection IDs or nonces would be worse than stopping.
pub struct UrandomEntropy(File);

impl UrandomEntropy {
    pub fn open() -> std::io::Result<Self> {
        File::open("/dev/urandom").map(Self)
    }
}

impl Entropy for UrandomEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        if self.0.read_exact(out).is_err() {
            std::process::abort();
        }
    }
}

enum Out {
    Frame { bytes: Vec<u8>, counted: bool },
    Close,
}

struct Writer {
    tx: mpsc::Sender<Out>,
    kill: Arc<Notify>,
}

struct Inner<A: Authenticator, E: Entropy> {
    core: RelayCore<A, E>,
    writers: HashMap<ConnKey, Writer>,
    next_conn: ConnKey,
    #[cfg(feature = "test-faults")]
    faults: faults::FaultState,
}

/// Shared state of one v2 relay.
pub struct V2State<A: Authenticator, E: Entropy> {
    inner: Mutex<Inner<A, E>>,
    epoch: Instant,
    channel_capacity: usize,
    /// Upper bound for one socket write: the PONG window.
    write_deadline: Duration,
    /// Live per-connection socket tasks, whether or not the core still knows the connection.
    tasks: AtomicUsize,
    /// Behind a same-host TLS proxy: take the client address from its single `X-Forwarded-For` value.
    forwarded_for: AtomicBool,
}

impl<A, E> V2State<A, E>
where
    A: Authenticator + Send + 'static,
    A::Grant: Send,
    E: Entropy + Send + 'static,
{
    /// `audience_utf8` must equal what clients sign, e.g. `wss://relay.example.org:443/v2/ws|pda-relay.cbor.v2`.
    pub fn new(auth: A, entropy: E, audience_utf8: &[u8], limits: Limits) -> Option<Arc<Self>> {
        let core = RelayCore::new(auth, entropy, audience_utf8, limits)?;
        Some(Arc::new(Self {
            inner: Mutex::new(Inner {
                core,
                writers: HashMap::new(),
                next_conn: 1,
                #[cfg(feature = "test-faults")]
                faults: faults::FaultState::new(),
            }),
            epoch: Instant::now(),
            channel_capacity: limits.queue_frames + CONTROL_SLACK,
            write_deadline: Duration::from_millis(limits.pong_wait_millis.max(1)),
            tasks: AtomicUsize::new(0),
            forwarded_for: AtomicBool::new(false),
        }))
    }

    /// Live connections known to the core (for tests and health only; no identities).
    pub fn connection_count(&self) -> usize {
        self.lock().core.connection_count()
    }

    /// Live socket tasks (for tests and health only). A task can outlive its core connection only while it
    /// finishes its last write.
    pub fn socket_tasks(&self) -> usize {
        self.tasks.load(Ordering::SeqCst)
    }

    /// One-way switch for a relay behind a TLS proxy on the same host: from now on only loopback peers are
    /// served, and the availability-limit source is the single IP address in their `X-Forwarded-For` header
    /// (which the proxy must overwrite, never append). Missing, repeated, multi-valued or invalid values are
    /// refused rather than merged into the proxy's own address.
    pub fn trust_forwarded_for(&self) {
        self.forwarded_for.store(true, Ordering::SeqCst);
    }

    /// Starts the timer that drives HELLO/PROOF deadlines and the server heartbeat.
    pub fn start_ticker(self: &Arc<Self>, period: Duration) -> JoinHandle<()> {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let now = state.now();
                let mut inner = state.lock();
                let actions = inner.core.tick(now);
                inner.dispatch(actions);
            }
        })
    }

    fn now(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner<A, E>> {
        // A panic while holding the lock leaves no partial core mutation that later calls could not handle.
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<A: Authenticator, E: Entropy> Inner<A, E> {
    fn dispatch(&mut self, actions: Vec<Action>) {
        #[cfg(feature = "test-faults")]
        let actions = self.faults.apply(&mut self.core, actions);
        for action in actions {
            let (conn, out) = match action {
                Action::Send { conn, frame } => (conn, Out::Frame { bytes: frame, counted: false }),
                Action::Deliver { conn, frame } => (conn, Out::Frame { bytes: frame, counted: true }),
                Action::Close { conn } => (conn, Out::Close),
            };
            let closing = matches!(out, Out::Close);
            let Some(writer) = self.writers.get(&conn) else { continue };
            if writer.tx.try_send(out).is_err() {
                // The connection is not reading: drop it rather than grow memory or block the core.
                writer.kill.notify_one();
                self.writers.remove(&conn);
                self.core.on_closed(conn);
            } else if closing {
                // The core already forgot it; later actions for this key must not reach the socket.
                self.writers.remove(&conn);
            }
        }
    }
}

/// `GET /v2/ws` with subprotocol `pda-relay.cbor.v2` only.
pub fn v2_router<A, E>(state: Arc<V2State<A, E>>) -> Router
where
    A: Authenticator + Send + 'static,
    A::Grant: Send,
    E: Entropy + Send + 'static,
{
    Router::new().route(WS_PATH, any(upgrade::<A, E>)).with_state(state)
}

/// The client address for availability limits: the TCP peer, or behind a trusted same-host proxy the single
/// `X-Forwarded-For` address. None means refuse.
pub fn client_address(forwarded_for: bool, peer: IpAddr, headers: &HeaderMap) -> Option<IpAddr> {
    if !forwarded_for {
        return Some(peer);
    }
    if !peer.to_canonical().is_loopback() {
        return None;
    }
    let mut values = headers.get_all("x-forwarded-for").iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()?.trim().parse::<IpAddr>().ok()
}

/// Availability-limit key of a source address: the full IPv4 address, or the IPv6 /64 prefix.
pub fn source_key(address: IpAddr) -> SourceKey {
    match address {
        IpAddr::V4(v4) => u64::from(u32::from(v4)),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => u64::from(u32::from(v4)),
            // Tagged so no /64 can collide with an IPv4 key.
            None => u64::from_be_bytes(v6.octets()[..8].try_into().expect("8 bytes")) | (1 << 63),
        },
    }
}

async fn upgrade<A, E>(
    State(state): State<Arc<V2State<A, E>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response
where
    A: Authenticator + Send + 'static,
    A::Grant: Send,
    E: Entropy + Send + 'static,
{
    let offered = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|item| item.trim() == WS_SUBPROTOCOL));
    if !offered {
        return (StatusCode::UPGRADE_REQUIRED, "Sec-WebSocket-Protocol: pda-relay.cbor.v2 is required").into_response();
    }
    let Some(client) = client_address(state.forwarded_for.load(Ordering::SeqCst), peer.ip(), &headers) else {
        return (StatusCode::BAD_REQUEST, "untrusted or missing X-Forwarded-For").into_response();
    };
    let source = source_key(client);
    ws.protocols([WS_SUBPROTOCOL])
        .max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| run(socket, state, source))
}

async fn run<A, E>(mut socket: WebSocket, state: Arc<V2State<A, E>>, source: SourceKey)
where
    A: Authenticator + Send + 'static,
    A::Grant: Send,
    E: Entropy + Send + 'static,
{
    struct Task<'a>(&'a AtomicUsize);
    impl Drop for Task<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    state.tasks.fetch_add(1, Ordering::SeqCst);
    let _task = Task(&state.tasks);
    let (tx, mut rx) = mpsc::channel(state.channel_capacity);
    let kill = Arc::new(Notify::new());
    let conn = {
        let mut inner = state.lock();
        let conn = inner.next_conn;
        inner.next_conn += 1;
        inner.writers.insert(conn, Writer { tx, kill: Arc::clone(&kill) });
        let actions = inner.core.accept(conn, source, state.now());
        inner.dispatch(actions);
        conn
    };
    loop {
        tokio::select! {
            biased;
            _ = kill.notified() => break,
            outbound = rx.recv() => match outbound {
                Some(Out::Frame { bytes, counted }) => {
                    let len = bytes.len();
                    if !write(&mut socket, &kill, state.write_deadline, Message::Binary(bytes.into())).await {
                        break;
                    }
                    if counted {
                        state.lock().core.written(conn, len);
                    }
                }
                Some(Out::Close) => {
                    let close = Message::Close(Some(CloseFrame { code: 1008, reason: "".into() }));
                    let _ = write(&mut socket, &kill, state.write_deadline, close).await;
                    break;
                }
                None => break,
            },
            incoming = socket.recv() => {
                let bytes = match incoming {
                    Some(Ok(Message::Binary(bytes))) => bytes.to_vec(),
                    // Text is not a v2 frame; the strict codec answers MALFORMED and closes.
                    Some(Ok(Message::Text(text))) => text.as_str().as_bytes().to_vec(),
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                };
                let mut inner = state.lock();
                #[cfg(feature = "test-faults")]
                inner.faults.incoming(&bytes);
                let actions = inner.core.on_frame(conn, &bytes, state.now());
                inner.dispatch(actions);
            }
        }
    }
    let mut inner = state.lock();
    inner.writers.remove(&conn);
    inner.core.on_closed(conn);
}

/// One bounded socket write: false when it failed, did not finish within `deadline` (the peer stopped reading)
/// or the connection was killed meanwhile.
async fn write(socket: &mut WebSocket, kill: &Notify, deadline: Duration, message: Message) -> bool {
    tokio::select! {
        biased;
        _ = kill.notified() => false,
        written = tokio::time::timeout(deadline, socket.send(message)) => matches!(written, Ok(Ok(()))),
    }
}
