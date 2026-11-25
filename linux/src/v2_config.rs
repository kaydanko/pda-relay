//! Explicit operator configuration for `/v2/ws` (R4 "Audience and public key acceptance").
//!
//! v2 is enabled only by `PDA_RELAY_V2_AUDIENCE`; without it the binary serves v1 alone. The audience is the
//! exact UTF-8 string clients sign and always carries an explicit decimal port:
//! - production `wss://<lowercase ASCII DNS host>:<port>/v2/ws|pda-relay.cbor.v2` (TLS is terminated in front
//!   of this process; the relay validates against this fixed value, never a forwarded Host);
//! - debug `ws://127.0.0.1:<port>/v2/ws|pda-relay.cbor.v2`, accepted only with `PDA_RELAY_V2_DEBUG_LOOPBACK=1`
//!   and only when the relay itself listens on 127.0.0.1 with that same port (cleartext stays on loopback).
//!
//! Host rules match the Android `NetworkRelayAudiencePolicy`: at least two labels, `[a-z0-9-]` labels of
//! 1..63 without leading/trailing hyphen or a reserved `??--` form except `xn--`, the last label letters only
//! or an `xn--` A-label, no IP literals, userinfo, query, fragment, percent escapes or trailing dot.

use std::{
    env, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::Router;
use pda_relay_protocol::{
    v2::{WS_PATH, WS_SUBPROTOCOL},
    v2_auth::{P256Authenticator, MAX_AUDIENCE_BYTES},
    v2_relay::Limits,
};

use crate::v2::{v2_router, UrandomEntropy, V2State};

/// Timer granularity for HELLO/PROOF/PONG deadlines and server pings (frames also check deadlines).
pub const V2_TICK: Duration = Duration::from_millis(250);

pub type ProductionV2 = V2State<P256Authenticator, UrandomEntropy>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2Config {
    pub audience: String,
    pub debug_loopback: bool,
    /// `PDA_RELAY_V2_TRUST_PROXY=1`: production only, behind a TLS proxy on the same host (loopback listener);
    /// availability limits then use the proxy's single `X-Forwarded-For` address.
    pub trust_proxy: bool,
}

impl V2Config {
    /// None when `PDA_RELAY_V2_AUDIENCE` is absent (v2 disabled); an error for any invalid value.
    pub fn from_env(listen: SocketAddr) -> io::Result<Option<Self>> {
        let audience = match env::var("PDA_RELAY_V2_AUDIENCE") {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => return Ok(None),
            Err(_) => return Err(invalid("PDA_RELAY_V2_AUDIENCE is not valid UTF-8")),
        };
        let debug_loopback = match env::var("PDA_RELAY_V2_DEBUG_LOOPBACK") {
            Ok(value) if value == "1" => true,
            Ok(_) => return Err(invalid("PDA_RELAY_V2_DEBUG_LOOPBACK must be exactly 1 when set")),
            Err(env::VarError::NotPresent) => false,
            Err(_) => return Err(invalid("PDA_RELAY_V2_DEBUG_LOOPBACK is not valid UTF-8")),
        };
        let trust_proxy = match env::var("PDA_RELAY_V2_TRUST_PROXY") {
            Ok(value) if value == "1" => true,
            Ok(_) => return Err(invalid("PDA_RELAY_V2_TRUST_PROXY must be exactly 1 when set")),
            Err(env::VarError::NotPresent) => false,
            Err(_) => return Err(invalid("PDA_RELAY_V2_TRUST_PROXY is not valid UTF-8")),
        };
        Self::parse(&audience, debug_loopback, listen)?.with_trust_proxy(trust_proxy, listen).map(Some)
    }

    /// Enables [Self::trust_proxy]: only for a production audience and a loopback listener, so nothing but a
    /// proxy on the same host can supply forwarded addresses.
    pub fn with_trust_proxy(mut self, trust_proxy: bool, listen: SocketAddr) -> io::Result<Self> {
        if trust_proxy {
            if self.debug_loopback {
                return Err(invalid("PDA_RELAY_V2_TRUST_PROXY is for a production audience behind a TLS proxy"));
            }
            if !listen.ip().is_loopback() {
                return Err(invalid("PDA_RELAY_V2_TRUST_PROXY requires PDA_RELAY_LISTEN on loopback (proxy on the same host)"));
            }
        }
        self.trust_proxy = trust_proxy;
        Ok(self)
    }

    pub fn parse(audience: &str, debug_loopback: bool, listen: SocketAddr) -> io::Result<Self> {
        if audience.is_empty() || audience.len() > MAX_AUDIENCE_BYTES || !audience.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(invalid("v2 audience must be 1..512 printable ASCII bytes"));
        }
        let suffix = format!("{WS_PATH}|{WS_SUBPROTOCOL}");
        let rest = audience.strip_suffix(suffix.as_str()).ok_or_else(|| invalid("v2 audience must end with /v2/ws|pda-relay.cbor.v2"))?;
        let (scheme, authority) = rest.split_once("://").ok_or_else(|| invalid("v2 audience needs a scheme"))?;
        if authority.bytes().any(|b| b"@?#%\\/[]".contains(&b)) {
            return Err(invalid("v2 audience authority must be host:port only"));
        }
        let (host, port_text) = authority.split_once(':').ok_or_else(|| invalid("v2 audience needs an explicit port"))?;
        let port = parse_port(port_text)?;
        match (scheme, debug_loopback) {
            ("wss", false) => require_dns_host(host)?,
            ("ws", true) => {
                if host != "127.0.0.1" {
                    return Err(invalid("debug v2 audience host must be 127.0.0.1"));
                }
                if listen.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || listen.port() != port {
                    return Err(invalid("debug v2 audience requires PDA_RELAY_LISTEN=127.0.0.1:<the audience port>"));
                }
            }
            ("ws", false) => return Err(invalid("a ws:// v2 audience needs PDA_RELAY_V2_DEBUG_LOOPBACK=1")),
            ("wss", true) => return Err(invalid("PDA_RELAY_V2_DEBUG_LOOPBACK=1 allows only a ws://127.0.0.1 audience")),
            _ => return Err(invalid("v2 audience scheme must be wss (or ws for debug loopback)")),
        }
        Ok(Self { audience: audience.to_string(), debug_loopback, trust_proxy: false })
    }
}

/// Creates the production v2 relay (P-256 verifier, OS entropy, R4 limits), starts its timer and returns
/// its router. Must run inside the Tokio runtime; serve with `into_make_service_with_connect_info`.
pub fn start_v2(config: &V2Config) -> io::Result<(Router, Arc<ProductionV2>)> {
    let state = V2State::new(P256Authenticator, UrandomEntropy::open()?, config.audience.as_bytes(), Limits::default())
        .ok_or_else(|| invalid("v2 audience rejected by the relay core"))?;
    if config.trust_proxy {
        state.trust_forwarded_for();
    }
    state.start_ticker(V2_TICK);
    let router = v2_router(Arc::clone(&state));
    #[cfg(feature = "test-faults")]
    let router = if config.debug_loopback { router.merge(crate::v2::faults::faults_router(Arc::clone(&state))) } else { router };
    Ok((router, state))
}

/// Whether [start_v2] serves the Stage 6 `/v2/test/*` fault hooks: only a `test-faults` build with a
/// debug-loopback configuration.
pub fn test_faults_enabled(config: &V2Config) -> bool {
    cfg!(feature = "test-faults") && config.debug_loopback
}

fn parse_port(text: &str) -> io::Result<u16> {
    let valid = (1..=5).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit()) && !text.starts_with('0');
    match text.parse::<u32>() {
        Ok(port @ 1..=65535) if valid => Ok(port as u16),
        _ => Err(invalid("v2 audience port must be 1..65535 without leading zeros")),
    }
}

fn require_dns_host(host: &str) -> io::Result<()> {
    let bad = || invalid("v2 audience host must be a lowercase ASCII DNS name");
    if host.is_empty() || host.len() > 253 || host.ends_with('.') {
        return Err(bad());
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return Err(bad());
    }
    for label in &labels {
        let ok = (1..=63).contains(&label.len())
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
            && (label.len() < 4 || &label[2..4] != "--" || label.starts_with("xn--"));
        if !ok {
            return Err(bad());
        }
    }
    let top = labels[labels.len() - 1];
    if top.bytes().all(|b| b.is_ascii_lowercase()) || (top.starts_with("xn--") && top.len() > 4) {
        Ok(())
    } else {
        Err(bad())
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}
