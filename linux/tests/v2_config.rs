//! `/v2/ws` audience configuration: what an operator may and may not configure.

use std::net::SocketAddr;

use pda_relay::v2_config::V2Config;

const SUFFIX: &str = "/v2/ws|pda-relay.cbor.v2";

fn listen(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn production(audience: &str) -> bool {
    V2Config::parse(audience, false, listen("127.0.0.1:8080")).is_ok()
}

#[test]
fn production_audiences_need_a_lowercase_dns_host_and_an_explicit_port() {
    for ok in [
        "wss://relay.pda.test:443/v2/ws|pda-relay.cbor.v2",
        "wss://a.b.example:8443/v2/ws|pda-relay.cbor.v2",
        "wss://xn--80ak6aa92e.xn--p1ai:443/v2/ws|pda-relay.cbor.v2",
        "wss://r1-2.example.org:65535/v2/ws|pda-relay.cbor.v2",
    ] {
        let config = V2Config::parse(ok, false, listen("0.0.0.0:8080")).unwrap_or_else(|e| panic!("{ok}: {e}"));
        assert_eq!(config, V2Config { audience: ok.to_string(), debug_loopback: false, trust_proxy: false });
    }
    for bad in [
        "wss://relay.pda.test/v2/ws|pda-relay.cbor.v2",               // port omitted
        "wss://relay.pda.test:0/v2/ws|pda-relay.cbor.v2",
        "wss://relay.pda.test:0443/v2/ws|pda-relay.cbor.v2",
        "wss://relay.pda.test:65536/v2/ws|pda-relay.cbor.v2",
        "wss://relay.pda.test:44a/v2/ws|pda-relay.cbor.v2",
        "wss://Relay.pda.test:443/v2/ws|pda-relay.cbor.v2",           // uppercase
        "wss://relay.pda.test.:443/v2/ws|pda-relay.cbor.v2",          // trailing dot
        "wss://localhost:443/v2/ws|pda-relay.cbor.v2",                // single label
        "wss://10.0.0.1:443/v2/ws|pda-relay.cbor.v2",                 // IPv4 literal
        "wss://[::1]:443/v2/ws|pda-relay.cbor.v2",                    // IPv6 literal
        "wss://user@relay.pda.test:443/v2/ws|pda-relay.cbor.v2",
        "wss://relay.pda.test:443/v2/ws?x|pda-relay.cbor.v2",
        "wss://relay.pda.test:443/v1/ws|pda-relay.cbor.v2",
        "wss://relay.pda.test:443/v2/ws|pda-relay.cbor.v1",
        "wss://relay.pda.test:443/v2/ws",
        "https://relay.pda.test:443/v2/ws|pda-relay.cbor.v2",
        "wss://-relay.pda.test:443/v2/ws|pda-relay.cbor.v2",
        "wss://ab--c.pda.test:443/v2/ws|pda-relay.cbor.v2",           // reserved ??-- form
        "wss://relay.pda.t3st:443/v2/ws|pda-relay.cbor.v2",           // top label not letters
        "wss://relay.pda.test:443:1/v2/ws|pda-relay.cbor.v2",
        "wss://rélay.pda.test:443/v2/ws|pda-relay.cbor.v2",           // non-ASCII
        "",
    ] {
        assert!(!production(bad), "accepted {bad:?}");
    }
    let long_label = format!("wss://{}.example:443{SUFFIX}", "a".repeat(64));
    assert!(!production(&long_label));
    let too_long = format!("wss://{}.example:443{SUFFIX}", vec!["a".repeat(60); 8].join("."));
    assert!(too_long.len() > 512 && !production(&too_long));
}

#[test]
fn debug_loopback_is_explicit_cleartext_on_127_0_0_1_with_the_listening_port() {
    let audience = "ws://127.0.0.1:47821/v2/ws|pda-relay.cbor.v2";
    let config = V2Config::parse(audience, true, listen("127.0.0.1:47821")).unwrap();
    assert!(config.debug_loopback);

    assert!(V2Config::parse(audience, false, listen("127.0.0.1:47821")).is_err(), "ws needs the debug flag");
    assert!(V2Config::parse(audience, true, listen("127.0.0.1:47822")).is_err(), "port must equal the listen port");
    assert!(V2Config::parse(audience, true, listen("0.0.0.0:47821")).is_err(), "must listen on loopback only");
    assert!(V2Config::parse(audience, true, listen("[::1]:47821")).is_err());
    assert!(V2Config::parse("ws://localhost:47821/v2/ws|pda-relay.cbor.v2", true, listen("127.0.0.1:47821")).is_err());
    assert!(V2Config::parse("ws://10.0.2.2:47821/v2/ws|pda-relay.cbor.v2", true, listen("127.0.0.1:47821")).is_err());
    assert!(V2Config::parse("wss://relay.pda.test:443/v2/ws|pda-relay.cbor.v2", true, listen("127.0.0.1:443")).is_err(),
            "the debug flag never relaxes a production audience");
}

#[test]
fn trusting_a_proxy_needs_a_production_audience_and_a_loopback_listener() {
    let audience = "wss://relay.pda.test:443/v2/ws|pda-relay.cbor.v2";
    for ok in ["127.0.0.1:8080", "[::1]:8080"] {
        let config = V2Config::parse(audience, false, listen(ok)).unwrap().with_trust_proxy(true, listen(ok)).unwrap();
        assert!(config.trust_proxy, "{ok}");
    }
    let public = listen("0.0.0.0:8080");
    assert!(V2Config::parse(audience, false, public).unwrap().with_trust_proxy(true, public).is_err(),
            "a public listener could receive forged X-Forwarded-For directly");
    let debug = listen("127.0.0.1:47821");
    let config = V2Config::parse("ws://127.0.0.1:47821/v2/ws|pda-relay.cbor.v2", true, debug).unwrap();
    assert!(config.with_trust_proxy(true, debug).is_err(), "debug loopback never trusts a proxy");
    let untouched = V2Config::parse(audience, false, public).unwrap().with_trust_proxy(false, public).unwrap();
    assert!(!untouched.trust_proxy);
}

