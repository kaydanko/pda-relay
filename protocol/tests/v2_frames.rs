//! Relay v2 codec against the shared cross-language artifacts:
//! `protocol/test-vectors/network-relay-v2-frames.txt` (also consumed by the Android
//! `NetworkRelayV2FrameArtifactTest`) and `network-hpke-low-order-v2.txt`.

use std::collections::BTreeMap;

use pda_relay_protocol::v2::{
    check_der, check_spki, decode_activation, decode_envelope, decode_frame, encode_frame,
    is_x25519_low_order, scan_hpke_public_keyset, Direction, ErrorCode, FrameV2, PacketKind,
    MAX_FRAME_BYTES, MAX_NONCE,
};

const FRAMES: &str = include_str!("../../test-vectors/network-relay-v2-frames.txt");
const LOW_ORDER: &str = include_str!("../../test-vectors/network-hpke-low-order-v2.txt");
const KEYSETS: &str = include_str!("../../test-vectors/network-hpke-public-keysets-v2.txt");
const BOTH: [Direction; 2] = [Direction::ClientToServer, Direction::ServerToClient];

fn fixture(input: &'static str) -> BTreeMap<&'static str, Vec<u8>> {
    let mut values = BTreeMap::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("invalid fixture line: {line}"));
        assert!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_')),
            "invalid fixture name: {name}"
        );
        assert!(!value.is_empty(), "fixture value must not be empty: {name}");
        assert!(
            values.insert(name, hex(value)).is_none(),
            "duplicate fixture field: {name}"
        );
    }
    values
}

fn hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex must contain whole bytes");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid lowercase hex digit"),
    }
}

fn directions(prefix: &str) -> Vec<Direction> {
    match prefix {
        "C2S" => vec![Direction::ClientToServer],
        "S2C" => vec![Direction::ServerToClient],
        "BOTH" => BOTH.to_vec(),
        other => panic!("unknown direction prefix {other}"),
    }
}

#[test]
fn every_valid_artifact_frame_parses_only_in_its_directions_and_reencodes_exactly() {
    let values = fixture(FRAMES);
    let mut count = 0;
    for (name, bytes) in &values {
        let prefix = name.split('_').next().unwrap();
        if !matches!(prefix, "C2S" | "S2C" | "BOTH") {
            continue;
        }
        count += 1;
        let allowed = directions(prefix);
        for direction in BOTH {
            if allowed.contains(&direction) {
                let frame = decode_frame(direction, bytes).unwrap_or_else(|_| panic!("{name} must parse"));
                assert!(frame.allowed(direction), "{name}");
                assert_eq!(encode_frame(direction, &frame).unwrap(), *bytes, "{name}");
            } else {
                assert!(decode_frame(direction, bytes).is_err(), "{name} must be rejected {direction:?}");
            }
        }
    }
    assert_eq!(count, 15);
}

#[test]
fn every_reject_artifact_frame_is_refused_in_its_stated_directions() {
    let values = fixture(FRAMES);
    let rejects: Vec<_> = values.iter().filter(|(name, _)| name.starts_with("REJECT_")).collect();
    assert_eq!(rejects.len(), 27);
    for (name, bytes) in rejects {
        let prefix = name.trim_start_matches("REJECT_").split('_').next().unwrap();
        for direction in directions(prefix) {
            assert!(decode_frame(direction, bytes).is_err(), "{name} must be rejected {direction:?}");
        }
    }
}

#[test]
fn nested_artifact_values_are_the_exact_bytes_carried_by_the_frames() {
    let values = fixture(FRAMES);
    let hello = decode_frame(Direction::ClientToServer, &values["C2S_HELLO"]).unwrap();
    let FrameV2::ClientHello { root_spki, authorization, client_nonce } = hello else {
        panic!("HELLO expected")
    };
    assert_eq!(root_spki, values["G_SPKI"].as_slice());
    assert_eq!(authorization.envelope, values["AUTHORIZATION_ENVELOPE"].as_slice());
    assert_eq!(authorization.root_id.as_slice(), values["ROOT_ID"].as_slice());
    assert_eq!(authorization.epoch, [7u8; 32]);
    assert_eq!(authorization.issued_at_millis, 123);
    assert_eq!(authorization.hpke_key_id, u32::MAX);
    assert_eq!(authorization.historical_v1_tbs_digest, None);
    assert_eq!(client_nonce, core::array::from_fn::<u8, 32, _>(|i| 0x40 + i as u8));

    let envelope = values["PACKET_ENVELOPE"].as_slice();
    for (name, direction) in [("C2S_FORWARD", Direction::ClientToServer), ("S2C_DELIVER", Direction::ServerToClient)] {
        let parsed = match decode_frame(direction, &values[name]).unwrap() {
            FrameV2::ClientForward { envelope } | FrameV2::ServerDeliver { envelope } => envelope,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(parsed.original, envelope);
        assert_eq!(parsed.header.kind, PacketKind::Chat);
        assert_eq!(parsed.header.packet_id, core::array::from_fn::<u8, 16, _>(|i| 0xc0 + i as u8));
        assert_eq!(parsed.ciphertext.len(), 300);
    }
    assert_eq!(decode_envelope(envelope).unwrap().original, envelope);
    // The relay treats every registered kind as opaque; kinds 3 (Community sync), 4 and 5 (candidates) are registered, 6 and 7 are contact packets, 8 is not.
    // The kind byte follows `85 02 58 E0 | 89 02`; the device signature is not checked by this codec.
    for (kind, expected) in [(3u8, Some(PacketKind::CommunitySync)), (4u8, Some(PacketKind::CommunityCandidate)),
        (5u8, Some(PacketKind::CommunityCandidateReceipt)), (6u8, Some(PacketKind::ContactRequest)), (7u8, Some(PacketKind::ContactRejection)), (8u8, None), (0u8, None)] {
        let mut changed = envelope.to_vec();
        assert_eq!(changed[6], 1);
        changed[6] = kind;
        assert_eq!(decode_envelope(&changed).ok().map(|e| e.header.kind), expected);
    }
    assert_eq!(
        decode_frame(Direction::ServerToClient, &values["BOTH_PING_MAX"]).unwrap(),
        FrameV2::Ping { nonce: MAX_NONCE }
    );
    assert_eq!(
        decode_frame(Direction::ServerToClient, &values["S2C_ERROR_MALFORMED"]).unwrap(),
        FrameV2::ServerError { code: ErrorCode::Malformed, related_packet_id: None }
    );
}

#[test]
fn encoder_refuses_wrong_direction_out_of_range_nonce_and_never_emits_unparseable_bytes() {
    assert!(encode_frame(Direction::ClientToServer, &FrameV2::ServerAccepted { packet_id: [1; 16] }).is_err());
    assert!(encode_frame(Direction::ServerToClient, &FrameV2::ClientProof { signature_der: &[0x30, 0x06, 2, 1, 1, 2, 1, 1] }).is_err());
    assert!(encode_frame(Direction::ClientToServer, &FrameV2::Ping { nonce: MAX_NONCE + 1 }).is_err());
    assert!(encode_frame(Direction::ClientToServer, &FrameV2::ClientProof { signature_der: &[0x30, 0x06, 2, 1, 0, 2, 1, 1] }).is_err());
    assert_eq!(
        encode_frame(Direction::ServerToClient, &FrameV2::ServerAccepted { packet_id: [0xc0; 16] }).unwrap()[..2],
        [0x83, 0x14]
    );
    assert!(decode_frame(Direction::ClientToServer, &[]).is_err());
    let oversized = vec![0u8; MAX_FRAME_BYTES + 1];
    assert!(decode_frame(Direction::ClientToServer, &oversized).is_err());
    for code in 1..=10 {
        let code = ErrorCode::from_code(code).unwrap();
        assert_eq!(code.is_per_packet(), matches!(code, ErrorCode::RecipientOffline | ErrorCode::Backpressure));
    }
    assert!(ErrorCode::from_code(0).is_none() && ErrorCode::from_code(11).is_none());
}

#[test]
fn canonical_der_and_spki_profiles_match_the_android_rules() {
    // r = s = 1 (minimal), high-bit integers need one leading zero, n-1 accepted, n rejected.
    assert!(check_der(&hex("3006020101020101")).is_ok());
    let n_minus_1 = "00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550";
    let n = "00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    assert!(check_der(&hex(&format!("3026022100{}020101", &n_minus_1[2..]))).is_ok());
    assert!(check_der(&hex(&format!("3026022100{}020101", &n[2..]))).is_err());
    for bad in [
        "3006020100020101",       // r = 0
        "300702020001020101",     // redundant leading zero
        "3006020181020101",       // negative
        "3106020101020101",       // not a SEQUENCE
        "3007020101020101",       // wrong sequence length
        "300602010102010100",     // trailing byte
        "30060201010201",         // truncated
        "3081060201010201",       // long-form length
    ] {
        assert!(check_der(&hex(bad)).is_err(), "{bad}");
    }
    let values = fixture(FRAMES);
    let g = values["G_SPKI"].clone();
    assert!(check_spki(&g).is_ok());
    let mut wrong_prefix = g.clone();
    wrong_prefix[26] = 0x02; // compressed marker
    assert!(check_spki(&wrong_prefix).is_err());
    let mut x_is_p = g.clone();
    x_is_p[27..59].copy_from_slice(&hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"));
    assert!(check_spki(&x_is_p).is_err());
    assert!(check_spki(&g[..90]).is_err());
    assert!(decode_activation(&values["AUTHORIZATION_ENVELOPE"]).is_ok());
}

#[test]
fn hpke_scanner_matches_the_low_order_artifact_and_the_generated_keysets() {
    let low = fixture(LOW_ORDER);
    let keysets = fixture(KEYSETS);
    for (name, keyset) in &keysets {
        let id: u64 = name.trim_start_matches("PUBLIC_KEYSET_").parse().unwrap();
        let (key_id, point) = scan_hpke_public_keyset(keyset).unwrap_or_else(|_| panic!("{name}"));
        assert_eq!(u64::from(key_id), id);
        assert_eq!(point.as_slice(), low[format!("GENERATED_POINT_{id}").as_str()].as_slice());
    }
    for n in 1..=7 {
        for prefix in ["LOW_ORDER_", "HIGH_BIT_ALIAS_"] {
            let raw: [u8; 32] = low[format!("{prefix}{n}").as_str()].clone().try_into().unwrap();
            assert!(is_x25519_low_order(&raw), "{prefix}{n}");
            assert!(scan_hpke_public_keyset(&low[format!("SCHEMA_{prefix}{n}").as_str()]).is_err(), "SCHEMA_{prefix}{n}");
        }
        let near: [u8; 32] = low[format!("NEAR_MISS_{n}").as_str()].clone().try_into().unwrap();
        assert!(!is_x25519_low_order(&near));
        assert_eq!(scan_hpke_public_keyset(&low[format!("SCHEMA_NEAR_MISS_{n}").as_str()]).unwrap().1, near);
    }
    let base = &low["SCHEMA_BASE"];
    assert_eq!(scan_hpke_public_keyset(base).unwrap().0, 1);
    let mut trailing = base.clone();
    trailing.push(0);
    assert!(scan_hpke_public_keyset(&trailing).is_err());
    let mut zero_id = base.clone();
    zero_id[1] = 0;
    assert!(scan_hpke_public_keyset(&zero_id).is_err());
}
