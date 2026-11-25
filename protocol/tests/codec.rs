use std::collections::BTreeMap;

use pda_relay_protocol::{
    decode_client_frame, decode_server_frame, encode_client_frame, encode_server_frame,
    ClientFrame, ErrorCode, Limits, ProtocolError, ServerFrame,
};

const VECTORS: &str = include_str!("../../test-vectors/v1.txt");
const PACKET_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const TO_PDA_ID: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];
const FROM_PDA_ID: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];

fn parse_vectors() -> BTreeMap<&'static str, Vec<u8>> {
    let mut vectors = BTreeMap::new();
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, hex) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("invalid vector line: {line}"));
        assert!(!name.is_empty(), "vector name must not be empty");
        assert!(hex.len() % 2 == 0, "odd hex length for {name}");
        let bytes = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect();
        assert!(
            vectors.insert(name, bytes).is_none(),
            "duplicate vector {name}"
        );
    }
    vectors
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid lowercase hex digit"),
    }
}

fn assert_client_vector(
    vectors: &mut BTreeMap<&str, Vec<u8>>,
    name: &str,
    expected: ClientFrame<'_>,
) {
    let golden = vectors
        .remove(name)
        .unwrap_or_else(|| panic!("missing vector {name}"));
    assert_eq!(
        encode_client_frame(&expected).unwrap(),
        golden,
        "encoding mismatch for {name}"
    );
    assert_eq!(
        decode_client_frame(&golden, Limits::default()).unwrap(),
        expected,
        "decoding mismatch for {name}"
    );
}

fn assert_server_vector(
    vectors: &mut BTreeMap<&str, Vec<u8>>,
    name: &str,
    expected: ServerFrame<'_>,
) {
    let golden = vectors
        .remove(name)
        .unwrap_or_else(|| panic!("missing vector {name}"));
    assert_eq!(
        encode_server_frame(&expected).unwrap(),
        golden,
        "encoding mismatch for {name}"
    );
    assert_eq!(
        decode_server_frame(&golden, Limits::default()).unwrap(),
        expected,
        "decoding mismatch for {name}"
    );
}

#[test]
fn shared_v1_vectors_cover_every_client_and_server_shape() {
    let mut vectors = parse_vectors();

    assert_client_vector(
        &mut vectors,
        "CLIENT_HELLO",
        ClientFrame::Hello {
            min_version: 1,
            max_version: 1,
            pda_id: [0; 32],
        },
    );
    assert_client_vector(&mut vectors, "CLIENT_PING", ClientFrame::Ping { nonce: 42 });
    assert_client_vector(
        &mut vectors,
        "CLIENT_PONG",
        ClientFrame::Pong { nonce: 500 },
    );
    assert_client_vector(
        &mut vectors,
        "CLIENT_FORWARD",
        ClientFrame::Forward {
            packet_id: PACKET_ID,
            to: TO_PDA_ID,
            opaque_payload: &[0xde, 0xad, 0xbe, 0xef],
        },
    );
    assert_client_vector(
        &mut vectors,
        "CLIENT_ACK",
        ClientFrame::Ack {
            acked_packet_id: PACKET_ID,
            to: TO_PDA_ID,
        },
    );

    assert_server_vector(
        &mut vectors,
        "SERVER_HELLO_OK",
        ServerFrame::HelloOk {
            selected_version: 1,
        },
    );
    assert_server_vector(&mut vectors, "SERVER_PING", ServerFrame::Ping { nonce: 42 });
    assert_server_vector(
        &mut vectors,
        "SERVER_PONG",
        ServerFrame::Pong { nonce: 500 },
    );
    assert_server_vector(
        &mut vectors,
        "SERVER_DELIVER",
        ServerFrame::Deliver {
            packet_id: PACKET_ID,
            from: FROM_PDA_ID,
            opaque_payload: &[0xde, 0xad, 0xbe, 0xef],
        },
    );
    assert_server_vector(
        &mut vectors,
        "SERVER_DELIVERY_ACK",
        ServerFrame::DeliveryAck {
            acked_packet_id: PACKET_ID,
            from: FROM_PDA_ID,
        },
    );
    assert_server_vector(
        &mut vectors,
        "SERVER_ERROR_NULL",
        ServerFrame::Error {
            code: ErrorCode::MalformedFrame,
            related_packet_id: None,
        },
    );
    assert_server_vector(
        &mut vectors,
        "SERVER_ERROR_RELATED_PACKET",
        ServerFrame::Error {
            code: ErrorCode::RecipientOffline,
            related_packet_id: Some(PACKET_ID),
        },
    );

    assert!(
        vectors.is_empty(),
        "unverified shared vectors: {:?}",
        vectors.keys().collect::<Vec<_>>()
    );
}

#[test]
fn rejects_indefinite_trailing_and_oversized_input() {
    assert_eq!(
        decode_client_frame(&[0x9f, 0x00, 0x01, 0x01, 0x40, 0xff], Limits::default()),
        Err(ProtocolError::Malformed(
            "indefinite arrays are not allowed"
        ))
    );

    let mut hello = encode_client_frame(&ClientFrame::Hello {
        min_version: 1,
        max_version: 1,
        pda_id: [0; 32],
    })
    .unwrap();
    hello.push(0);
    assert_eq!(
        decode_client_frame(&hello, Limits::default()),
        Err(ProtocolError::Malformed("trailing bytes"))
    );

    let limits = Limits {
        max_frame_bytes: 4,
        max_payload_bytes: 4,
    };
    assert_eq!(
        decode_client_frame(&hello, limits),
        Err(ProtocolError::FrameTooLarge)
    );
}

#[test]
fn rejects_invalid_id_length_and_oversized_payload() {
    let invalid = [0x84, 0x00, 0x01, 0x01, 0x41, 0x00];
    assert_eq!(
        decode_client_frame(&invalid, Limits::default()),
        Err(ProtocolError::Malformed("invalid PDA ID"))
    );

    let encoded = encode_client_frame(&ClientFrame::Forward {
        packet_id: [1; 16],
        to: [2; 32],
        opaque_payload: b"12345",
    })
    .unwrap();
    let limits = Limits {
        max_frame_bytes: 1024,
        max_payload_bytes: 4,
    };
    assert_eq!(
        decode_client_frame(&encoded, limits),
        Err(ProtocolError::PayloadTooLarge)
    );
}
