//! Cross-language signed vectors (`protocol/test-vectors/network-v2-signed-vectors.txt`, verify-only, made by
//! OpenSSL with throwaway keys): the v2 structure codec parses the activation and packet envelopes, and the
//! existing p256 dev-dependency verifies every signature over the ORIGINAL domain||canonical transcript
//! (one SHA-256). Both s and n-s verify; forged, pre-hashed, wrong-key and tampered rows reject. This is
//! evidence for the future package-2 verifier; it does not replace the reviewed production dependency gate.

use std::collections::BTreeMap;

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use pda_relay_protocol::v2::{decode_activation, decode_envelope, Direction, FrameV2, PacketKind};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../test-vectors/network-v2-signed-vectors.txt");

fn fixture() -> BTreeMap<&'static str, Vec<u8>> {
    let mut values = BTreeMap::new();
    for line in VECTORS.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=').expect("fixture line");
        let bytes = (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("lowercase hex"))
            .collect();
        assert!(values.insert(name, bytes).is_none(), "duplicate {name}");
    }
    values
}

fn key(spki: &[u8]) -> VerifyingKey {
    assert_eq!(spki.len(), 91);
    assert_eq!(spki[..27], hex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")[..]);
    VerifyingKey::from_sec1_bytes(&spki[26..]).expect("valid P-256 point")
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn verifies(spki: &[u8], message: &[u8], der: &[u8]) -> bool {
    match Signature::from_der(der) {
        Ok(signature) => key(spki).verify(message, &signature).is_ok(),
        Err(_) => false,
    }
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

/// Shortest-form CBOR head, independent of the crate's writer.
fn head(major: u8, value: u64) -> Vec<u8> {
    let m = major << 5;
    match value {
        0..=23 => vec![m | value as u8],
        24..=0xff => vec![m | 24, value as u8],
        0x100..=0xffff => [vec![m | 25], (value as u16).to_be_bytes().to_vec()].concat(),
        _ => [vec![m | 26], (value as u32).to_be_bytes().to_vec()].concat(),
    }
}

fn bstr(value: &[u8]) -> Vec<u8> {
    [head(2, value.len() as u64), value.to_vec()].concat()
}

#[test]
fn activation_envelope_parses_and_its_root_signature_verifies() {
    let v = fixture();
    let activation = decode_activation(&v["ACTIVATION_ENVELOPE"]).expect("strict activation");
    assert_eq!(activation.tbs, &v["ACTIVATION_TBS"][..]);
    assert_eq!(activation.root_id[..], v["ROOT_ID"][..]);
    assert_eq!(activation.epoch[..], v["EPOCH"][..]);
    assert_eq!(activation.signing_spki, &v["DEVICE_SPKI"][..]);
    assert_eq!(activation.hpke_key_id, 1);
    assert_eq!(sha256(&[b"PDA-NETWORK/ROOT-ID/V1\0", &v["ROOT_SPKI"]]), v["ROOT_ID"]);
    assert_eq!(sha256(&[b"PDA-NETWORK/ACTIVATION-ID/V2\0", activation.tbs]), v["ACTIVATION_DIGEST"]);
    let input = [b"PDA-NETWORK/ACTIVATION/V2\0".as_slice(), activation.tbs].concat();
    assert!(verifies(&v["ROOT_SPKI"], &input, activation.signature_der));

    let wrong = decode_activation(&v["REJECT_ACTIVATION_WRONG_ROOT"]).expect("structurally valid");
    assert!(!verifies(&v["ROOT_SPKI"], &input, wrong.signature_der));
}

#[test]
fn possession_transcript_is_rebuilt_byte_for_byte_and_only_genuine_proofs_verify() {
    let v = fixture();
    let transcript = [
        b"PDA-NETWORK/RELAY-POSSESSION/V2\0".to_vec(),
        head(4, 8),
        head(0, 2),
        bstr(&v["AUDIENCE_UTF8"]),
        bstr(&v["CONNECTION_ID"]),
        bstr(&v["SERVER_NONCE"]),
        bstr(&v["CLIENT_NONCE"]),
        bstr(&v["ROOT_ID"]),
        bstr(&v["EPOCH"]),
        bstr(&v["ACTIVATION_DIGEST"]),
    ]
    .concat();
    assert_eq!(transcript, v["POSSESSION_SIGNING_INPUT"]);
    let device = &v["DEVICE_SPKI"];
    assert!(verifies(device, &transcript, &v["POSSESSION_PROOF_DER"]));
    assert!(verifies(device, &transcript, &v["POSSESSION_PROOF_HIGH_S_DER"]));
    for name in [
        "REJECT_POSSESSION_OTHER_AUDIENCE_DER",
        "REJECT_POSSESSION_PREHASHED_DER",
        "REJECT_POSSESSION_ROOT_KEY_DER",
    ] {
        assert!(!verifies(device, &transcript, &v[name]), "{name}");
    }
    // The proof travels as a strict v2 PROOF frame.
    let frame = [head(4, 3), head(0, 1), head(0, 1), bstr(&v["POSSESSION_PROOF_DER"])].concat();
    let parsed = pda_relay_protocol::v2::decode_frame(Direction::ClientToServer, &frame).expect("PROOF frame");
    assert_eq!(parsed, FrameV2::ClientProof { signature_der: &v["POSSESSION_PROOF_DER"] });
}

#[test]
fn packet_envelope_parses_and_its_device_signature_and_identity_match() {
    let v = fixture();
    let envelope = decode_envelope(&v["PACKET_ENVELOPE"]).expect("strict envelope");
    assert_eq!(envelope.header_bytes, &v["PACKET_HEADER"][..]);
    assert_eq!(envelope.ciphertext, &v["PACKET_CIPHERTEXT"][..]);
    assert_eq!(envelope.header.kind, PacketKind::Chat);
    assert_eq!(envelope.header.sender_root[..], v["ROOT_ID"][..]);
    assert_eq!(envelope.header.recipient_root[..], v["RECIPIENT_ROOT"][..]);
    let signed_content = [head(4, 2), bstr(envelope.header_bytes), bstr(envelope.ciphertext)].concat();
    let input = [b"PDA-NETWORK/PACKET/V2\0".as_slice(), &signed_content].concat();
    assert_eq!(input, v["PACKET_SIGNING_INPUT"]);
    assert_eq!(sha256(&[b"PDA-NETWORK/PACKET-ID/V2\0", &signed_content]), v["PACKET_ENVELOPE_DIGEST"]);
    let device = &v["DEVICE_SPKI"];
    assert!(verifies(device, &input, envelope.signature_der));
    let high_s = decode_envelope(&v["PACKET_ENVELOPE_HIGH_S"]).expect("strict envelope");
    assert_eq!(high_s.header_bytes, envelope.header_bytes);
    assert!(verifies(device, &input, high_s.signature_der));

    let tampered = decode_envelope(&v["REJECT_PACKET_TAMPERED_CIPHERTEXT"]).expect("structurally valid");
    let tampered_input = [
        b"PDA-NETWORK/PACKET/V2\0".to_vec(),
        head(4, 2),
        bstr(tampered.header_bytes),
        bstr(tampered.ciphertext),
    ]
    .concat();
    assert!(!verifies(device, &tampered_input, tampered.signature_der));
    let root_signed = decode_envelope(&v["REJECT_PACKET_ROOT_SIGNED"]).expect("structurally valid");
    assert!(!verifies(device, &input, root_signed.signature_der));
}
