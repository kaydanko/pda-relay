//! Package 2: the production [P256Authenticator] against the cross-language signed vectors
//! (`protocol/test-vectors/network-v2-signed-vectors.txt`, made by OpenSSL with throwaway keys) and against
//! activations re-signed here by a deterministic TEST root key (fixed scalar, never a real identity) for the
//! negatives the vector file cannot carry: an off-curve device key and a mismatched root ID under a valid
//! root signature. Ends with the full HELLO -> CHALLENGE -> PROOF -> REGISTERED exchange through
//! [RelayCore] with the exact vector connection ID, server nonce and audience.

use std::collections::BTreeMap;

use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use pda_relay_protocol::{
    v2::{check_spki, decode_activation, decode_frame, encode_frame, Direction, ErrorCode, FrameV2},
    v2_auth::{possession_signing_input, P256Authenticator, MAX_AUDIENCE_BYTES},
    v2_relay::{Action, Authenticator, Authority, Entropy, Limits, RelayCore},
};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../test-vectors/network-v2-signed-vectors.txt");
const SPKI_PREFIX: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

fn fixture() -> BTreeMap<&'static str, Vec<u8>> {
    let mut values = BTreeMap::new();
    for line in VECTORS.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=').expect("fixture line");
        assert!(values.insert(name, hex(value)).is_none(), "duplicate {name}");
    }
    values
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("lowercase hex")).collect()
}

fn b32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().unwrap()
}

fn b16(bytes: &[u8]) -> [u8; 16] {
    bytes.try_into().unwrap()
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn authority(v: &BTreeMap<&str, Vec<u8>>) -> Authority {
    Authority { root: b32(&v["ROOT_ID"]), epoch: b32(&v["EPOCH"]), activation_digest: b32(&v["ACTIVATION_DIGEST"]) }
}

fn grant(v: &BTreeMap<&str, Vec<u8>>) -> <P256Authenticator as Authenticator>::Grant {
    let activation = decode_activation(&v["ACTIVATION_ENVELOPE"]).unwrap();
    P256Authenticator.authorize(&v["ROOT_SPKI"], &activation).expect("genuine activation")
}

fn possession(v: &BTreeMap<&str, Vec<u8>>, audience: &[u8], cid: &[u8], sn: &[u8], cn: &[u8], proof: &[u8]) -> bool {
    P256Authenticator.possession(&grant(v), audience, &b16(cid), &b32(sn), &b32(cn), proof)
}

fn bstr(value: &[u8]) -> Vec<u8> {
    let mut out = match value.len() {
        0..=23 => vec![0x40 | value.len() as u8],
        24..=0xff => vec![0x58, value.len() as u8],
        _ => [vec![0x59], (value.len() as u16).to_be_bytes().to_vec()].concat(),
    };
    out.extend_from_slice(value);
    out
}

fn spki(key: &VerifyingKey) -> Vec<u8> {
    [hex(SPKI_PREFIX), key.to_sec1_point(false).as_bytes().to_vec()].concat()
}

/// The vector activation TBS with its root ID and device SPKI replaced, signed by `root`.
fn resigned_activation(v: &BTreeMap<&str, Vec<u8>>, root: &SigningKey, root_id: &[u8; 32], device_spki: &[u8]) -> Vec<u8> {
    let replace = |bytes: &mut Vec<u8>, from: &[u8], to: &[u8]| {
        let at = bytes.windows(from.len()).position(|w| w == from).expect("field present");
        bytes[at..at + from.len()].copy_from_slice(to);
    };
    let mut tbs = v["ACTIVATION_TBS"].clone();
    replace(&mut tbs, &v["ROOT_ID"], root_id);
    replace(&mut tbs, &v["DEVICE_SPKI"], device_spki);
    let signature: Signature = root.sign(&[b"PDA-NETWORK/ACTIVATION/V2\0".as_slice(), &tbs].concat());
    [vec![0x84, 0x02], bstr(&tbs), vec![0x01], bstr(signature.to_der().as_bytes())].concat()
}

fn test_root() -> (SigningKey, Vec<u8>, [u8; 32]) {
    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let spki = spki(key.verifying_key());
    let id = sha256(&[b"PDA-NETWORK/ROOT-ID/V1\0", &spki]);
    (key, spki, id)
}

#[test]
fn the_genuine_activation_yields_exactly_the_vector_authority() {
    let v = fixture();
    let activation = decode_activation(&v["ACTIVATION_ENVELOPE"]).unwrap();
    let grant = P256Authenticator.authorize(&v["ROOT_SPKI"], &activation).expect("root-signed activation");
    assert_eq!(P256Authenticator.authority(&grant), authority(&v));
}

#[test]
fn root_authorization_rejects_every_forgery() {
    let v = fixture();
    let genuine = decode_activation(&v["ACTIVATION_ENVELOPE"]).unwrap();

    // Signed by another key.
    let wrong_root = decode_activation(&v["REJECT_ACTIVATION_WRONG_ROOT"]).unwrap();
    assert!(P256Authenticator.authorize(&v["ROOT_SPKI"], &wrong_root).is_none());

    // Presented under a root SPKI whose ROOT-ID is not the activation's root ID.
    assert!(P256Authenticator.authorize(&v["DEVICE_SPKI"], &genuine).is_none());

    // Root SPKI with a coordinate in range but the point off the curve.
    let mut off_curve = v["ROOT_SPKI"].clone();
    off_curve[90] ^= 1;
    assert!(check_spki(&off_curve).is_ok(), "precondition: structurally canonical");
    assert!(P256Authenticator.authorize(&off_curve, &genuine).is_none());

    // A TBS byte changed after signing (the epoch), still structurally valid.
    let mut tampered = v["ACTIVATION_ENVELOPE"].clone();
    let at = tampered.windows(32).position(|w| w == &v["EPOCH"][..]).unwrap();
    tampered[at] ^= 0x01;
    let tampered = decode_activation(&tampered).expect("structurally valid");
    assert!(P256Authenticator.authorize(&v["ROOT_SPKI"], &tampered).is_none());
}

#[test]
fn a_validly_root_signed_activation_still_needs_the_matching_root_id_and_an_on_curve_device_key() {
    let v = fixture();
    let (root, root_spki, root_id) = test_root();
    let device = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let device_spki = spki(device.verifying_key());

    let good = resigned_activation(&v, &root, &root_id, &device_spki);
    let parsed = decode_activation(&good).unwrap();
    assert!(P256Authenticator.authorize(&root_spki, &parsed).is_some(), "control: re-signed activation verifies");

    let mut device_off_curve = device_spki.clone();
    device_off_curve[90] ^= 1;
    assert!(check_spki(&device_off_curve).is_ok() && VerifyingKey::from_sec1_bytes(&device_off_curve[26..]).is_err());
    let bad_device = resigned_activation(&v, &root, &root_id, &device_off_curve);
    let parsed = decode_activation(&bad_device).expect("the structural codec does not check the curve");
    assert!(P256Authenticator.authorize(&root_spki, &parsed).is_none());

    let other_id = sha256(&[b"PDA-NETWORK/ROOT-ID/V1\0", &v["ROOT_SPKI"]]);
    let wrong_id = resigned_activation(&v, &root, &other_id, &device_spki);
    assert!(P256Authenticator.authorize(&root_spki, &decode_activation(&wrong_id).unwrap()).is_none());
}

#[test]
fn a_self_consistent_identity_with_a_non_canonical_root_spki_is_refused() {
    // Same 91-byte length and the same valid point, but another algorithm-identifier byte. Its ROOT-ID is
    // computed over these exact bytes and the activation is validly signed by that key, so only the
    // canonical-SPKI rule can refuse it when `authorize` is called directly (not only via a HELLO frame).
    let v = fixture();
    let (root, mut odd_spki, _) = test_root();
    odd_spki[12] ^= 0x01;
    assert!(check_spki(&odd_spki).is_err() && VerifyingKey::from_sec1_bytes(&odd_spki[26..]).is_ok());
    let odd_id = sha256(&[b"PDA-NETWORK/ROOT-ID/V1\0", &odd_spki]);
    let device_spki = spki(SigningKey::from_slice(&[9u8; 32]).unwrap().verifying_key());
    let activation = resigned_activation(&v, &root, &odd_id, &device_spki);
    assert!(P256Authenticator.authorize(&odd_spki, &decode_activation(&activation).unwrap()).is_none());
}

#[test]
fn the_possession_input_is_the_vector_transcript_byte_for_byte() {
    let v = fixture();
    let input = possession_signing_input(&v["AUDIENCE_UTF8"], &b16(&v["CONNECTION_ID"]), &b32(&v["SERVER_NONCE"]),
                                         &b32(&v["CLIENT_NONCE"]), &authority(&v)).unwrap();
    assert_eq!(input, v["POSSESSION_SIGNING_INPUT"]);
    let a = authority(&v);
    let (cid, sn, cn) = ([1u8; 16], [2u8; 32], [3u8; 32]);
    assert!(possession_signing_input(b"", &cid, &sn, &cn, &a).is_none());
    assert!(possession_signing_input(&[0xff], &cid, &sn, &cn, &a).is_none());
    assert!(possession_signing_input(&[b'a'; MAX_AUDIENCE_BYTES + 1], &cid, &sn, &cn, &a).is_none());
    let longest = possession_signing_input(&[b'a'; MAX_AUDIENCE_BYTES], &cid, &sn, &cn, &a).unwrap();
    assert_eq!(&longest[32..36], &[0x88, 0x02, 0x59, 0x02], "two-byte bstr head for a 512-byte audience");
}

#[test]
fn only_the_genuine_device_proof_for_these_exact_values_verifies() {
    let v = fixture();
    let (aud, cid, sn, cn) = (&v["AUDIENCE_UTF8"], &v["CONNECTION_ID"], &v["SERVER_NONCE"], &v["CLIENT_NONCE"]);
    assert!(possession(&v, aud, cid, sn, cn, &v["POSSESSION_PROOF_DER"]));
    assert!(possession(&v, aud, cid, sn, cn, &v["POSSESSION_PROOF_HIGH_S_DER"]), "n-s is accepted, as on Android");
    for name in ["REJECT_POSSESSION_OTHER_AUDIENCE_DER", "REJECT_POSSESSION_PREHASHED_DER", "REJECT_POSSESSION_ROOT_KEY_DER"] {
        assert!(!possession(&v, aud, cid, sn, cn, &v[name]), "{name}");
    }
    let proof = &v["POSSESSION_PROOF_DER"];
    let flip = |bytes: &[u8]| { let mut out = bytes.to_vec(); out[0] ^= 1; out };
    assert!(!possession(&v, b"wss://other.example:443/v2/ws|pda-relay.cbor.v2", cid, sn, cn, proof));
    assert!(!possession(&v, aud, &flip(cid), sn, cn, proof));
    assert!(!possession(&v, aud, cid, &flip(sn), cn, proof));
    assert!(!possession(&v, aud, cid, sn, &flip(cn), proof));

    // Non-canonical DER of the same (r, s): an extra leading zero on r.
    let (r_len, r) = (proof[3] as usize, &proof[4..4 + proof[3] as usize]);
    let rest = &proof[4 + r_len..];
    let padded = [vec![0x30, proof[1] + 1, 0x02, r_len as u8 + 1, 0x00], r.to_vec(), rest.to_vec()].concat();
    assert!(!possession(&v, aud, cid, sn, cn, &padded));
}

/// Hands out the vector connection ID, then the vector server nonce, then zeros.
struct Scripted(Vec<u8>);

impl Entropy for Scripted {
    fn fill(&mut self, out: &mut [u8]) {
        for byte in out {
            *byte = if self.0.is_empty() { 0 } else { self.0.remove(0) };
        }
    }
}

fn shown(actions: &[Action]) -> Vec<String> {
    actions
        .iter()
        .map(|action| match action {
            Action::Close { conn } => format!("{conn}:CLOSE"),
            Action::Send { conn, frame } | Action::Deliver { conn, frame } => {
                let name = match decode_frame(Direction::ServerToClient, frame).unwrap() {
                    FrameV2::ServerChallenge { .. } => "CHALLENGE".to_string(),
                    FrameV2::ServerRegistered { .. } => "REGISTERED".to_string(),
                    FrameV2::ServerError { code, .. } => format!("ERROR{}", code.code()),
                    other => format!("{other:?}"),
                };
                format!("{conn}:{name}")
            }
        })
        .collect()
}

#[test]
fn the_relay_core_registers_the_vector_identity_with_the_production_verifier() {
    let v = fixture();
    let core_for = |audience: &[u8]| {
        let script = [v["CONNECTION_ID"].clone(), v["SERVER_NONCE"].clone()].concat();
        RelayCore::new(P256Authenticator, Scripted(script), audience, Limits::default()).unwrap()
    };
    let hello = encode_frame(Direction::ClientToServer, &FrameV2::ClientHello {
        root_spki: &v["ROOT_SPKI"],
        authorization: decode_activation(&v["ACTIVATION_ENVELOPE"]).unwrap(),
        client_nonce: b32(&v["CLIENT_NONCE"]),
    }).unwrap();
    let proof = encode_frame(Direction::ClientToServer, &FrameV2::ClientProof { signature_der: &v["POSSESSION_PROOF_DER"] }).unwrap();

    let mut core = core_for(&v["AUDIENCE_UTF8"]);
    assert!(core.accept(1, 7, 0).is_empty());
    let challenged = core.on_frame(1, &hello, 1);
    assert_eq!(shown(&challenged), ["1:CHALLENGE"]);
    let Action::Send { frame, .. } = &challenged[0] else { unreachable!() };
    assert_eq!(decode_frame(Direction::ServerToClient, frame).unwrap(),
               FrameV2::ServerChallenge { connection_id: b16(&v["CONNECTION_ID"]), server_nonce: b32(&v["SERVER_NONCE"]) });
    assert_eq!(shown(&core.on_frame(1, &proof, 2)), ["1:REGISTERED"]);
    assert_eq!(core.route(&b32(&v["ROOT_ID"])), Some(1));

    // The same genuine proof is worthless to a relay configured with another audience.
    let mut other = core_for(b"wss://other.example:443/v2/ws|pda-relay.cbor.v2");
    other.accept(1, 7, 0);
    assert_eq!(shown(&other.on_frame(1, &hello, 1)), ["1:CHALLENGE"]);
    assert_eq!(shown(&other.on_frame(1, &proof, 2)), [format!("1:ERROR{}", ErrorCode::AuthFailed.code()), "1:CLOSE".into()]);
    assert_eq!(other.route(&b32(&v["ROOT_ID"])), None);

    // A forged activation never reaches a challenge.
    let forged = encode_frame(Direction::ClientToServer, &FrameV2::ClientHello {
        root_spki: &v["ROOT_SPKI"],
        authorization: decode_activation(&v["REJECT_ACTIVATION_WRONG_ROOT"]).unwrap(),
        client_nonce: b32(&v["CLIENT_NONCE"]),
    }).unwrap();
    let mut third = core_for(&v["AUDIENCE_UTF8"]);
    third.accept(1, 7, 0);
    assert_eq!(shown(&third.on_frame(1, &forged, 1)), [format!("1:ERROR{}", ErrorCode::AuthFailed.code()), "1:CLOSE".into()]);
}

#[test]
fn bootstrap_packet_binds_card_metadata_signature_and_session_authority() {
    use pda_relay_protocol::v2::decode_envelope;
    let v = fixture();
    let (root, root_spki, root_id) = test_root();
    let device = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let activation_bytes = resigned_activation(&v, &root, &root_id, &spki(device.verifying_key()));
    let activation = decode_activation(&activation_bytes).unwrap();
    let grant = P256Authenticator.authorize(&root_spki, &activation).unwrap();
    let authority = P256Authenticator.authority(&grant);
    let card = [vec![0x84, 2], bstr(&root_spki), bstr(&activation_bytes), bstr(b"SENDER")].concat();
    let wrapper = [vec![0x82], bstr(&card), bstr(&[1; 80])].concat();
    for kind in [6, 7] {
        let header = [vec![0x89, 2, kind], bstr(&authority.root), bstr(&[4;32]), bstr(&authority.epoch),
            bstr(&[5;32]), bstr(&authority.activation_digest), bstr(&[6;32]), bstr(&[7;16])].concat();
        let input = [b"PDA-NETWORK/PACKET/V2\0".as_slice(), &[0x82], &bstr(&header), &bstr(&wrapper)].concat();
        let signature: Signature = device.sign(&input);
        let envelope = [vec![0x85, 2], bstr(&header), bstr(&wrapper), vec![1], bstr(signature.to_der().as_bytes())].concat();
        let parsed = decode_envelope(&envelope).unwrap();
        assert!(P256Authenticator.bootstrap(&parsed, &authority));
        let mut other = authority; other.epoch[0] ^= 1;
        assert!(!P256Authenticator.bootstrap(&parsed, &other));
        let mut tampered = envelope.clone();
        let at = tampered.windows(6).position(|x| x == b"SENDER").unwrap();
        tampered[at] = b'F';
        assert!(!P256Authenticator.bootstrap(&decode_envelope(&tampered).unwrap(), &authority));
    }
}
