use std::collections::BTreeMap;

use minicbor::{Decoder, Encoder};
use p256_v013::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    pkcs8::{DecodePublicKey, EncodePublicKey},
    PublicKey,
};
use sha2_v010::{Digest, Sha256};

const ROOT_ID_DOMAIN: &[u8] = b"PDA-NETWORK/ROOT-ID/V1\0";
const CREDENTIAL_DOMAIN: &[u8] = b"PDA-NETWORK/DEVICE-CREDENTIAL/V1\0";
const CANONICAL_SPKI_HEADER_HEX: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004";

fn fixture(input: &'static str) -> BTreeMap<&'static str, &'static str> {
    let mut values = BTreeMap::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (name, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("invalid fixture line: {line}"));
        assert!(!name.is_empty(), "fixture name must not be empty");
        assert!(
            name.bytes()
                .all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_')),
            "invalid fixture name: {name}"
        );
        assert!(!value.is_empty(), "fixture value must not be empty: {name}");
        assert!(
            values.insert(name, value).is_none(),
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

fn take<'a>(values: &mut BTreeMap<&'a str, &'a str>, name: &str) -> &'a str {
    values
        .remove(name)
        .unwrap_or_else(|| panic!("missing fixture field: {name}"))
}

fn take_hex<'a>(values: &mut BTreeMap<&'a str, &'a str>, name: &str) -> Vec<u8> {
    hex(take(values, name))
}

fn assert_all_consumed(values: &BTreeMap<&str, &str>) {
    assert!(
        values.is_empty(),
        "unverified fixture fields: {:?}",
        values.keys().collect::<Vec<_>>()
    );
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

fn canonicalize_spki(input: &[u8]) -> Result<Vec<u8>, String> {
    let key = PublicKey::from_public_key_der(input).map_err(|error| error.to_string())?;
    let encoded = key.to_public_key_der().map_err(|error| error.to_string())?;
    Ok(encoded.as_bytes().to_vec())
}

fn require_canonical_spki(input: &[u8]) -> Result<PublicKey, String> {
    let key = PublicKey::from_public_key_der(input).map_err(|error| error.to_string())?;
    let reconstructed = key.to_public_key_der().map_err(|error| error.to_string())?;
    let header = hex(CANONICAL_SPKI_HEADER_HEX);

    if input.len() != 91
        || !input.starts_with(&header)
        || input.get(26) != Some(&0x04)
        || reconstructed.as_bytes() != input
    {
        return Err("non-canonical P-256 SPKI".to_owned());
    }

    Ok(key)
}

fn public_spki(signing_key: &SigningKey) -> Vec<u8> {
    let verifying_key = VerifyingKey::from(signing_key);
    let point = verifying_key.to_encoded_point(false);
    let public_key = PublicKey::from_sec1_bytes(point.as_bytes()).expect("valid P-256 point");
    public_key
        .to_public_key_der()
        .expect("P-256 SPKI encoding")
        .as_bytes()
        .to_vec()
}

fn format_fingerprint(pda_id: &[u8]) -> String {
    pda_id
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_display_id(pda_id: &[u8]) -> String {
    format!(
        "PDA-{:02X}{:02X}-{:02X}{:02X}",
        pda_id[0], pda_id[1], pda_id[2], pda_id[3]
    )
}

#[test]
fn public_identity_vector_enforces_canonical_spki() {
    let mut values = fixture(include_str!(
        "../../test-vectors/identity-v1.txt"
    ));
    let root_spki = take_hex(&mut values, "ROOT_PUBLIC_SPKI_DER");
    let root_spki_sha256 = take_hex(&mut values, "ROOT_PUBLIC_SPKI_SHA256");
    let expected_pda_id = take_hex(&mut values, "PDA_ID");
    let expected_fingerprint = take(&mut values, "FULL_FINGERPRINT");
    let expected_display_id = take(&mut values, "DISPLAY_ID");
    let compressed = take_hex(&mut values, "ALT_COMPRESSED_ROOT_PUBLIC_SPKI_DER");
    let compressed_canonical = take_hex(&mut values, "ALT_COMPRESSED_CANONICAL_SPKI_DER");
    let compressed_policy = take(&mut values, "ALT_COMPRESSED_POLICY");
    let trailing = take_hex(&mut values, "MALFORMED_TRAILING_ROOT_PUBLIC_SPKI_DER");
    assert_all_consumed(&values);

    require_canonical_spki(&root_spki).expect("canonical fixture SPKI");

    assert_eq!(sha256(&[&root_spki]), root_spki_sha256);
    let pda_id = sha256(&[ROOT_ID_DOMAIN, &root_spki]);
    assert_eq!(pda_id, expected_pda_id);
    assert_eq!(format_fingerprint(&pda_id), expected_fingerprint);
    assert_eq!(format_display_id(&pda_id), expected_display_id);

    let normalized = canonicalize_spki(&compressed).expect("compressed point is valid P-256");
    assert_eq!(normalized, compressed_canonical);
    assert_eq!(compressed_policy, "REJECT_NON_CANONICAL");
    assert!(require_canonical_spki(&compressed).is_err());

    assert!(canonicalize_spki(&trailing).is_err());
    assert!(require_canonical_spki(&trailing).is_err());
}

#[test]
fn credential_vector_generates_canonical_bytes_and_verifies_signatures() {
    let mut values = fixture(include_str!(
        "../../test-vectors/identity-credential-v1.txt"
    ));
    let algorithm = take(&mut values, "ALGORITHM");
    let root_scalar = take_hex(&mut values, "ROOT_PRIVATE_SCALAR32");
    let expected_root_spki = take_hex(&mut values, "ROOT_PUBLIC_SPKI_DER");
    let expected_root_pda_id = take_hex(&mut values, "ROOT_PDA_ID");
    let device_scalar = take_hex(&mut values, "DEVICE_PRIVATE_SCALAR32");
    let expected_device_spki = take_hex(&mut values, "DEVICE_PUBLIC_SPKI_DER");
    let generation = take(&mut values, "CREDENTIAL_GENERATION")
        .parse::<u64>()
        .expect("fixture generation");
    let serial = take_hex(&mut values, "CREDENTIAL_SERIAL16");
    let issued_at = take(&mut values, "ISSUED_AT_EPOCH_MILLIS")
        .parse::<u64>()
        .expect("fixture issued-at");
    let expected_tbs = take_hex(&mut values, "CANONICAL_TBS_CBOR");
    let expected_tbs_sha256 = take_hex(&mut values, "CREDENTIAL_TBS_SHA256");
    let expected_signing_input_sha256 = take_hex(&mut values, "SIGNING_INPUT_SHA256");
    let golden_der = take_hex(&mut values, "ECDSA_DER_SIGNATURE");
    let expected_envelope = take_hex(&mut values, "CREDENTIAL_ENVELOPE_CBOR");
    let malformed_der = take_hex(&mut values, "MALFORMED_TRAILING_SIGNATURE_DER");
    assert_all_consumed(&values);

    assert_eq!(algorithm, "P256_SHA256_DER");

    let root_signing = SigningKey::from_slice(&root_scalar).expect("valid test root scalar");
    let root_verifying = VerifyingKey::from(&root_signing);
    let root_spki = public_spki(&root_signing);
    assert_eq!(root_spki, expected_root_spki);
    require_canonical_spki(&root_spki).expect("canonical root fixture SPKI");

    let root_pda_id = sha256(&[ROOT_ID_DOMAIN, &root_spki]);
    assert_eq!(root_pda_id, expected_root_pda_id);

    let device_signing = SigningKey::from_slice(&device_scalar).expect("valid test device scalar");
    let device_spki = public_spki(&device_signing);
    assert_eq!(device_spki, expected_device_spki);
    require_canonical_spki(&device_spki).expect("canonical device fixture SPKI");

    let mut tbs = Vec::new();
    let mut encoder = Encoder::new(&mut tbs);
    encoder.array(6).expect("array");
    encoder.u8(1).expect("format version");
    encoder.bytes(&root_pda_id).expect("root PDA ID");
    encoder.u64(generation).expect("generation");
    encoder.bytes(&serial).expect("serial");
    encoder.u64(issued_at).expect("issued-at");
    encoder.array(1).expect("key list");
    encoder.array(3).expect("key descriptor");
    encoder.u8(1).expect("SIGNING purpose");
    encoder.u8(1).expect("P256_SHA256_DER algorithm");
    encoder.bytes(&device_spki).expect("device SPKI");

    assert_eq!(tbs, expected_tbs);
    assert_eq!(sha256(&[&tbs]), expected_tbs_sha256);

    let mut decoder = Decoder::new(&tbs);
    assert_eq!(decoder.array().expect("TBS array"), Some(6));
    assert_eq!(decoder.u8().expect("format version"), 1);
    assert_eq!(decoder.bytes().expect("root PDA ID"), root_pda_id);
    assert_eq!(decoder.u64().expect("generation"), generation);
    assert_eq!(decoder.bytes().expect("serial"), serial);
    assert_eq!(decoder.u64().expect("issued-at"), issued_at);
    assert_eq!(decoder.array().expect("key list"), Some(1));
    assert_eq!(decoder.array().expect("key descriptor"), Some(3));
    assert_eq!(decoder.u8().expect("purpose"), 1);
    assert_eq!(decoder.u8().expect("algorithm"), 1);
    assert_eq!(decoder.bytes().expect("device SPKI"), device_spki);
    assert_eq!(
        decoder.position(),
        tbs.len(),
        "TBS must have no trailing bytes"
    );

    let signing_input = [CREDENTIAL_DOMAIN, tbs.as_slice()].concat();
    assert_eq!(sha256(&[&signing_input]), expected_signing_input_sha256);

    let golden_signature = Signature::from_der(&golden_der).expect("strict DER signature");
    root_verifying
        .verify(&signing_input, &golden_signature)
        .expect("golden signature verifies");

    let generated_signature: Signature = root_signing.sign(&signing_input);
    let generated_der = generated_signature.to_der();
    let parsed_generated =
        Signature::from_der(generated_der.as_bytes()).expect("fresh signature is strict DER");
    root_verifying
        .verify(&signing_input, &parsed_generated)
        .expect("fresh DER round-tripped ECDSA signature verifies");

    let mut envelope = Vec::new();
    let mut encoder = Encoder::new(&mut envelope);
    encoder.array(4).expect("credential envelope");
    encoder.u8(1).expect("envelope version");
    encoder.bytes(&tbs).expect("canonical TBS bytes");
    encoder.u8(1).expect("P256_SHA256_DER algorithm");
    encoder.bytes(&golden_der).expect("DER signature");
    assert_eq!(envelope, expected_envelope);

    let mut decoder = Decoder::new(&envelope);
    assert_eq!(decoder.array().expect("envelope array"), Some(4));
    assert_eq!(decoder.u8().expect("envelope version"), 1);
    assert_eq!(decoder.bytes().expect("embedded TBS"), tbs);
    assert_eq!(decoder.u8().expect("signature algorithm"), 1);
    assert_eq!(decoder.bytes().expect("signature"), golden_der);
    assert_eq!(
        decoder.position(),
        envelope.len(),
        "credential envelope must have no trailing bytes"
    );

    assert!(Signature::from_der(&malformed_der).is_err());
}

#[test]
fn fixture_parser_rejects_duplicates_invalid_names_and_uppercase_hex() {
    assert!(std::panic::catch_unwind(|| fixture("FIELD=aa\nFIELD=bb\n")).is_err());
    assert!(std::panic::catch_unwind(|| fixture("bad_name=aa\n")).is_err());
    assert!(std::panic::catch_unwind(|| hex("AA")).is_err());
}
