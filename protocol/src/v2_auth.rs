//! Relay v2 root authorization and device possession (R4 "Root-signed activation authorization",
//! "Authenticated relay v2 dialect", "Audience and public key acceptance"); package 2.
//!
//! Byte-for-byte the rules of the Android `SignedActivationV2Codec.verify` and
//! `NetworkRelayPossessionVerifier`:
//! - root SPKI: the exact 91-byte canonical uncompressed P-256 SPKI whose point is on the curve;
//! - `activation.root_id == SHA-256("PDA-NETWORK/ROOT-ID/V1\0" || rootSpki)`;
//! - root ECDSA-P256-SHA256 signature over `"PDA-NETWORK/ACTIVATION/V2\0" || tbs`, canonical DER;
//! - device signing SPKI canonical and on the curve;
//! - `activationDigest = SHA-256("PDA-NETWORK/ACTIVATION-ID/V2\0" || tbs)`;
//! - device signature over `"PDA-NETWORK/RELAY-POSSESSION/V2\0" || canonical([2, audience, connectionId,
//!   serverNonce, clientNonce, rootId, epoch, activationDigest])`, canonical DER.
//!
//! Every verification hashes the ORIGINAL domain||bytes exactly once (`Verifier::verify`); the prehash
//! path is never used. Both s and n-s verify (P-256 `NORMALIZE_S = false`, as on Android). Structure,
//! nonzero epoch and the strict HPKE keyset profile (including X25519 low-order rejection) are already
//! enforced by [crate::v2::decode_activation] before this verifier runs. Nothing here reveals why a check
//! failed: callers only see `None`/`false`.

use alloc::vec::Vec;

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::v2::{check_der, check_spki, ActivationV2, ROOT_SPKI_BYTES};
use crate::v2_relay::{Authenticator, Authority};

const ROOT_ID_DOMAIN: &[u8] = b"PDA-NETWORK/ROOT-ID/V1\0";
const ACTIVATION_DOMAIN: &[u8] = b"PDA-NETWORK/ACTIVATION/V2\0";
const ACTIVATION_ID_DOMAIN: &[u8] = b"PDA-NETWORK/ACTIVATION-ID/V2\0";
const POSSESSION_DOMAIN: &[u8] = b"PDA-NETWORK/RELAY-POSSESSION/V2\0";
/// R4 maximum relay audience length.
pub const MAX_AUDIENCE_BYTES: usize = 512;
/// Offset of the SEC1 `04 || x || y` point inside the canonical 91-byte SPKI.
const SPKI_POINT_OFFSET: usize = 26;

/// Root-verified authority of one HELLO plus its device verification key.
#[derive(Clone, Debug)]
pub struct VerifiedActivation {
    authority: Authority,
    device: VerifyingKey,
}

/// The production [Authenticator]: stateless, pure public-key verification.
#[derive(Clone, Copy, Debug, Default)]
pub struct P256Authenticator;

impl Authenticator for P256Authenticator {
    type Grant = VerifiedActivation;

    fn authorize(&self, root_spki: &[u8], activation: &ActivationV2<'_>) -> Option<VerifiedActivation> {
        let root = canonical_key(root_spki)?;
        if sha256(&[ROOT_ID_DOMAIN, root_spki]) != activation.root_id {
            return None;
        }
        if !verifies(&root, &[ACTIVATION_DOMAIN, activation.tbs], activation.signature_der) {
            return None;
        }
        let device = canonical_key(activation.signing_spki)?;
        let authority = Authority {
            root: activation.root_id,
            epoch: activation.epoch,
            activation_digest: sha256(&[ACTIVATION_ID_DOMAIN, activation.tbs]),
        };
        Some(VerifiedActivation { authority, device })
    }

    fn authority(&self, grant: &VerifiedActivation) -> Authority {
        grant.authority
    }

    fn bootstrap(&self, envelope: &crate::v2::PacketEnvelopeV2<'_>, authority: &Authority) -> bool {
        let Ok((root, activation)) = crate::v2::decode_bootstrap(envelope.ciphertext) else { return false };
        let Some(grant) = self.authorize(root, &activation) else { return false };
        if self.authority(&grant) != *authority { return false; }
        let mut input = Vec::new();
        input.extend_from_slice(b"PDA-NETWORK/PACKET/V2\0");
        head(&mut input, 4, 2);
        head(&mut input, 2, envelope.header_bytes.len() as u64);
        input.extend_from_slice(envelope.header_bytes);
        head(&mut input, 2, envelope.ciphertext.len() as u64);
        input.extend_from_slice(envelope.ciphertext);
        verifies(&grant.device, &[&input], envelope.signature_der)
    }

    fn possession(&self, grant: &VerifiedActivation, audience_utf8: &[u8], connection_id: &[u8; 16],
                  server_nonce: &[u8; 32], client_nonce: &[u8; 32], signature_der: &[u8]) -> bool {
        match possession_signing_input(audience_utf8, connection_id, server_nonce, client_nonce, &grant.authority) {
            Some(input) => verifies(&grant.device, &[&input], signature_der),
            None => false,
        }
    }
}

/// `"PDA-NETWORK/RELAY-POSSESSION/V2\0" || canonical([2, audience, cid, sn, cn, rootId, epoch, digest])`.
/// None for an empty, oversized or non-UTF-8 audience.
pub fn possession_signing_input(audience_utf8: &[u8], connection_id: &[u8; 16], server_nonce: &[u8; 32],
                                client_nonce: &[u8; 32], authority: &Authority) -> Option<Vec<u8>> {
    if audience_utf8.is_empty() || audience_utf8.len() > MAX_AUDIENCE_BYTES || core::str::from_utf8(audience_utf8).is_err() {
        return None;
    }
    let mut out = Vec::with_capacity(POSSESSION_DOMAIN.len() + 2 + 3 + audience_utf8.len() + 6 * 2 + 16 + 5 * 32);
    out.extend_from_slice(POSSESSION_DOMAIN);
    head(&mut out, 4, 8);
    head(&mut out, 0, 2);
    for field in [audience_utf8, connection_id, server_nonce, client_nonce, &authority.root, &authority.epoch,
                  &authority.activation_digest] {
        head(&mut out, 2, field.len() as u64);
        out.extend_from_slice(field);
    }
    Some(out)
}

/// Canonical 91-byte SPKI whose SEC1 point is a valid, non-identity P-256 point.
fn canonical_key(spki: &[u8]) -> Option<VerifyingKey> {
    if spki.len() != ROOT_SPKI_BYTES || check_spki(spki).is_err() {
        return None;
    }
    // `from_sec1_bytes` also accepts compressed points; the canonical prefix above already pinned `04`.
    VerifyingKey::from_sec1_bytes(&spki[SPKI_POINT_OFFSET..]).ok()
}

/// One SHA-256 over the concatenated original parts, then ECDSA; canonical DER only.
fn verifies(key: &VerifyingKey, parts: &[&[u8]], signature_der: &[u8]) -> bool {
    if check_der(signature_der).is_err() {
        return false;
    }
    let Ok(signature) = Signature::from_der(signature_der) else { return false };
    if signature.to_der().as_bytes() != signature_der {
        return false;
    }
    let message: Vec<u8> = parts.concat();
    key.verify(&message, &signature).is_ok()
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Shortest-form CBOR head (RFC 8949 core deterministic encoding).
fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let m = major << 5;
    match value {
        0..=23 => out.push(m | value as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, value as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        _ => {
            out.push(m | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
    }
}
