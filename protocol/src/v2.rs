//! Relay v2 dialect (`/v2/ws`, subprotocol `pda-relay.cbor.v2`): strict, bounded frame parsing and
//! canonical encoding for R4 "Authenticated relay v2 dialect". Decoding never allocates (borrowed
//! slices, in-place canonical comparison). Encoding validates every field allocation-free first and then
//! allocates exactly one buffer of the counted, bounded output length.
//!
//! Mirrors the reviewed Android codecs (`NetworkRelayFrameCodec`, `SignedActivationV2Codec`,
//! `NetworkPacketCodec`, `EcdsaDer`, `StrictHpkePublicProfile`) on original bytes:
//! deterministic shortest-form CBOR only, definite lengths, exact arity, exact consumption, no
//! trailing bytes, and the encoder output must equal the input. It is a STRUCTURE codec only:
//! - no root signature, device possession, audience or current-epoch verification;
//! - P-256 SPKIs are checked for the exact 91-byte canonical prefix and field range (x, y < p),
//!   but NOT for the curve equation; on-curve validation belongs to the authentication layer
//!   built on the reviewed p256 dependency (dependency gate `docs/RELAY_V2_RUST_DEPENDENCY_GATE.patch`);
//! - ACCEPTED is bounded queue admission only, never delivery.
//!
//! Every failure is the single opaque [`InvalidFrame`]; no content or crypto detail is echoed.
//! The v1 API in the crate root is unchanged and never reinterprets these tags.

use alloc::vec::Vec;
use core::fmt;

pub const WS_SUBPROTOCOL: &str = "pda-relay.cbor.v2";
pub const WS_PATH: &str = "/v2/ws";
pub const MAX_FRAME_BYTES: usize = 81_920;
pub const MAX_DIRECTORY_PAYLOAD_BYTES: usize = 16_384;
pub const MAX_AUTHORIZATION_ENVELOPE_BYTES: usize = 4_352;
pub const MAX_TBS_BYTES: usize = 4_096;
pub const MAX_KEYSET_BYTES: usize = 1_024;
pub const MAX_ENVELOPE_BYTES: usize = 73_728;
pub const MAX_CIPHERTEXT_BYTES: usize = 65_664;
pub const HEADER_BYTES: usize = 224;
pub const MAX_SIGNATURE_BYTES: usize = 72;
pub const MIN_SIGNATURE_BYTES: usize = 8;
/// Ping/pong nonces are 0..=2^63-1 (R4 heartbeat numeric domain).
pub const MAX_NONCE: u64 = i64::MAX as u64;
pub const ROOT_SPKI_BYTES: usize = 91;

const VERSION: u64 = 2;
const PROOF_ALGORITHM_P256_SHA256_DER: u64 = 1;
const ACCEPTED_QUEUE_ADMISSION: u64 = 1;
const ENVELOPE_SIGNATURE_P256_SHA256_DER: u64 = 1;

/// `SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING 04 || X || Y }` prefix.
const CANONICAL_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];
/// P-256 field prime p, big-endian.
const P256_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
/// P-256 group order n, big-endian.
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const HPKE_TYPE_URL: &[u8] = b"type.googleapis.com/google.crypto.tink.HpkePublicKey";
/// HpkeParams: kem DHKEM_X25519_HKDF_SHA256 (1), kdf HKDF_SHA256 (1), aead AES_256_GCM (2).
const HPKE_PARAMS: [u8; 6] = [8, 1, 16, 1, 24, 2];
/// tink-java v1.23.0 `internal/Curve25519.java` BANNED_PUBLIC_KEYS, compared after clearing bit 255
/// (artifact `protocol/test-vectors/network-hpke-low-order-v2.txt`, table SHA-256 b70daac1…bd2e).
const X25519_LOW_ORDER: [[u8; 32]; 7] = [
    [0; 32],
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
        0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
        0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ],
];

/// The only error: input is not a strict R4 relay v2 frame (or an encoder input is invalid).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidFrame;

impl fmt::Display for InvalidFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid relay v2 frame")
    }
}

type Result<T> = core::result::Result<T, InvalidFrame>;

fn ensure(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(InvalidFrame)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// R4 error registry. Codes 1..4 and 8..10 close the connection, 5/6 are per packet, 7 closes after one error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    Malformed = 1,
    AuthFailed = 2,
    ChallengeExpired = 3,
    RootAlreadyConnected = 4,
    RecipientOffline = 5,
    Backpressure = 6,
    RateLimit = 7,
    AuthorityMismatch = 8,
    PolicyViolation = 9,
    Capacity = 10,
}

impl ErrorCode {
    pub fn code(self) -> u64 {
        self as u64
    }

    pub fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Self::Malformed,
            2 => Self::AuthFailed,
            3 => Self::ChallengeExpired,
            4 => Self::RootAlreadyConnected,
            5 => Self::RecipientOffline,
            6 => Self::Backpressure,
            7 => Self::RateLimit,
            8 => Self::AuthorityMismatch,
            9 => Self::PolicyViolation,
            10 => Self::Capacity,
            _ => return None,
        })
    }

    /// Only RECIPIENT_OFFLINE and BACKPRESSURE keep the connection open.
    pub fn is_per_packet(self) -> bool {
        matches!(self, Self::RecipientOffline | Self::Backpressure)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketKind {
    Chat = 1,
    Receipt = 2,
    /// Stage 8D Community sync (docs/COMMUNITY_RECORDS_V1_CONTRACT.md); opaque to the relay like the others.
    CommunitySync = 3,
    /// Stage 8E candidate submission (docs/COMMUNITY_CANDIDATE_TRANSPORT_V1_CONTRACT.md); opaque, never stored.
    CommunityCandidate = 4,
    /// Stage 8E moderator custody receipt for one submission; opaque, never stored.
    CommunityCandidateReceipt = 5,
    ContactRequest = 6,
    ContactRejection = 7,
}

/// Strictly parsed public activation v2 binding. The root signature is UNVERIFIED.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationV2<'a> {
    pub envelope: &'a [u8],
    pub tbs: &'a [u8],
    pub signature_der: &'a [u8],
    pub root_id: [u8; 32],
    pub epoch: [u8; 32],
    pub issued_at_millis: u64,
    /// Structurally canonical SPKI (prefix and field range); curve equation NOT yet checked.
    pub signing_spki: &'a [u8],
    pub hpke_public_keyset: &'a [u8],
    pub hpke_key_id: u32,
    pub hpke_raw_public_key: [u8; 32],
    pub historical_v1_tbs_digest: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketHeaderV2 {
    pub kind: PacketKind,
    pub sender_root: [u8; 32],
    pub recipient_root: [u8; 32],
    pub sender_epoch: [u8; 32],
    pub recipient_epoch: [u8; 32],
    pub sender_activation_digest: [u8; 32],
    pub recipient_activation_digest: [u8; 32],
    pub packet_id: [u8; 16],
}

/// Strictly parsed packet envelope E; the device signature is UNVERIFIED and the ciphertext opaque.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketEnvelopeV2<'a> {
    pub original: &'a [u8],
    pub header_bytes: &'a [u8],
    pub header: PacketHeaderV2,
    pub ciphertext: &'a [u8],
    pub signature_der: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameV2<'a> {
    /// `[0, 2, rootSpki:b91, authorizationEnvelope:bstr, clientNonce:b32]` — UNAUTHENTICATED.
    ClientHello { root_spki: &'a [u8], authorization: ActivationV2<'a>, client_nonce: [u8; 32] },
    /// `[1, 1, deviceSignature:bstr]` — canonical DER, UNVERIFIED.
    ClientProof { signature_der: &'a [u8] },
    /// `[3, packetId:b16, to:b32, E:bstr]`; outer IDs equal the nested header.
    ClientForward { envelope: PacketEnvelopeV2<'a> },
    /// `[5, 2, publicContactCard:bstr]`; accepted only after authenticated possession.
    ClientDirectoryPublish { card: &'a [u8] },
    /// `[6, 2, shortHandle:utf8-bstr]`; bounded directory lookup.
    ClientDirectorySearch { query: &'a [u8] },
    /// `[8, nonce]` in either direction.
    Ping { nonce: u64 },
    /// `[9, nonce]` in either direction.
    Pong { nonce: u64 },
    /// `[16, 2, connectionId:b16, serverNonce:b32]`.
    ServerChallenge { connection_id: [u8; 16], server_nonce: [u8; 32] },
    /// `[17, 2, connectionId:b16]`.
    ServerRegistered { connection_id: [u8; 16] },
    /// `[19, packetId:b16, from:b32, E:bstr]`; outer IDs equal the nested header.
    ServerDeliver { envelope: PacketEnvelopeV2<'a> },
    /// `[20, packetId:b16, 1]` — bounded queue admission only, never delivery.
    ServerAccepted { packet_id: [u8; 16] },
    /// `[21, 2, boundedResults:bstr]`; result bytes are an opaque canonical directory response.
    ServerDirectoryResult { results: &'a [u8] },
    /// `[31, code, [0, h''] | [1, packetId:b16]]`.
    ServerError { code: ErrorCode, related_packet_id: Option<[u8; 16]> },
}

impl FrameV2<'_> {
    fn tag(&self) -> u64 {
        match self {
            Self::ClientHello { .. } => 0,
            Self::ClientProof { .. } => 1,
            Self::ClientForward { .. } => 3,
            Self::ClientDirectoryPublish { .. } => 5,
            Self::ClientDirectorySearch { .. } => 6,
            Self::Ping { .. } => 8,
            Self::Pong { .. } => 9,
            Self::ServerChallenge { .. } => 16,
            Self::ServerRegistered { .. } => 17,
            Self::ServerDeliver { .. } => 19,
            Self::ServerAccepted { .. } => 20,
            Self::ServerDirectoryResult { .. } => 21,
            Self::ServerError { .. } => 31,
        }
    }

    /// Whether this frame type is legal in [direction] (PING/PONG are legal in both).
    pub fn allowed(&self, direction: Direction) -> bool {
        allows(self.tag(), direction)
    }
}

fn arity(tag: u64) -> Option<u64> {
    Some(match tag {
        0 => 5,
        1 | 17 | 20 | 31 => 3,
        3 | 16 | 19 => 4,
        5 | 6 | 21 => 3,
        8 | 9 => 2,
        _ => return None,
    })
}

fn allows(tag: u64, direction: Direction) -> bool {
    match direction {
        Direction::ClientToServer => matches!(tag, 0 | 1 | 3 | 5 | 6 | 8 | 9),
        Direction::ServerToClient => matches!(tag, 8 | 9 | 16 | 17 | 19 | 20 | 21 | 31),
    }
}

/// Parses one complete WebSocket binary message received in [direction].
pub fn decode_frame(direction: Direction, input: &[u8]) -> Result<FrameV2<'_>> {
    ensure(!input.is_empty() && input.len() <= MAX_FRAME_BYTES)?;
    let mut r = Reader::new(input);
    let items = r.array()?;
    let tag = r.unsigned()?;
    ensure(arity(tag) == Some(items) && allows(tag, direction))?;
    let frame = match tag {
        0 => {
            ensure(r.unsigned()? == VERSION)?;
            let root_spki = r.bytes_exact(ROOT_SPKI_BYTES)?;
            check_spki(root_spki)?;
            let authorization = decode_activation(r.bytes_max(MAX_AUTHORIZATION_ENVELOPE_BYTES)?)?;
            FrameV2::ClientHello { root_spki, authorization, client_nonce: r.array_of::<32>()? }
        }
        1 => {
            ensure(r.unsigned()? == PROOF_ALGORITHM_P256_SHA256_DER)?;
            let signature_der = r.bytes_max(MAX_SIGNATURE_BYTES)?;
            check_der(signature_der)?;
            FrameV2::ClientProof { signature_der }
        }
        3 | 19 => {
            let packet_id = r.array_of::<16>()?;
            let root = r.array_of::<32>()?;
            let envelope = decode_envelope(r.bytes_max(MAX_ENVELOPE_BYTES)?)?;
            ensure(envelope.header.packet_id == packet_id)?;
            if tag == 3 {
                ensure(envelope.header.recipient_root == root)?;
                FrameV2::ClientForward { envelope }
            } else {
                ensure(envelope.header.sender_root == root)?;
                FrameV2::ServerDeliver { envelope }
            }
        }
        5 => {
            ensure(r.unsigned()? == VERSION)?;
            FrameV2::ClientDirectoryPublish { card: r.bytes_max(MAX_DIRECTORY_PAYLOAD_BYTES)? }
        }
        6 => {
            ensure(r.unsigned()? == VERSION)?;
            let query = r.bytes_max(128)?;
            ensure(core::str::from_utf8(query).is_ok())?;
            FrameV2::ClientDirectorySearch { query }
        }
        8 | 9 => {
            let nonce = r.unsigned()?;
            ensure(nonce <= MAX_NONCE)?;
            if tag == 8 {
                FrameV2::Ping { nonce }
            } else {
                FrameV2::Pong { nonce }
            }
        }
        16 => {
            ensure(r.unsigned()? == VERSION)?;
            let connection_id = r.array_of::<16>()?;
            FrameV2::ServerChallenge { connection_id, server_nonce: r.array_of::<32>()? }
        }
        17 => {
            ensure(r.unsigned()? == VERSION)?;
            FrameV2::ServerRegistered { connection_id: r.array_of::<16>()? }
        }
        20 => {
            let packet_id = r.array_of::<16>()?;
            ensure(r.unsigned()? == ACCEPTED_QUEUE_ADMISSION)?;
            FrameV2::ServerAccepted { packet_id }
        }
        21 => {
            ensure(r.unsigned()? == VERSION)?;
            FrameV2::ServerDirectoryResult { results: r.bytes_max(MAX_DIRECTORY_PAYLOAD_BYTES)? }
        }
        31 => {
            let code = ErrorCode::from_code(r.unsigned()?).ok_or(InvalidFrame)?;
            ensure(r.array()? == 2)?;
            let related_packet_id = match r.unsigned()? {
                0 => {
                    r.bytes_exact(0)?;
                    None
                }
                1 => Some(r.array_of::<16>()?),
                _ => return Err(InvalidFrame),
            };
            FrameV2::ServerError { code, related_packet_id }
        }
        _ => return Err(InvalidFrame),
    };
    r.end()?;
    // Canonical form is the only accepted form: re-encoding must reproduce the input exactly.
    // Compared in place, so decoding never allocates.
    let mut canonical = Compare::new(input);
    emit(&frame, &mut canonical);
    ensure(canonical.matches())?;
    Ok(frame)
}

/// Canonical encoding. Every caller-supplied field is validated without allocating (nested activation
/// and packet envelopes are re-decoded and must equal the supplied structures), the exact output length
/// is counted and bounded by [MAX_FRAME_BYTES], and only then is one buffer of exactly that capacity
/// allocated. The output is re-parsed in [direction] and returned only if it round-trips.
pub fn encode_frame(direction: Direction, frame: &FrameV2<'_>) -> Result<Vec<u8>> {
    ensure(frame.allowed(direction))?;
    validate_fields(frame)?;
    let mut counter = Counter(0);
    emit(frame, &mut counter);
    ensure(counter.0 <= MAX_FRAME_BYTES)?;
    let mut encoded = Vec::with_capacity(counter.0);
    emit(frame, &mut encoded);
    ensure(encoded.len() == counter.0)?;
    ensure(decode_frame(direction, &encoded)? == *frame)?;
    Ok(encoded)
}

/// Allocation-free checks of every variable-size or caller-constructed field, before any output exists.
fn validate_fields(frame: &FrameV2<'_>) -> Result<()> {
    match frame {
        FrameV2::ClientHello { root_spki, authorization, .. } => {
            check_spki(root_spki)?;
            ensure(decode_activation(authorization.envelope)? == *authorization)
        }
        FrameV2::ClientProof { signature_der } => check_der(signature_der),
        FrameV2::ClientForward { envelope } | FrameV2::ServerDeliver { envelope } => {
            ensure(decode_envelope(envelope.original)? == *envelope)
        }
        FrameV2::ClientDirectoryPublish { card } => ensure(!card.is_empty() && card.len() <= MAX_DIRECTORY_PAYLOAD_BYTES),
        FrameV2::ClientDirectorySearch { query } => ensure(!query.is_empty() && query.len() <= 128 && core::str::from_utf8(query).is_ok()),
        FrameV2::ServerDirectoryResult { results } => ensure(results.len() <= MAX_DIRECTORY_PAYLOAD_BYTES),
        FrameV2::Ping { nonce } | FrameV2::Pong { nonce } => ensure(*nonce <= MAX_NONCE),
        // Fixed-size arrays and a registered error code: nothing caller-sized remains.
        FrameV2::ServerChallenge { .. }
        | FrameV2::ServerRegistered { .. }
        | FrameV2::ServerAccepted { .. }
        | FrameV2::ServerError { .. } => Ok(()),
    }
}

/// The single canonical serialization, written to any [Sink] (counter, exact buffer or comparator).
fn emit<S: Sink>(frame: &FrameV2<'_>, out: &mut S) {
    let tag = frame.tag();
    cbor_array(out, arity(tag).unwrap_or(0));
    cbor_unsigned(out, tag);
    match frame {
        FrameV2::ClientHello { root_spki, authorization, client_nonce } => {
            cbor_unsigned(out, VERSION);
            cbor_bytes(out, root_spki);
            cbor_bytes(out, authorization.envelope);
            cbor_bytes(out, client_nonce);
        }
        FrameV2::ClientProof { signature_der } => {
            cbor_unsigned(out, PROOF_ALGORITHM_P256_SHA256_DER);
            cbor_bytes(out, signature_der);
        }
        FrameV2::ClientForward { envelope } => {
            cbor_bytes(out, &envelope.header.packet_id);
            cbor_bytes(out, &envelope.header.recipient_root);
            cbor_bytes(out, envelope.original);
        }
        FrameV2::ClientDirectoryPublish { card } | FrameV2::ClientDirectorySearch { query: card } => {
            cbor_unsigned(out, VERSION);
            cbor_bytes(out, card);
        }
        FrameV2::ServerDeliver { envelope } => {
            cbor_bytes(out, &envelope.header.packet_id);
            cbor_bytes(out, &envelope.header.sender_root);
            cbor_bytes(out, envelope.original);
        }
        FrameV2::Ping { nonce } | FrameV2::Pong { nonce } => cbor_unsigned(out, *nonce),
        FrameV2::ServerChallenge { connection_id, server_nonce } => {
            cbor_unsigned(out, VERSION);
            cbor_bytes(out, connection_id);
            cbor_bytes(out, server_nonce);
        }
        FrameV2::ServerRegistered { connection_id } => {
            cbor_unsigned(out, VERSION);
            cbor_bytes(out, connection_id);
        }
        FrameV2::ServerAccepted { packet_id } => {
            cbor_bytes(out, packet_id);
            cbor_unsigned(out, ACCEPTED_QUEUE_ADMISSION);
        }
        FrameV2::ServerDirectoryResult { results } => {
            cbor_unsigned(out, VERSION);
            cbor_bytes(out, results);
        }
        FrameV2::ServerError { code, related_packet_id } => {
            cbor_unsigned(out, code.code());
            cbor_array(out, 2);
            match related_packet_id {
                None => {
                    cbor_unsigned(out, 0);
                    cbor_bytes(out, &[]);
                }
                Some(id) => {
                    cbor_unsigned(out, 1);
                    cbor_bytes(out, id);
                }
            }
        }
    }
}

/// `[2, tbs:bstr, 1, signature:bstr]` with TBS
/// `[2, rootId:b32, epoch:b32, issuedAt, [[1,1,signingSpki:b91],[2,2,keyset:bstr]], [0,h''] | [1,b32]]`.
pub fn decode_activation(original: &[u8]) -> Result<ActivationV2<'_>> {
    ensure(!original.is_empty() && original.len() <= MAX_AUTHORIZATION_ENVELOPE_BYTES)?;
    let mut e = Reader::new(original);
    ensure(e.array()? == 4 && e.unsigned()? == 2)?;
    let tbs = e.bytes_max(MAX_TBS_BYTES)?;
    ensure(!tbs.is_empty() && e.unsigned()? == 1)?;
    let signature_der = e.bytes_max(MAX_SIGNATURE_BYTES)?;
    check_der(signature_der)?;
    e.end()?;

    let mut r = Reader::new(tbs);
    ensure(r.array()? == 6 && r.unsigned()? == 2)?;
    let root_id = r.array_of::<32>()?;
    let epoch = r.array_of::<32>()?;
    ensure(epoch.iter().any(|byte| *byte != 0))?;
    let issued_at_millis = r.unsigned()?;
    ensure(r.array()? == 2)?;
    ensure(r.array()? == 3 && r.unsigned()? == 1 && r.unsigned()? == 1)?;
    let signing_spki = r.bytes_exact(ROOT_SPKI_BYTES)?;
    check_spki(signing_spki)?;
    ensure(r.array()? == 3 && r.unsigned()? == 2 && r.unsigned()? == 2)?;
    let hpke_public_keyset = r.bytes_max(MAX_KEYSET_BYTES)?;
    let (hpke_key_id, hpke_raw_public_key) = scan_hpke_public_keyset(hpke_public_keyset)?;
    ensure(r.array()? == 2)?;
    let historical_v1_tbs_digest = match r.unsigned()? {
        0 => {
            r.bytes_exact(0)?;
            None
        }
        1 => Some(r.array_of::<32>()?),
        _ => return Err(InvalidFrame),
    };
    r.end()?;
    Ok(ActivationV2 {
        envelope: original,
        tbs,
        signature_der,
        root_id,
        epoch,
        issued_at_millis,
        signing_spki,
        hpke_public_keyset,
        hpke_key_id,
        hpke_raw_public_key,
        historical_v1_tbs_digest,
    })
}

/// `E = [2, H:bstr(224), ciphertext:bstr(1..65664), 1, signature:bstr]`, H a 9-item header.
pub fn decode_envelope(original: &[u8]) -> Result<PacketEnvelopeV2<'_>> {
    ensure(!original.is_empty() && original.len() <= MAX_ENVELOPE_BYTES)?;
    let mut e = Reader::new(original);
    ensure(e.array()? == 5 && e.unsigned()? == 2)?;
    let header_bytes = e.bytes_exact(HEADER_BYTES)?;
    let header = decode_header(header_bytes)?;
    let ciphertext = e.bytes_max(MAX_CIPHERTEXT_BYTES)?;
    ensure(!ciphertext.is_empty() && e.unsigned()? == ENVELOPE_SIGNATURE_P256_SHA256_DER)?;
    let signature_der = e.bytes_max(MAX_SIGNATURE_BYTES)?;
    check_der(signature_der)?;
    e.end()?;
    Ok(PacketEnvelopeV2 { original, header_bytes, header, ciphertext, signature_der })
}

fn decode_header(bytes: &[u8]) -> Result<PacketHeaderV2> {
    ensure(bytes.len() == HEADER_BYTES)?;
    let mut r = Reader::new(bytes);
    ensure(r.array()? == 9 && r.unsigned()? == VERSION)?;
    let kind = match r.unsigned()? {
        1 => PacketKind::Chat,
        2 => PacketKind::Receipt,
        3 => PacketKind::CommunitySync,
        4 => PacketKind::CommunityCandidate,
        5 => PacketKind::CommunityCandidateReceipt,
        6 => PacketKind::ContactRequest,
        7 => PacketKind::ContactRejection,
        _ => return Err(InvalidFrame),
    };
    let header = PacketHeaderV2 {
        kind,
        sender_root: r.array_of::<32>()?,
        recipient_root: r.array_of::<32>()?,
        sender_epoch: r.array_of::<32>()?,
        recipient_epoch: r.array_of::<32>()?,
        sender_activation_digest: r.array_of::<32>()?,
        recipient_activation_digest: r.array_of::<32>()?,
        packet_id: r.array_of::<16>()?,
    };
    r.end()?;
    Ok(header)
}

/// Exact 91-byte canonical uncompressed P-256 SPKI with x, y < p. The curve equation is NOT checked here.
pub fn check_spki(spki: &[u8]) -> Result<()> {
    ensure(spki.len() == ROOT_SPKI_BYTES && spki[..27] == CANONICAL_SPKI_PREFIX)?;
    ensure(less_than(&spki[27..59], &P256_P) && less_than(&spki[59..91], &P256_P))
}

/// Strict canonical DER `SEQUENCE { INTEGER r, INTEGER s }`, 8..=72 bytes, short-form lengths,
/// positive minimal integers of 1..=33 bytes and 1 <= r, s < n (both high-S and low-S accepted).
pub fn check_der(der: &[u8]) -> Result<()> {
    ensure(der.len() >= MIN_SIGNATURE_BYTES && der.len() <= MAX_SIGNATURE_BYTES)?;
    ensure(der[0] == 0x30 && usize::from(der[1]) == der.len() - 2 && der[1] < 0x80)?;
    let mut offset = 2;
    for _ in 0..2 {
        ensure(offset + 2 <= der.len() && der[offset] == 0x02)?;
        let length = usize::from(der[offset + 1]);
        offset += 2;
        ensure((1..=33).contains(&length) && offset + length <= der.len())?;
        let integer = &der[offset..offset + length];
        offset += length;
        ensure(integer[0] & 0x80 == 0)?;
        ensure(length == 1 || integer[0] != 0 || integer[1] & 0x80 != 0)?;
        let significant = match integer.iter().position(|byte| *byte != 0) {
            Some(first) => &integer[first..],
            None => return Err(InvalidFrame),
        };
        ensure(significant.len() <= 32)?;
        let mut padded = [0u8; 32];
        padded[32 - significant.len()..].copy_from_slice(significant);
        ensure(less_than(&padded, &P256_N))?;
    }
    ensure(offset == der.len())
}

/// Finite Tink public keyset profile (R4 / NETWORK_HPKE_PUBLIC_KEYSET_PROFILE_DISCOVERY): one ENABLED
/// TINK primary HpkePublicKey (X25519 / HKDF-SHA256 / AES-256-GCM), nonzero uint32 key ID, exact field
/// order, minimal varints, no unknown/duplicate/trailing fields, raw point not in the low-order table.
/// Returns the key ID and the raw 32-byte public point.
pub fn scan_hpke_public_keyset(original: &[u8]) -> Result<(u32, [u8; 32])> {
    ensure(!original.is_empty() && original.len() <= MAX_KEYSET_BYTES)?;
    let mut outer = Proto::new(original);
    outer.expect(8)?;
    let id = outer.number()?;
    ensure(id != 0)?;
    let mut key = outer.message(18)?;
    outer.end()?;
    let mut data = key.message(10)?;
    ensure(data.message(10)?.rest() == HPKE_TYPE_URL)?;
    let mut hpke = data.message(18)?;
    data.expect(24)?;
    data.expect(3)?;
    data.end()?;
    ensure(hpke.message(18)?.rest() == HPKE_PARAMS)?;
    let raw = hpke.message(26)?.rest();
    ensure(raw.len() == 32)?;
    let mut point = [0u8; 32];
    point.copy_from_slice(raw);
    ensure(!is_x25519_low_order(&point))?;
    hpke.end()?;
    key.expect(16)?;
    key.expect(1)?;
    key.expect(24)?;
    ensure(key.number()? == id)?;
    key.expect(32)?;
    key.expect(1)?;
    key.end()?;
    Ok((u32::try_from(id).map_err(|_| InvalidFrame)?, point))
}

/// Tink rule: copy, clear bit 255, compare with every BANNED_PUBLIC_KEYS row.
pub fn is_x25519_low_order(point: &[u8; 32]) -> bool {
    let mut cleared = *point;
    cleared[31] &= 0x7f;
    X25519_LOW_ORDER.contains(&cleared)
}

/// Big-endian `a < b` for equal-length inputs.
fn less_than(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(b) {
        if x != y {
            return x < y;
        }
    }
    false
}

/// Strict deterministic CBOR reader: major types 0 (uint), 2 (bstr) and 4 (array) only, shortest
/// heads, definite lengths, every length checked against the remaining input before slicing.
struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn head(&mut self, major: u8) -> Result<u64> {
        let initial = *self.input.get(self.offset).ok_or(InvalidFrame)?;
        self.offset += 1;
        ensure(initial >> 5 == major)?;
        let (count, minimum) = match initial & 0x1f {
            value @ 0..=23 => return Ok(u64::from(value)),
            24 => (1, 24),
            25 => (2, 0x100),
            26 => (4, 0x1_0000),
            27 => (8, 0x1_0000_0000),
            _ => return Err(InvalidFrame),
        };
        let end = self.offset.checked_add(count).ok_or(InvalidFrame)?;
        let bytes = self.input.get(self.offset..end).ok_or(InvalidFrame)?;
        self.offset = end;
        let value = bytes.iter().fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
        // Shortest form only, and (as on Android) every value fits a signed 64-bit host integer.
        ensure(value >= minimum && value <= MAX_NONCE)?;
        Ok(value)
    }

    fn unsigned(&mut self) -> Result<u64> {
        self.head(0)
    }

    fn array(&mut self) -> Result<u64> {
        self.head(4)
    }

    fn bytes_max(&mut self, max: usize) -> Result<&'a [u8]> {
        let length = self.head(2)?;
        let length = usize::try_from(length).map_err(|_| InvalidFrame)?;
        ensure(length <= max && length <= self.input.len() - self.offset)?;
        let value = &self.input[self.offset..self.offset + length];
        self.offset += length;
        Ok(value)
    }

    fn bytes_exact(&mut self, size: usize) -> Result<&'a [u8]> {
        let value = self.bytes_max(size)?;
        ensure(value.len() == size)?;
        Ok(value)
    }

    fn array_of<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.bytes_exact(N)?.try_into().map_err(|_| InvalidFrame)
    }

    fn end(&self) -> Result<()> {
        ensure(self.offset == self.input.len())
    }
}

/// Destination of canonical output.
trait Sink {
    fn put(&mut self, bytes: &[u8]);
}

/// Counts output bytes without storing them.
struct Counter(usize);

impl Sink for Counter {
    fn put(&mut self, bytes: &[u8]) {
        self.0 = self.0.saturating_add(bytes.len());
    }
}

/// Writes into a buffer whose capacity was reserved from [Counter] beforehand.
impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// Compares the canonical output with existing bytes, in place.
struct Compare<'a> {
    expected: &'a [u8],
    offset: usize,
    equal: bool,
}

impl<'a> Compare<'a> {
    fn new(expected: &'a [u8]) -> Self {
        Self { expected, offset: 0, equal: true }
    }

    fn matches(&self) -> bool {
        self.equal && self.offset == self.expected.len()
    }
}

impl Sink for Compare<'_> {
    fn put(&mut self, bytes: &[u8]) {
        let end = self.offset.saturating_add(bytes.len());
        self.equal = self.equal && self.expected.get(self.offset..end) == Some(bytes);
        self.offset = end;
    }
}

/// Shortest-form deterministic CBOR head for major types 0 (uint), 2 (bstr) and 4 (array).
fn cbor_head<S: Sink>(out: &mut S, major: u8, value: u64) {
    let major = major << 5;
    let mut head = [0u8; 9];
    let used = if value < 24 {
        head[0] = major | value as u8;
        1
    } else if value <= 0xff {
        head[0] = major | 24;
        head[1] = value as u8;
        2
    } else if value <= 0xffff {
        head[0] = major | 25;
        head[1..3].copy_from_slice(&(value as u16).to_be_bytes());
        3
    } else if value <= 0xffff_ffff {
        head[0] = major | 26;
        head[1..5].copy_from_slice(&(value as u32).to_be_bytes());
        5
    } else {
        head[0] = major | 27;
        head[1..9].copy_from_slice(&value.to_be_bytes());
        9
    };
    out.put(&head[..used]);
}

fn cbor_unsigned<S: Sink>(out: &mut S, value: u64) {
    cbor_head(out, 0, value);
}

fn cbor_array<S: Sink>(out: &mut S, items: u64) {
    cbor_head(out, 4, items);
}

fn cbor_bytes<S: Sink>(out: &mut S, value: &[u8]) {
    cbor_head(out, 2, value.len() as u64);
    out.put(value);
}

/// Exact-tag protobuf reader for the finite HPKE public profile: single-byte tags, minimal varints of at
/// most five bytes (uint32 range), length-delimited messages consumed exactly.
struct Proto<'a> {
    input: &'a [u8],
}

impl<'a> Proto<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    fn next(&mut self) -> Result<u8> {
        let (first, rest) = self.input.split_first().ok_or(InvalidFrame)?;
        self.input = rest;
        Ok(*first)
    }

    fn expect(&mut self, value: u8) -> Result<()> {
        ensure(self.next()? == value)
    }

    fn number(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for index in 0..5 {
            let byte = self.next()?;
            if index == 4 {
                ensure(byte <= 15)?;
            }
            value |= u64::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                ensure(index == 0 || byte != 0)?;
                return Ok(value);
            }
        }
        Err(InvalidFrame)
    }

    fn message(&mut self, tag: u8) -> Result<Proto<'a>> {
        self.expect(tag)?;
        let length = usize::try_from(self.number()?).map_err(|_| InvalidFrame)?;
        ensure(length <= self.input.len())?;
        let (inner, rest) = self.input.split_at(length);
        self.input = rest;
        Ok(Proto { input: inner })
    }

    fn rest(&self) -> &'a [u8] {
        self.input
    }

    fn end(&self) -> Result<()> {
        ensure(self.input.is_empty())
    }
}

/// Strict bootstrap wrapper; card authority and device signature are checked by the authenticator.
pub fn decode_bootstrap(ciphertext: &[u8]) -> Result<(&[u8], ActivationV2<'_>)> {
    let mut outer = Reader::new(ciphertext);
    ensure(outer.array()? == 2)?;
    let card = outer.bytes_max(4608)?;
    let encrypted = outer.bytes_max(MAX_CIPHERTEXT_BYTES)?;
    ensure(!encrypted.is_empty())?;
    outer.end()?;
    let mut r = Reader::new(card);
    ensure(r.array()? == 4 && r.unsigned()? == VERSION)?;
    let root = r.bytes_exact(ROOT_SPKI_BYTES)?;
    check_spki(root)?;
    let activation = decode_activation(r.bytes_max(4352)?)?;
    let callsign = r.bytes_max(24)?;
    ensure(callsign.len() >= 3 && callsign.iter().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-'))?;
    r.end()?;
    Ok((root, activation))
}
