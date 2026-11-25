#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use minicbor::{data::Type, Decoder, Encoder};

/// Relay v2 dialect (R4). Separate module; the v1 API below is unchanged.
pub mod v2;
/// Relay v2 runtime core (sans-IO registry, phases, budgets, heartbeat).
pub mod v2_relay;
/// Relay v2 root authorization and device possession verifier (production `Authenticator`).
pub mod v2_auth;

pub const PROTOCOL_V1: u16 = 1;
pub const WS_SUBPROTOCOL: &str = "pda-relay.cbor.v1";
pub const PDA_ID_LEN: usize = 32;
pub const PACKET_ID_LEN: usize = 16;

const CLIENT_HELLO: u8 = 0;
const CLIENT_PING: u8 = 1;
const CLIENT_PONG: u8 = 2;
const CLIENT_FORWARD: u8 = 3;
const CLIENT_ACK: u8 = 4;
const SERVER_HELLO_OK: u8 = 16;
const SERVER_PING: u8 = 17;
const SERVER_PONG: u8 = 18;
const SERVER_DELIVER: u8 = 19;
const SERVER_DELIVERY_ACK: u8 = 20;
const SERVER_ERROR: u8 = 31;

pub type PdaId = [u8; PDA_ID_LEN];
pub type PacketId = [u8; PACKET_ID_LEN];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_frame_bytes: usize,
    pub max_payload_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 16_384,
            max_payload_bytes: 16_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ErrorCode {
    MalformedFrame = 1,
    PacketTooLarge = 2,
    VersionUnsupported = 3,
    HelloRequired = 4,
    RouteInUse = 5,
    RecipientOffline = 6,
    RateLimited = 7,
    Backpressure = 8,
}

impl ErrorCode {
    fn from_u16(value: u16) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::MalformedFrame),
            2 => Ok(Self::PacketTooLarge),
            3 => Ok(Self::VersionUnsupported),
            4 => Ok(Self::HelloRequired),
            5 => Ok(Self::RouteInUse),
            6 => Ok(Self::RecipientOffline),
            7 => Ok(Self::RateLimited),
            8 => Ok(Self::Backpressure),
            _ => Err(ProtocolError::Malformed("unknown error code")),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ClientFrame<'a> {
    Hello {
        min_version: u16,
        max_version: u16,
        pda_id: PdaId,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Forward {
        packet_id: PacketId,
        to: PdaId,
        opaque_payload: &'a [u8],
    },
    Ack {
        acked_packet_id: PacketId,
        to: PdaId,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub enum ServerFrame<'a> {
    HelloOk {
        selected_version: u16,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Deliver {
        packet_id: PacketId,
        from: PdaId,
        opaque_payload: &'a [u8],
    },
    DeliveryAck {
        acked_packet_id: PacketId,
        from: PdaId,
    },
    Error {
        code: ErrorCode,
        related_packet_id: Option<PacketId>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    FrameTooLarge,
    PayloadTooLarge,
    Malformed(&'static str),
    Codec,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge => f.write_str("frame exceeds configured maximum"),
            Self::PayloadTooLarge => f.write_str("payload exceeds configured maximum"),
            Self::Malformed(reason) => write!(f, "malformed frame: {reason}"),
            Self::Codec => f.write_str("CBOR codec error"),
        }
    }
}

pub fn decode_client_frame(input: &[u8], limits: Limits) -> Result<ClientFrame<'_>, ProtocolError> {
    check_frame_size(input, limits)?;
    let mut decoder = Decoder::new(input);
    let array_len = definite_array(&mut decoder)?;
    let tag = decoder
        .u8()
        .map_err(|_| ProtocolError::Malformed("invalid type tag"))?;
    let frame = match tag {
        CLIENT_HELLO => {
            require_len(array_len, 4)?;
            let min_version = decoder
                .u16()
                .map_err(|_| ProtocolError::Malformed("invalid minimum version"))?;
            let max_version = decoder
                .u16()
                .map_err(|_| ProtocolError::Malformed("invalid maximum version"))?;
            let pda_id = read_fixed::<PDA_ID_LEN>(&mut decoder, "invalid PDA ID")?;
            ClientFrame::Hello {
                min_version,
                max_version,
                pda_id,
            }
        }
        CLIENT_PING => {
            require_len(array_len, 2)?;
            ClientFrame::Ping {
                nonce: decoder
                    .u64()
                    .map_err(|_| ProtocolError::Malformed("invalid ping nonce"))?,
            }
        }
        CLIENT_PONG => {
            require_len(array_len, 2)?;
            ClientFrame::Pong {
                nonce: decoder
                    .u64()
                    .map_err(|_| ProtocolError::Malformed("invalid pong nonce"))?,
            }
        }
        CLIENT_FORWARD => {
            require_len(array_len, 4)?;
            let packet_id = read_fixed::<PACKET_ID_LEN>(&mut decoder, "invalid packet ID")?;
            let to = read_fixed::<PDA_ID_LEN>(&mut decoder, "invalid recipient PDA ID")?;
            let opaque_payload = decoder
                .bytes()
                .map_err(|_| ProtocolError::Malformed("invalid payload"))?;
            if opaque_payload.len() > limits.max_payload_bytes {
                return Err(ProtocolError::PayloadTooLarge);
            }
            ClientFrame::Forward {
                packet_id,
                to,
                opaque_payload,
            }
        }
        CLIENT_ACK => {
            require_len(array_len, 3)?;
            let acked_packet_id =
                read_fixed::<PACKET_ID_LEN>(&mut decoder, "invalid acknowledged packet ID")?;
            let to = read_fixed::<PDA_ID_LEN>(&mut decoder, "invalid ACK recipient PDA ID")?;
            ClientFrame::Ack {
                acked_packet_id,
                to,
            }
        }
        _ => return Err(ProtocolError::Malformed("unknown client frame type")),
    };
    require_eof(&decoder, input.len())?;
    Ok(frame)
}

pub fn decode_server_frame(input: &[u8], limits: Limits) -> Result<ServerFrame<'_>, ProtocolError> {
    check_frame_size(input, limits)?;
    let mut decoder = Decoder::new(input);
    let array_len = definite_array(&mut decoder)?;
    let tag = decoder
        .u8()
        .map_err(|_| ProtocolError::Malformed("invalid type tag"))?;
    let frame = match tag {
        SERVER_HELLO_OK => {
            require_len(array_len, 2)?;
            ServerFrame::HelloOk {
                selected_version: decoder
                    .u16()
                    .map_err(|_| ProtocolError::Malformed("invalid selected version"))?,
            }
        }
        SERVER_PING => {
            require_len(array_len, 2)?;
            ServerFrame::Ping {
                nonce: decoder
                    .u64()
                    .map_err(|_| ProtocolError::Malformed("invalid ping nonce"))?,
            }
        }
        SERVER_PONG => {
            require_len(array_len, 2)?;
            ServerFrame::Pong {
                nonce: decoder
                    .u64()
                    .map_err(|_| ProtocolError::Malformed("invalid pong nonce"))?,
            }
        }
        SERVER_DELIVER => {
            require_len(array_len, 4)?;
            let packet_id = read_fixed::<PACKET_ID_LEN>(&mut decoder, "invalid packet ID")?;
            let from = read_fixed::<PDA_ID_LEN>(&mut decoder, "invalid sender PDA ID")?;
            let opaque_payload = decoder
                .bytes()
                .map_err(|_| ProtocolError::Malformed("invalid payload"))?;
            if opaque_payload.len() > limits.max_payload_bytes {
                return Err(ProtocolError::PayloadTooLarge);
            }
            ServerFrame::Deliver {
                packet_id,
                from,
                opaque_payload,
            }
        }
        SERVER_DELIVERY_ACK => {
            require_len(array_len, 3)?;
            let acked_packet_id =
                read_fixed::<PACKET_ID_LEN>(&mut decoder, "invalid acknowledged packet ID")?;
            let from = read_fixed::<PDA_ID_LEN>(&mut decoder, "invalid ACK sender PDA ID")?;
            ServerFrame::DeliveryAck {
                acked_packet_id,
                from,
            }
        }
        SERVER_ERROR => {
            require_len(array_len, 3)?;
            let code = ErrorCode::from_u16(
                decoder
                    .u16()
                    .map_err(|_| ProtocolError::Malformed("invalid error code"))?,
            )?;
            let related_packet_id = if decoder
                .datatype()
                .map_err(|_| ProtocolError::Malformed("invalid related packet ID"))?
                == Type::Null
            {
                decoder
                    .null()
                    .map_err(|_| ProtocolError::Malformed("invalid null"))?;
                None
            } else {
                Some(read_fixed::<PACKET_ID_LEN>(
                    &mut decoder,
                    "invalid related packet ID",
                )?)
            };
            ServerFrame::Error {
                code,
                related_packet_id,
            }
        }
        _ => return Err(ProtocolError::Malformed("unknown server frame type")),
    };
    require_eof(&decoder, input.len())?;
    Ok(frame)
}

pub fn encode_client_frame(frame: &ClientFrame<'_>) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    match frame {
        ClientFrame::Hello {
            min_version,
            max_version,
            pda_id,
        } => {
            encoder
                .array(4)
                .and_then(|e| e.u8(CLIENT_HELLO))
                .and_then(|e| e.u16(*min_version))
                .and_then(|e| e.u16(*max_version))
                .and_then(|e| e.bytes(pda_id))
                .map_err(|_| ProtocolError::Codec)?;
        }
        ClientFrame::Ping { nonce } => {
            encoder
                .array(2)
                .and_then(|e| e.u8(CLIENT_PING))
                .and_then(|e| e.u64(*nonce))
                .map_err(|_| ProtocolError::Codec)?;
        }
        ClientFrame::Pong { nonce } => {
            encoder
                .array(2)
                .and_then(|e| e.u8(CLIENT_PONG))
                .and_then(|e| e.u64(*nonce))
                .map_err(|_| ProtocolError::Codec)?;
        }
        ClientFrame::Forward {
            packet_id,
            to,
            opaque_payload,
        } => {
            encoder
                .array(4)
                .and_then(|e| e.u8(CLIENT_FORWARD))
                .and_then(|e| e.bytes(packet_id))
                .and_then(|e| e.bytes(to))
                .and_then(|e| e.bytes(opaque_payload))
                .map_err(|_| ProtocolError::Codec)?;
        }
        ClientFrame::Ack {
            acked_packet_id,
            to,
        } => {
            encoder
                .array(3)
                .and_then(|e| e.u8(CLIENT_ACK))
                .and_then(|e| e.bytes(acked_packet_id))
                .and_then(|e| e.bytes(to))
                .map_err(|_| ProtocolError::Codec)?;
        }
    }
    Ok(encoder.into_writer())
}

pub fn encode_server_frame(frame: &ServerFrame<'_>) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    match frame {
        ServerFrame::HelloOk { selected_version } => {
            encoder
                .array(2)
                .and_then(|e| e.u8(SERVER_HELLO_OK))
                .and_then(|e| e.u16(*selected_version))
                .map_err(|_| ProtocolError::Codec)?;
        }
        ServerFrame::Ping { nonce } => {
            encoder
                .array(2)
                .and_then(|e| e.u8(SERVER_PING))
                .and_then(|e| e.u64(*nonce))
                .map_err(|_| ProtocolError::Codec)?;
        }
        ServerFrame::Pong { nonce } => {
            encoder
                .array(2)
                .and_then(|e| e.u8(SERVER_PONG))
                .and_then(|e| e.u64(*nonce))
                .map_err(|_| ProtocolError::Codec)?;
        }
        ServerFrame::Deliver {
            packet_id,
            from,
            opaque_payload,
        } => {
            encoder
                .array(4)
                .and_then(|e| e.u8(SERVER_DELIVER))
                .and_then(|e| e.bytes(packet_id))
                .and_then(|e| e.bytes(from))
                .and_then(|e| e.bytes(opaque_payload))
                .map_err(|_| ProtocolError::Codec)?;
        }
        ServerFrame::DeliveryAck {
            acked_packet_id,
            from,
        } => {
            encoder
                .array(3)
                .and_then(|e| e.u8(SERVER_DELIVERY_ACK))
                .and_then(|e| e.bytes(acked_packet_id))
                .and_then(|e| e.bytes(from))
                .map_err(|_| ProtocolError::Codec)?;
        }
        ServerFrame::Error {
            code,
            related_packet_id,
        } => {
            encoder
                .array(3)
                .and_then(|e| e.u8(SERVER_ERROR))
                .and_then(|e| e.u16(*code as u16))
                .map_err(|_| ProtocolError::Codec)?;
            if let Some(packet_id) = related_packet_id {
                encoder.bytes(packet_id).map_err(|_| ProtocolError::Codec)?;
            } else {
                encoder.null().map_err(|_| ProtocolError::Codec)?;
            }
        }
    }
    Ok(encoder.into_writer())
}

fn check_frame_size(input: &[u8], limits: Limits) -> Result<(), ProtocolError> {
    if input.len() > limits.max_frame_bytes {
        Err(ProtocolError::FrameTooLarge)
    } else {
        Ok(())
    }
}

fn definite_array(decoder: &mut Decoder<'_>) -> Result<u64, ProtocolError> {
    decoder
        .array()
        .map_err(|_| ProtocolError::Malformed("top-level value must be an array"))?
        .ok_or(ProtocolError::Malformed(
            "indefinite arrays are not allowed",
        ))
}

fn require_len(actual: u64, expected: u64) -> Result<(), ProtocolError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ProtocolError::Malformed("wrong array length"))
    }
}

fn read_fixed<const N: usize>(
    decoder: &mut Decoder<'_>,
    reason: &'static str,
) -> Result<[u8; N], ProtocolError> {
    let bytes = decoder
        .bytes()
        .map_err(|_| ProtocolError::Malformed(reason))?;
    bytes
        .try_into()
        .map_err(|_| ProtocolError::Malformed(reason))
}

fn require_eof(decoder: &Decoder<'_>, input_len: usize) -> Result<(), ProtocolError> {
    if decoder.position() == input_len {
        Ok(())
    } else {
        Err(ProtocolError::Malformed("trailing bytes"))
    }
}
