# PDA Relay Protocol v1

This document is the implementation-independent wire contract for the Phase 1 PDA Network relay. The relay transports opaque application envelopes between currently connected PDA devices. It does not persist packets or routes.

## Transport and versioning

- Transport: one CBOR application frame per binary WebSocket message.
- WebSocket endpoint: `/v1/ws`.
- Required WebSocket subprotocol: `pda-relay.cbor.v1`.
- Application protocol version: unsigned integer `1`.
- Text WebSocket messages are invalid application frames.
- RFC 6455 Ping/Pong control frames are independent of the application `PING` and `PONG` frames below.
- Relay v1 does not define an Internet-safe deployment profile. Phase 1 plain
  `ws://` is restricted to localhost or Android-emulator host development. A future
  Internet dialect requires TLS plus authenticated route registration; TLS alone
  does not authenticate a PDA identity.

The client sends `HELLO` as its first application frame within the relay's configured timeout. The relay chooses the highest mutually supported version; v1 relays support only version 1. A client offering a range that excludes 1 receives `VERSION_UNSUPPORTED` and is disconnected.

## CBOR profile

Every frame is a definite-length CBOR array. The first array item is an unsigned integer type tag. Implementations must reject:

- indefinite arrays or byte strings;
- a wrong array length;
- unknown tags or error codes;
- non-canonical field types;
- IDs with incorrect lengths;
- trailing bytes after the top-level value;
- frames or opaque payloads over configured limits.

`pda_id` and `from`/`to` values are exactly 32 bytes. Packet IDs are exactly 16 bytes. Nonces are unsigned 64-bit integers. The opaque payload is a definite-length byte string.

## Client-to-relay frames

| Tag | Name | CBOR array |
|---:|---|---|
| 0 | `HELLO` | `[0, min_version:u16, max_version:u16, pda_id:bstr(32)]` |
| 1 | `PING` | `[1, nonce:u64]` |
| 2 | `PONG` | `[2, nonce:u64]` |
| 3 | `FORWARD` | `[3, packet_id:bstr(16), to:bstr(32), opaque_payload:bstr]` |
| 4 | `ACK` | `[4, acked_packet_id:bstr(16), to:bstr(32)]` |

## Relay-to-client frames

| Tag | Name | CBOR array |
|---:|---|---|
| 16 | `HELLO_OK` | `[16, selected_version:u16]` |
| 17 | `PING` | `[17, nonce:u64]` |
| 18 | `PONG` | `[18, nonce:u64]` |
| 19 | `DELIVER` | `[19, packet_id:bstr(16), from:bstr(32), opaque_payload:bstr]` |
| 20 | `DELIVERY_ACK` | `[20, acked_packet_id:bstr(16), from:bstr(32)]` |
| 31 | `ERROR` | `[31, code:u16, related_packet_id:null\|bstr(16)]` |

## Routing and delivery

After `HELLO_OK`, the relay maps the 32-byte PDA ID to that live connection in RAM.
This value is self-asserted and unauthenticated: v1 proves neither possession of an
identity key nor that the connection belongs to that PDA. A second live connection
claiming the same ID receives `ROUTE_IN_USE`. Disconnect, heartbeat timeout,
process exit, or restart removes the route.

For `FORWARD`, the relay replaces `to` with the session's self-asserted registered
`from` value and sends `DELIVER` to the current recipient route. This is routing
metadata, not authenticated sender identity. The opaque payload is not interpreted.
If no route exists, the sender receives `RECIPIENT_OFFLINE`; the relay does not
queue the packet.

Only the receiving client sends `ACK` after its local duplicate check and durable
processing. The relay routes it as `DELIVERY_ACK`. V1 records this evidence as
`UNAUTHENTICATED_TRANSPORT_ACK`: both the recipient route and ACK are self-asserted,
not cryptographically authenticated. Successful admission to the relay's in-memory
output channel is not a delivery acknowledgment.

The sender must retain each outgoing packet in its device-local outbox until it receives the matching recipient-generated ACK. A recipient that sees a duplicate packet must not apply it twice and should ACK it again.

## Errors

| Code | Name | Meaning |
|---:|---|---|
| 1 | `MALFORMED_FRAME` | CBOR or frame shape is invalid |
| 2 | `PACKET_TOO_LARGE` | frame or opaque payload exceeds a configured bound |
| 3 | `VERSION_UNSUPPORTED` | HELLO range does not include a supported version |
| 4 | `HELLO_REQUIRED` | first application frame was not a valid HELLO, or HELLO was repeated |
| 5 | `ROUTE_IN_USE` | the PDA ID already has a live route |
| 6 | `RECIPIENT_OFFLINE` | no current route exists for the destination |
| 7 | `RATE_LIMITED` | per-connection packet rate was exceeded |
| 8 | `BACKPRESSURE` | recipient's bounded in-memory output channel is full |

Size violations close the WebSocket with code 1009. Repeated malformed frames and other policy violations close it with code 1008. Limits are operator-configurable; clients must not assume values beyond what an operator publishes.

## Heartbeat

The relay periodically sends application `PING` with a nonce. A client responds with `PONG` containing that nonce. Failure to return the matching PONG within the configured heartbeat timeout closes the session and removes its route. Clients may also send application `PING`; the relay returns `PONG` with the same nonce.

## Application envelope and identity limitation

`opaque_payload` carries client-produced, versioned application-envelope bytes. The
relay neither parses nor validates them. Phase 1 uses only the
`DEVELOPMENT_PLAINTEXT` security mode defined by
[`PDA_APPLICATION_ENVELOPE.md`](PDA_APPLICATION_ENVELOPE.md); opaque forwarding is
not encryption, authentication, integrity protection, or a secure receipt. No
future encrypted-envelope schema is defined by this relay contract.

Phase 1 `HELLO` does **not** prove possession of an identity private key. On an untrusted relay, a party that knows a PDA ID may claim it first. Production identity proof requires a future versioned challenge/signature exchange; it must use established cryptography and must not silently alter v1 framing.

TLS protects the client-to-relay hop but does not replace end-to-end encryption. A relay can still observe timing, packet sizes, live routing IDs, and communication relationships, and can drop, delay, replay, or refuse traffic.

## Federation extension points

Tags not defined here are reserved. Federation is not implemented in v1. Future federation must preserve PDA IDs independently of relay addresses, keep presence ephemeral, and introduce new versioned frames rather than reinterpreting v1 fields.

Golden byte vectors are in [`test-vectors/v1.txt`](test-vectors/v1.txt). The executable reference codec is in `relay/protocol`.

Root/device identity and credential bytes are specified separately in
[`PDA_IDENTITY.md`](PDA_IDENTITY.md). Relay v1 does not consume those credentials.
