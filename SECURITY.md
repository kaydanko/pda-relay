# Relay security

## Trust boundary

Treat every relay operator as potentially malicious. The relay sees live PDA routing IDs, connection timing, approximate packet sizes, source/destination relationships, and network-layer metadata. It can drop, delay, replay, reorder, rate-limit, or refuse packets.

Private application envelopes must be encrypted end-to-end and signed by PDA clients before `FORWARD`. TLS protects only the hop to the relay. This Phase 1 component does not implement, inspect, or log the cryptographic envelope.

## Phase 1 controls

- strict definite-array CBOR parser with exact shapes and ID lengths;
- frame and opaque-payload bounds before forwarding;
- WebSocket message/frame bounds configured in axum;
- binary application messages only;
- HELLO deadline and version negotiation;
- process-wide connection semaphore;
- per-connection packet-rate limiter;
- bounded output channels with explicit backpressure errors;
- malformed-frame threshold and policy close;
- heartbeat timeout and generation-safe route removal;
- no database, filesystem writes, offline queue, payload inspection, or payload logging.

The no-persistence integration test runs the binary in an isolated HOME/XDG/TMP directory, forwards a recognizable canary, terminates and restarts it, asserts no files were written, and confirms the old recipient route is offline.

## Known limitations

- `HELLO` has no challenge/signature identity proof. A client may claim a known PDA ID before its owner connects. Use only in controlled development until authenticated route registration is added.
- LAN and public/Internet deployments are unsupported in Phase 1. A TLS reverse
  proxy alone is insufficient because route registration remains unauthenticated.
  A future public dialect requires both TLS and authenticated route registration.
- The fixed one-second rate window is intentionally simple and is not a public
  abuse-control boundary.
- Traffic analysis and denial of service cannot be prevented by E2EE.
- Process memory can contain ciphertext and live routing metadata; host compromise can expose it.
- Limits are defaults, not verified ESP32-S3 or production capacity figures.

## Operator rules

Run as an unprivileged user, bind only to loopback, restrict ingress, keep Rust
dependencies patched, cap service memory/file descriptors, and minimize log
retention. Do not publish the Phase 1 listener through a reverse proxy. Do not add
request bodies, PDA IDs, packet IDs, payload bytes, or route-table dumps to logs.

Report suspected vulnerabilities privately to the project maintainers once a disclosure channel is published. Until then, do not publish real PDA identifiers or captured packet material in an issue.
