# Deployment

## Phase 1 development only (relay v1)

The supported Phase 1 deployment listens only on `127.0.0.1:8080`. Use it for
same-machine tests or Android emulator-host access through the emulator's host
loopback mapping. Keep the relay process bound to loopback and use synthetic data.

LAN, Wi-Fi, public, and Internet exposure are unsupported. Do not bind
`PDA_RELAY_LISTEN` to a non-loopback address, port-forward the listener, or place
this protocol version behind a public reverse proxy. Plain WebSocket traffic is
visible and modifiable, and `HELLO` route registration is self-asserted.

## Relay v1: never on the Internet

Relay v1 (`/v1/ws`) stays development-only. TLS alone would not fix its self-asserted
`HELLO` route claims, so no reverse-proxy recipe exists for v1, and a v2 proxy must
never forward `/v1/ws` (see below).

## Relay v2 behind a TLS proxy (Internet deployment)

Relay v2 (`/v2/ws`, subprotocol `pda-relay.cbor.v2`) authenticates every route. Each
HELLO carries a root-signed activation, and the PROOF is a device-key signature over
this relay's exact audience and a fresh challenge. The relay never sees plaintext;
packets are end-to-end encrypted and signed by the clients.

TLS is terminated by a reverse proxy **on the same host**. The relay itself listens
only on loopback.

**Environment:**

| Variable | Value |
|---|---|
| `PDA_RELAY_LISTEN` | `127.0.0.1:8080` (loopback only) |
| `PDA_RELAY_V2_AUDIENCE` | `wss://relay.example.org:443/v2/ws\|pda-relay.cbor.v2`: lowercase DNS host, **explicit port** (clients always sign `:443` for the default port), exact suffix |
| `PDA_RELAY_V2_TRUST_PROXY` | `1`: take each client's address from the proxy's single `X-Forwarded-For` value |
| `RUST_LOG` | `pda_relay=info` (no packet or payload logging exists at any level) |

**Why `PDA_RELAY_V2_TRUST_PROXY` matters.** The per-source limits apply per client
address: 8 unauthenticated connections and a handshake budget of 8 at once, then 30 a
minute. Without this variable, every client behind the proxy would share the proxy's
`127.0.0.1` budget. The relay accepts the setting only with a loopback listener and a
production audience. With it set:
- non-loopback peers are refused;
- a missing, repeated or comma-separated `X-Forwarded-For` is refused with HTTP 400.

The proxy must therefore **overwrite** the header with the real client address, never
append to it.

Expected stdout:
```
PDA_RELAY_LISTENING=127.0.0.1:8080
PDA_RELAY_V2=enabled
PDA_RELAY_V2_TRUST_PROXY=enabled
```

### nginx

```nginx
server {
    listen 443 ssl;
    server_name relay.example.org;
    ssl_certificate     /etc/letsencrypt/live/relay.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.org/privkey.pem;

    location = /v2/ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;   # overwrite; never $proxy_add_x_forwarded_for
        proxy_buffering off;
        proxy_read_timeout 120s;                         # above the 30 s application heartbeat
    }
    location / { return 404; }                           # never expose /v1/ws or anything else
}
```

### Caddy

```caddy
relay.example.org {
    @v2 path /v2/ws
    reverse_proxy @v2 127.0.0.1:8080 {
        header_up X-Forwarded-For {remote_host}
    }
    respond 404
}
```

### systemd

```ini
[Unit]
Description=PDA relay v2 (stateless, behind a same-host TLS proxy)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/pda-relay
Environment=PDA_RELAY_LISTEN=127.0.0.1:8080
Environment="PDA_RELAY_V2_AUDIENCE=wss://relay.example.org:443/v2/ws|pda-relay.cbor.v2"
Environment=PDA_RELAY_V2_TRUST_PROXY=1
Environment=RUST_LOG=pda_relay=info
DynamicUser=yes
WorkingDirectory=/
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
CapabilityBoundingSet=
LimitNOFILE=4096
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`PrivateDevices=yes` still provides `/dev/urandom`, the relay's only entropy source;
a read failure aborts the process by design.

### Build and checks

- **Build** on the deployment architecture with the pinned toolchain:
  ```bash
  cargo +1.87.0 build --release --locked -p pda-relay
  ```
  Never use `--features test-faults` for a deployed relay. Those hooks exist only in that
  build and are served only in debug loopback mode.
- **Check the build.** `GET /v2/test/counters` must answer 404, and `GET /v1/ws` must answer
  404 through the proxy.
- **Restart.** A restart drops all routes. Clients reconnect, and their outboxes resend the
  same packets; receivers deduplicate.
- **Capacity.** The defaults (512 connections, 64-frame / 2 MiB queue per recipient) are R4
  limits, not hardware claims. Benchmark before relying on them.

## Process supervision

Run the single binary as an unprivileged user with a read-only working directory and no application data directory. A service manager may capture operational logs; configure retention carefully because connection timing is metadata. Never enable packet/payload logging.

Restarting or replacing the binary intentionally discards every route. Sender PDAs reconnect and retry their device-local outboxes.

## Configuration

The relay reads environment variables only. It does not load `.env` automatically and has no database configuration. Copy values from [`docs/relay-settings.env.example`](docs/relay-settings.env.example) into your development process environment. Keep the listener on loopback. Defaults are conservative development values, not hardware capacity claims. Benchmark before raising limits.

Troubleshooting:

- HTTP 426: client did not offer `pda-relay.cbor.v1`.
- HTTP 503: live connection cap is reached.
- WebSocket close 1008: protocol/rate/heartbeat policy violation.
- WebSocket close 1009: configured frame or payload bound exceeded.
- `RECIPIENT_OFFLINE`: destination has no live route on this relay; the sender should retain and retry locally.
