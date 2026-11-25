FROM rust:1.87-bookworm AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY protocol ./protocol
COPY linux ./linux

RUN cargo build --release --locked -p pda-relay

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/pda-relay /usr/local/bin/pda-relay

USER 65532:65532
ENV PDA_RELAY_LISTEN=127.0.0.1:8080 \
    PDA_RELAY_V2_TRUST_PROXY=1 \
    RUST_LOG=pda_relay=info

ENTRYPOINT ["/usr/local/bin/pda-relay"]
