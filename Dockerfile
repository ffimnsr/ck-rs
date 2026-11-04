# Build both binaries in a pinned Rust image.
FROM rust:1.99-bookworm AS builder

WORKDIR /src
COPY . .
RUN cargo build --release --locked -p chainkeeper-cli -p chainkeeper-server

# Runtime image without build tooling.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin chainkeeper

COPY --from=builder /src/target/release/ck /usr/local/bin/ck
COPY --from=builder /src/target/release/ck-server /usr/local/bin/ck-server

USER chainkeeper
WORKDIR /home/chainkeeper
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail --silent http://127.0.0.1:8080/healthz || exit 1

CMD ["ck-server"]
