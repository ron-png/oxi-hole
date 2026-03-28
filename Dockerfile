FROM rust:1-slim AS builder

WORKDIR /build
COPY . .
RUN cargo build --release && strip target/release/oxi-hole

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/oxi-hole /usr/local/bin/oxi-hole
COPY config.toml /etc/oxi-hole/config.toml

EXPOSE 53/udp 53/tcp 853/tcp 443/tcp 8080/tcp

ENTRYPOINT ["oxi-hole", "/etc/oxi-hole/config.toml"]
