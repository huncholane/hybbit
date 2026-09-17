# syntax=docker/dockerfile:1
# Rust backend image. Build context: the repository root, because the binary embeds
# server/package.json's version and the image ships server/public.
#   docker buildx build --platform linux/amd64 -f server-rs/Dockerfile .

FROM rust:1-bookworm AS builder
WORKDIR /build

# Compile dependencies on their own layer so code changes don't rebuild them
COPY server-rs/Cargo.toml server-rs/Cargo.lock server-rs/
RUN mkdir -p server-rs/src \
 && echo 'fn main() {}' > server-rs/src/main.rs \
 && cd server-rs \
 && cargo build --release --locked \
 && rm -rf src target/release/hygo-backend target/release/deps/hygo_backend-*

COPY server/package.json server/package.json
COPY server-rs/src server-rs/src
RUN cd server-rs && touch src/main.rs && cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates wget \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/server-rs/target/release/hygo-backend /usr/local/bin/hygo-backend
COPY server/public ./public
COPY server/GeoLite2-City.mmdb server/GeoLite2-ASN.mmdb ./
EXPOSE 3001
CMD ["hygo-backend"]
