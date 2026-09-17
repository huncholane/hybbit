# syntax=docker/dockerfile:1
# Rust backend image. It also serves the dashboard: the static export of client/,
# which used to run as its own Next.js container. Build context: the repository
# root, because the binary embeds server/package.json's version and the image ships
# server/public and the client export.
#   docker buildx build --platform linux/amd64 -f server-rs/Dockerfile \
#     --build-arg NEXT_PUBLIC_BACKEND_URL=https://a.hygo.ai \
#     --build-arg NEXT_PUBLIC_DISABLE_SIGNUP=false .

# Dashboard: `next build` with `output: "export"` writes plain files to client/out
FROM node:24-alpine AS client
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Shared types package first; it changes rarely
COPY shared ./shared
RUN cd shared && npm install && npm run build

# Client dependencies on their own layer
COPY client/package.json client/package-lock.json ./client/
RUN cd client && npm ci --legacy-peer-deps

COPY client ./client

# Same build-time settings as client/Dockerfile; NEXT_PUBLIC_* values are inlined
# into the bundle, so they are fixed per image
ENV NEXT_TELEMETRY_DISABLED=1
ARG NEXT_PUBLIC_BACKEND_URL
ARG NEXT_PUBLIC_DISABLE_SIGNUP
ARG NEXT_PUBLIC_CLOUD
ARG NEXT_PUBLIC_TURNSTILE_SITE_KEY
ARG NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY
ARG NEXT_PUBLIC_DEPLOYMENT
ARG NEXT_PUBLIC_LITE_DASHBOARD
ENV NEXT_PUBLIC_BACKEND_URL=${NEXT_PUBLIC_BACKEND_URL}
ENV NEXT_PUBLIC_DISABLE_SIGNUP=${NEXT_PUBLIC_DISABLE_SIGNUP}
ENV NEXT_PUBLIC_CLOUD=${NEXT_PUBLIC_CLOUD}
ENV NEXT_PUBLIC_TURNSTILE_SITE_KEY=${NEXT_PUBLIC_TURNSTILE_SITE_KEY}
ENV NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=${NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY}
ENV NEXT_PUBLIC_DEPLOYMENT=${NEXT_PUBLIC_DEPLOYMENT}
ENV NEXT_PUBLIC_LITE_DASHBOARD=${NEXT_PUBLIC_LITE_DASHBOARD}

# npm links file:../shared as a symlink that leaves the project root, which
# Turbopack will not follow; materialise it (as client/Dockerfile does)
RUN cd client \
 && rm -rf node_modules/@hygo/shared \
 && mkdir -p node_modules/@hygo/shared \
 && cp -r ../shared/package.json ../shared/dist node_modules/@hygo/shared/ \
 && npm run build \
 && test -f out/index.html && test -f out/404.html

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
COPY --from=client /app/client/out ./client
ENV CLIENT_DIR=/app/client
# The embed widget points its script at the API the dashboard was built against
ARG NEXT_PUBLIC_BACKEND_URL
ENV NEXT_PUBLIC_BACKEND_URL=${NEXT_PUBLIC_BACKEND_URL}
EXPOSE 3001
CMD ["hygo-backend"]
