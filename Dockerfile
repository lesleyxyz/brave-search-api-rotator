# syntax=docker/dockerfile:1
ARG RUST_VERSION=1.98
ARG APP_NAME=brave-rotator

# ---- build stage -------------------------------------------------------------
# Alpine's toolchain is musl-native, so `cargo build --release` yields a fully
# static binary. If you have no access to Docker Hardened Images use instead:
#   FROM rust:${RUST_VERSION}-alpine AS build
#   RUN apk add --no-cache musl-dev
FROM rust:${RUST_VERSION}-alpine3.22 AS build
ARG APP_NAME
WORKDIR /app
RUN apk add --no-cache musl-dev

# 1) Compile dependencies against a stub so this layer is cached until Cargo.toml/Cargo.lock change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release --locked \
 && rm -rf src

# 2) Compile the real sources.
COPY src ./src
RUN touch src/main.rs \
 && cargo build --release --locked \
 && cp "target/release/${APP_NAME}" "/${APP_NAME}"

# ---- runtime stage -----------------------------------------------------------
# Static binary + bundled webpki TLS roots: nothing else is needed, not even CA certs.
FROM scratch
ARG APP_NAME
COPY --from=build "/${APP_NAME}" /brave-rotator
ENV LISTEN_ADDR=0.0.0.0:8080 \
    RUST_LOG=info \
    NO_COLOR=1
EXPOSE 8080
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD ["/brave-rotator", "healthcheck"]
ENTRYPOINT ["/brave-rotator"]
