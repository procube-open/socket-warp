FROM rust:trixie AS builder
WORKDIR /build
COPY ./sw_listener/. .
RUN cargo build --release

FROM debian:trixie-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3t64 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/sw_listener .
CMD ["./sw_listener"]
