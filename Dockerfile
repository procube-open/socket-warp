FROM rust:latest as builder
WORKDIR /build
COPY ./fc_server/. .
RUN cargo build --release

FROM rust:latest
WORKDIR /app
COPY --from=builder /build/target/release/fc_server .
CMD ["./fc_server"]
