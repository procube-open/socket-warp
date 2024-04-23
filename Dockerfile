FROM rust:latest as builder
WORKDIR /build
COPY ./sw_listener/. .
RUN cargo build --release

FROM rust:latest
WORKDIR /app
COPY ./sw_connector .
COPY --from=builder /build/target/release/sw_listener .
CMD ["./sw_listener"]
