FROM rust:latest as builder
WORKDIR /build
COPY ./sw_listener/. .
RUN cargo build --release

FROM rust:latest
WORKDIR /app
RUN mkdir sw_connector
COPY ./sw_connector/. ./sw_connector/.
COPY --from=builder /build/target/release/sw_listener .
CMD ["./sw_listener"]
