FROM rust:latest as builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build the application
RUN cargo build --release


FROM debian:stable-slim as runtime

RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

COPY --from=builder /app/target/release/wafstat .

RUN chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["./wafstat"]
