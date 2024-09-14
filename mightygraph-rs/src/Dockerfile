
FROM rust:latest as builder

WORKDIR /usr/src/myapp

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && echo 'fn main() { println!("dummy"); }' > src/main.rs

RUN cargo build --release

COPY . .

RUN cargo build --release

FROM debian:buster-slim

RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /usr/local/bin

COPY --from=builder /usr/src/myapp/target/release/myapp .

EXPOSE 8080

# Switch to the non-root user
USER appuser

# Run the application
CMD ["cargo","run","./src/main.rs"]
