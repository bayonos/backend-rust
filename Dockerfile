FROM rust:1.100-alpine AS build

WORKDIR /src
RUN apk add --no-cache musl-dev
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM alpine:3.22
WORKDIR /app
COPY --from=build /src/target/release/backend-rust ./server
ENV HOST=0.0.0.0
ENV PORT=8080
EXPOSE 8080
CMD ["./server"]
