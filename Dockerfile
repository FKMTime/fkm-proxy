FROM rust:1.84-alpine AS proxy-builder
RUN apk add --no-cache musl-dev

WORKDIR /build
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY ./utils/Cargo.toml ./utils/Cargo.toml
COPY ./utils/Cargo.lock ./utils/Cargo.lock

RUN mkdir -p ./src/server
RUN mkdir -p ./src/client
RUN mkdir -p ./utils/src
RUN echo "fn main() {println!(\"if you see this, the build broke\")}" > ./src/server/main.rs
RUN echo "fn main() {println!(\"if you see this, the build broke\")}" > ./src/client/main.rs
RUN echo "" > ./utils/src/lib.rs
RUN cargo build --release
RUN rm -f ./target/release/deps/fkm_proxy_* ./target/release/deps/utils* ./target/release/deps/libutils*

COPY . .
RUN cargo build --release
RUN cp -r ./target/release/fkm-proxy-server /build/proxy-server
RUN cp -r ./target/release/fkm-proxy-client /build/proxy-client


FROM alpine:latest AS proxy-server
COPY --from=proxy-builder /build/proxy-server /bin/proxy-server

ENTRYPOINT ["/bin/proxy-server"]


FROM nginx:alpine AS proxy-client
EXPOSE 80
COPY ./nginx/entrypoint.sh /entrypoint.sh

COPY --from=proxy-builder /build/proxy-client /bin/proxy-client
RUN chmod +x /bin/proxy-client

CMD ["/entrypoint.sh"]
