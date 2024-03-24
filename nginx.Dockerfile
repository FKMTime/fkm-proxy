FROM rust:1.77-slim AS proxy-builder
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools

WORKDIR /build
COPY ./client/Cargo.toml ./Cargo.toml
COPY ./client/Cargo.lock ./Cargo.lock
RUN mkdir -p ./src
RUN echo "fn main() {println!(\"if you see this, the build broke\")}" > ./src/main.rs
RUN cargo build --release --target=x86_64-unknown-linux-musl
RUN rm -f target/x86_64-unknown-linux-musl/release/deps/$(cat Cargo.toml | awk '/name/ {print}' | cut -d '"' -f 2 | sed 's/-/_/')*

COPY ./client .
RUN cargo build --release --target=x86_64-unknown-linux-musl
RUN cp -r target/x86_64-unknown-linux-musl/release/$(cat Cargo.toml | awk '/name/ {print}' | cut -d '"' -f 2) /build/server


FROM nginx:alpine
RUN apk add --no-cache certbot certbot-nginx
RUN mkdir -p /etc/letsencrypt

EXPOSE 80
COPY ./nginx/default.conf /etc/nginx/conf.template
COPY ./nginx/entrypoint.sh /entrypoint.sh
RUN rm /etc/nginx/conf.d/default.conf

COPY --from=proxy-builder /build/server /bin/proxy-server
RUN chmod +x /bin/proxy-server

CMD ["/entrypoint.sh"]
