# The engine is built from this immutable, merged source revision. Update it deliberately.
# ONNX Runtime in the locked engine needs C23 glibc symbols supplied by Debian Trixie.
FROM rust:1.93.0-trixie AS engine-builder
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler libprotobuf-dev libdbus-1-dev pkg-config git && test -f /usr/include/google/protobuf/empty.proto && rm -rf /var/lib/apt/lists/*
WORKDIR /engine
RUN git clone --filter=blob:none https://github.com/DigitumDei/agentpalace.git . \
    && git checkout ba2bb3d74845314d4f4031047101ad861dc49fb9 \
    && test "$(git rev-parse HEAD)" = "ba2bb3d74845314d4f4031047101ad861dc49fb9"
RUN cargo build --release --locked -p agentpalace-cli

FROM rust:1.93.0-trixie AS gateway-builder
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler libprotobuf-dev libdbus-1-dev pkg-config && test -f /usr/include/google/protobuf/empty.proto && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p agentpalace-demo-hub

FROM debian:trixie-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libdbus-1-3 && rm -rf /var/lib/apt/lists/*

FROM runtime AS engine
COPY --from=engine-builder /engine/target/release/agentpalace /usr/local/bin/agentpalace
COPY demo-hub/engine-entrypoint.sh /usr/local/bin/engine-entrypoint.sh
RUN chmod 0755 /usr/local/bin/engine-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/engine-entrypoint.sh"]

FROM runtime AS gateway
COPY --from=gateway-builder /src/target/release/agentpalace-demo-hub /usr/local/bin/agentpalace-demo-hub
ENTRYPOINT ["/usr/local/bin/agentpalace-demo-hub"]