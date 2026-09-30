FROM rust:1.98.1-slim-trixie AS core
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl patch gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl -fsSL https://codeload.github.com/owenewans/snolc/tar.gz/d71069837c12816b625c09ed0cd6ec1e3b4a7354 -o source.tar.gz \
    && echo '945144323ac0c1c71cf2a3ea6a5ef082b101baa63ca0a679f357df2130991e0d  source.tar.gz' | sha256sum -c - \
    && tar xzf source.tar.gz --strip-components=1
COPY dockerfile/snolc-core.patch /build/core.patch
RUN patch -p1 < core.patch \
    && cargo test --locked --release --workspace \
    && cargo build --locked --release -p snolc-cli
WORKDIR /modules
RUN curl -fsSL https://codeload.github.com/owenewans/snolc-modules/tar.gz/bdc701687ac4d69961e9d325db6be07d748a6e0a -o source.tar.gz \
    && echo 'f07ae9949c89875365bf65d4eb01d737fc8307f323ac24e4d44af4579c1e3c7e  source.tar.gz' | sha256sum -c - \
    && tar xzf source.tar.gz --strip-components=1
COPY dockerfile/snolc-modules.patch /modules/modules.patch
RUN patch -p1 < modules.patch \
    && cargo test --locked --release -p snolc-adapter-socks5 -p snolc-policy-local \
    && cargo build --locked --release -p snolc-adapter-socks5 -p snolc-policy-local

FROM debian:trixie-slim
LABEL io.vpnbot.snolc.version="0.0.4+vpnbot.3"
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates python3 python3-cryptography \
    && rm -rf /var/lib/apt/lists/*
COPY app/snolc /snolc
RUN PYTHONPATH=/snolc python3 -c 'from snolc_config import install; install("/opt/snolc/runtime", server=True)'
COPY --from=core /build/target/release/snolc /opt/snolc/runtime/bin/snolc
COPY --from=core /modules/target/release/libsnolc_adapter_socks5.so /tmp/libsnolc_adapter_socks5.so
COPY --from=core /modules/target/release/libsnolc_policy_local.so /tmp/libsnolc_policy_local.so
RUN python3 /snolc/build_patches.py /opt/snolc/runtime/bin/snolc /tmp/libsnolc_adapter_socks5.so /tmp/libsnolc_policy_local.so /opt/snolc/client-patches.zip \
    && PYTHONPATH=/snolc python3 -c 'from snolc_config import install_patches; install_patches("/opt/snolc/runtime", "/opt/snolc/client-patches.zip", server=True)' \
    && rm /tmp/libsnolc_adapter_socks5.so /tmp/libsnolc_policy_local.so
COPY scripts/protocol_service.py scripts/snolc_service.py /
ENV PYTHONPATH=/snolc
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=3 \
    CMD python3 -c 'import json,time; s=json.load(open("/state/status.json")); assert time.time()-s["time"]<15 and s["phase"] in ("running","idle","disabled")'
ENTRYPOINT ["python3", "/snolc_service.py", "/state"]
