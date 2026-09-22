# Prebuilt static Linux candidate. Packaging recipe only; Docker is not available on this host.
FROM scratch
WORKDIR /data
COPY artifacts/MODIFIED_FILE /mirror-gateway
ENV HOST=127.0.0.1 DATABASE_PATH=/data/gateway.db GATEWAY_COMPAT_PROFILE=mirror
ENTRYPOINT ["/mirror-gateway"]
