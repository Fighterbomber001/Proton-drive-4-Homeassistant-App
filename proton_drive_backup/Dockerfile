ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.22
FROM ${BUILD_FROM}

ARG BUILD_VERSION
ARG BUILD_ARCH
ARG PROTON_CLI_VERSION=0.7.0

RUN apk add --no-cache python3 py3-aiohttp ca-certificates gnupg pass bash tini \
    && wget -O /usr/local/bin/proton-drive "https://proton.me/download/drive/cli/${PROTON_CLI_VERSION}/linux-x64-musl/proton-drive" \
    && echo "fb0e9bb12e18ff3f9c07b18be76e209b7aeedcae23f0e6953d8334ba6516fb6264575f5c1f42021673b7562f0b751d476d4b92c01bffb5e02167f7d1f35889cb  /usr/local/bin/proton-drive" | sha512sum -c - \
    && chmod 0755 /usr/local/bin/proton-drive

ENV PROTON_DRIVE_CREDENTIALS_STORE=pass \
    PROTON_DRIVE_CACHE_DIR=/data/private/proton \
    PROTON_DRIVE_LOG_LEVEL=ERROR \
    PASSWORD_STORE_DIR=/data/private/pass \
    GNUPGHOME=/data/private/gnupg

WORKDIR /app
ENV PYTHONPATH=/app
COPY rootfs/app /app
RUN chmod 0755 /app/run.sh && python3 -m compileall -q /app/proton_backup

ENTRYPOINT ["tini", "--", "/app/run.sh"]
