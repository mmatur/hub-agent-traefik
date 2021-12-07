# syntax=docker/dockerfile:1.2
FROM alpine

RUN apk --no-cache --no-progress add ca-certificates tzdata git \
    && update-ca-certificates \
    && rm -rf /var/cache/apk/*

COPY neo-agent .

ENTRYPOINT ["/neo-agent"]
EXPOSE 80

# Metadata
LABEL org.opencontainers.image.source="https://github.com/traefik/neo-agent" \
    org.opencontainers.image.vendor="Traefik Labs" \
    org.opencontainers.image.url="https://traefik.io" \
    org.opencontainers.image.title="Traefik Hub" \
    org.opencontainers.image.description="The Global Networking Platform" \
    org.opencontainers.image.version="$VERSION" \
    org.opencontainers.image.documentation="https://hub.traefik.io/documentation"
