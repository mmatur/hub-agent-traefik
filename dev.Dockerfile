# syntax=docker/dockerfile:1.2
FROM golang:1-alpine AS delve-builder

RUN apk add --no-cache --no-progress build-base \
    && rm -rf /var/cache/apk/*

RUN go install github.com/go-delve/delve/cmd/dlv@v1.20.1

FROM alpine

RUN apk --no-cache --no-progress add ca-certificates tzdata git libc6-compat \
    && update-ca-certificates \
    && rm -rf /var/cache/apk/*

COPY --from=delve-builder /go/bin/dlv .
COPY hub-agent-traefik .

EXPOSE 80
EXPOSE 40000

ENTRYPOINT ["./dlv", "--listen=:40000", "--headless=true", "--api-version=2", "exec", "--accept-multiclient", "--continue", "--", "./hub-agent-traefik"]
