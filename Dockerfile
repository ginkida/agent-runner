# ---- Build stage ----
FROM golang:1.23-alpine AS builder

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /agent-runner ./cmd/agent-runner/

# ---- Runtime stage ----
FROM alpine:3.20

RUN apk add --no-cache ca-certificates git bash tini tzdata \
    && addgroup -S agent && adduser -S -G agent -H -s /sbin/nologin agent \
    && mkdir -p /workspace /tmp/agent-runner \
    && chown agent:agent /workspace /tmp/agent-runner

COPY --from=builder /agent-runner /usr/local/bin/agent-runner

LABEL org.opencontainers.image.title="Agent Runner" \
      org.opencontainers.image.description="LLM agent runner for Laravel applications" \
      org.opencontainers.image.source="https://github.com/ginkida/agent-runner" \
      org.opencontainers.image.licenses="MIT"

USER agent
WORKDIR /workspace
EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["wget", "--spider", "-q", "http://localhost:8090/health"]

ENTRYPOINT ["tini", "--", "agent-runner"]
CMD ["--config", "/etc/agent-runner/config.yaml"]
