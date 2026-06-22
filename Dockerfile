# syntax=docker/dockerfile:1
#
# Multi-stage build for the AgentFence proxy (issue #149).
#
# Stage 1 builds a fully static binary with the Go toolchain; stage 2 copies it
# onto a distroless static base that ships no shell or package manager, runs as
# a non-root user, and contains only CA certificates and the binary. The result
# is small and minimal-attack-surface, suitable for `agentfence proxy-http` as a
# sidecar or standalone container.
#
# Build (version-stamped to match the Makefile / .goreleaser.yml):
#   docker build --build-arg VERSION=$(git describe --tags --always) -t agentfence .
#
# Run the HTTP proxy with a mounted policy and an audit-log volume:
#   docker run --rm -p 8787:8787 \
#     -v "$PWD/policy.yaml:/policy/policy.yaml:ro" \
#     -v "$PWD/audit:/audit" \
#     agentfence proxy-http --upstream http://upstream:9000 \
#       --policy /policy/policy.yaml --listen 0.0.0.0:8787 \
#       --audit-log /audit/audit.jsonl
#
# Security note: bind the HTTP proxy to a trusted network and terminate TLS at a
# trusted layer — see docs/threat-model.md (streamable-HTTP proxy surface).

FROM golang:1.22-alpine AS build

# Version stamped into the binary via -ldflags, matching the Makefile LDFLAGS.
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

WORKDIR /src

# Cache module downloads independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 produces a static binary that runs on a scratch/distroless base.
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.Version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /out/agentfence ./cmd/agentfence

# Distroless static: no shell, no package manager, non-root by default.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="agentfence" \
      org.opencontainers.image.description="Local-first policy firewall for MCP tool calls" \
      org.opencontainers.image.source="https://github.com/dgenio/agentfence" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/agentfence /usr/local/bin/agentfence

# Run as the distroless non-root user (uid 65532).
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/agentfence"]
CMD ["--help"]
