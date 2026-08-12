# syntax=docker/dockerfile:1

# --- web build -------------------------------------------------------------
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# --- go build --------------------------------------------------------------
# Must satisfy the `go` directive in go.mod: the official images set
# GOTOOLCHAIN=local, so a lower base image fails the build instead of
# downloading a newer toolchain. CI builds this image on every push to catch
# a drift between the two.
FROM golang:1.25-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Bring in the built dashboard so go:embed (embedui tag) can bake it in.
COPY --from=web /web/dist ./web/dist

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -tags embedui \
    -ldflags "-s -w \
      -X github.com/julianhintermann-cmd/skopos/internal/version.Version=${VERSION} \
      -X github.com/julianhintermann-cmd/skopos/internal/version.Commit=${COMMIT} \
      -X github.com/julianhintermann-cmd/skopos/internal/version.Date=${DATE}" \
    -o /out/skopos ./cmd/skopos

# --- runtime ---------------------------------------------------------------
# distroless static: no shell, no package manager, minimal attack surface. The
# process runs as root *inside the container*, but the container is granted
# only NET_ADMIN + NET_RAW (see deploy/docker-compose.yml and SECURITY.md) —
# every other capability is dropped, so this root is confined to packet
# capture and firewall management.
FROM gcr.io/distroless/static-debian12:latest

COPY --from=build /out/skopos /skopos

# Config, hot data and cold archive are provided as volume mounts.
ENV SKOPOS_CONFIG=/config/config.yaml
EXPOSE 8686

# HEALTHCHECK uses the shell-free `skopos health` subcommand.
HEALTHCHECK --interval=30s --timeout=6s --start-period=15s --retries=3 \
    CMD ["/skopos", "health"]

ENTRYPOINT ["/skopos"]
CMD ["serve"]
