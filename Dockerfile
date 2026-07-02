# kspect container image.
#
# Usage (audit the host from a container):
#   docker run --rm -v /:/host:ro ghcr.io/5h4rk-lab/kspect scan --root /host
#
# The image is built FROM scratch: kspect is a static, zero-dependency
# binary that only reads files, so there is nothing else to ship — no
# shell, no libc, no package manager, no CVE surface.

# Cross-compile on the build host (BUILDPLATFORM) for the requested
# TARGETARCH instead of emulating the compiler under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
      go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /kspect ./cmd/kspect

FROM scratch
COPY --from=build /kspect /kspect
USER 65534:65534
ENTRYPOINT ["/kspect"]
CMD ["scan", "--root", "/host"]
