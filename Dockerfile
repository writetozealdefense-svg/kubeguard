# KubeGuard dashboard / engine image — multi-stage, distroless, non-root.
# The same binary serves the API ("dashboard") and the worker (add
# --async-workers). Build multi-arch with buildx:
#   docker buildx build --platform linux/amd64,linux/arm64 -t kubeguard:dev .
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/kubeguard ./cmd/kubeguard

# Distroless static — no shell, no package manager, runs as nonroot.
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/kubeguard /usr/local/bin/kubeguard
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/kubeguard"]
CMD ["dashboard", "--help"]
