# KubeGuard developer tasks. CI mirrors `make check`.
# golangci-lint is run via `go run` so no system install is required.

GOLANGCI_VERSION := v2.1.6
GOLANGCI := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)

.PHONY: build vet lint test cover check tidy clean

build:
	go build ./...

vet:
	go vet ./...

lint:
	$(GOLANGCI) run

test:
	go test ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

# The squad acceptance gate: build + vet + lint + test must all be clean.
check: build vet lint test

tidy:
	go mod tidy

clean:
	rm -rf dist bin coverage.out
