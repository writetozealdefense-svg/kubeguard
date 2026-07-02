# KubeGuard developer tasks. CI mirrors `make check`.
# golangci-lint is run via `go run` so no system install is required.

GOLANGCI_VERSION := v2.1.6
GOLANGCI := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)

COMPOSE := docker compose

.PHONY: build vet lint test cover check tidy clean up down logs ps rebuild

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

# --- Local Docker stack (see docs/local-docker.md) -------------------------

# Build + start the full stack (postgres + api + web) in the background.
up:
	$(COMPOSE) up --build -d
	@echo "dashboard:  http://localhost:$${WEB_PORT:-8088}  (token: $${KUBEGUARD_ADMIN_TOKEN:-local-admin})"
	@echo "api:        http://localhost:$${API_PORT:-8080}/healthz"

# Stop and remove the stack (keep the Postgres volume).
down:
	$(COMPOSE) down

# Stop and remove the stack AND the Postgres data volume.
rebuild:
	$(COMPOSE) down -v
	$(COMPOSE) up --build -d

logs:
	$(COMPOSE) logs -f

ps:
	$(COMPOSE) ps
