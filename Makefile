# go-ipsec — build, test and live-interop targets.
#
# Offline targets need only the Go toolchain. The `e2e*` targets stand up a
# local strongSwan IKEv2-EAP-MSCHAPv2 server in Docker (test/strongswan/) and
# run the build-tagged live tests against it.

GO      ?= go
PKG     := ./...
COMPOSE := docker compose -f test/strongswan/docker-compose.yml

# Live e2e configuration — defaults match test/strongswan/{ipsec.secrets,ipsec.conf}.
# Override on the command line, e.g. `make e2e IPSEC_EAP_PASS=secret`.
IPSEC_SERVER    ?= 127.0.0.1:500
IPSEC_EAP_USER  ?= testuser
IPSEC_EAP_PASS  ?= testpass
IPSEC_REMOTE_ID ?= vpn.example.com
# Pre-shared key for the PSK live test; matches the `rw-psk` conn secret in
# test/strongswan/ipsec.secrets.
IPSEC_PSK       ?= test-preshared-key
# Exported by the strongSwan container's entrypoint on startup (see e2e-up).
IPSEC_CA        := $(abspath test/strongswan/pki/caCert.pem)
PKI_DIR         := test/strongswan/pki

E2E_ENV = IPSEC_SERVER=$(IPSEC_SERVER) IPSEC_EAP_USER=$(IPSEC_EAP_USER) \
          IPSEC_EAP_PASS=$(IPSEC_EAP_PASS) IPSEC_REMOTE_ID=$(IPSEC_REMOTE_ID) \
          IPSEC_CA=$(IPSEC_CA) IPSEC_PSK=$(IPSEC_PSK)

.DEFAULT_GOAL := help

.PHONY: help build bin fmt fmt-check vet test test-race cover tidy \
        e2e e2e-up e2e-down e2e-test clean

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

## --- build ---

build: ## Compile every package
	$(GO) build $(PKG)

bin: ## Build the ipsec2socks CLI into bin/
	$(GO) build -o bin/ipsec2socks ./cmd/ipsec2socks

## --- quality ---

fmt: ## Format the code in place
	gofmt -w .

fmt-check: ## Fail if any file is not gofmt-clean
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet: ## go vet (including the build-tagged e2e package)
	$(GO) vet $(PKG)
	$(GO) vet -tags e2e_server ./test/integration/

tidy: ## Tidy go.mod/go.sum
	$(GO) mod tidy

## --- offline tests ---

test: ## Run the offline test suite
	$(GO) test -count=1 $(PKG)

test-race: ## Run the offline test suite under -race
	$(GO) test -race -count=1 $(PKG)

cover: ## Offline tests with a coverage summary
	$(GO) test -count=1 -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -func=coverage.out | tail -1

## --- live e2e (Docker strongSwan) ---
# The container's entrypoint generates the CA + server cert on startup and
# exports the CA to $(PKI_DIR)/caCert.pem — no separate cert step.

e2e-up: ## Build & start the strongSwan server, wait until ready
	@mkdir -p $(PKI_DIR)
	$(COMPOSE) up -d --build
	@echo "waiting for strongSwan to start..."; \
	for i in $$(seq 1 30); do \
		if $(COMPOSE) exec -T vpn ipsec status >/dev/null 2>&1 && [ -f $(IPSEC_CA) ]; then \
			echo "server ready"; exit 0; fi; \
		sleep 1; \
	done; echo "timed out waiting for strongSwan"; $(COMPOSE) logs | tail -20; exit 1

e2e-down: ## Stop and remove the strongSwan server
	$(COMPOSE) down

e2e-test: ## Run the live tests (assumes the server is already up)
	$(E2E_ENV) $(GO) test -tags e2e_server -count=1 -v ./test/integration

e2e: ## Full live run: start server, run live tests, always tear down
	@status=0; \
	$(MAKE) e2e-up || { $(MAKE) e2e-down; exit 1; }; \
	$(MAKE) e2e-test || status=$$?; \
	$(MAKE) e2e-down; \
	exit $$status

## --- misc ---

clean: ## Remove build/test artifacts and the exported test CA
	rm -rf bin coverage.out $(PKI_DIR)
	$(GO) clean -testcache
