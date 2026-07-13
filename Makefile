GO ?= go
FUZZTIME ?= 5s
GOVULNCHECK_VERSION ?= v1.6.0
GOSEC_VERSION ?= v2.27.1
GORELEASER_VERSION ?= v2.15.4
VULNDB ?= https://vuln.go.dev
GOSEC_EXCLUDES = G101,G104,G204,G302,G304,G702,G703

.PHONY: all build clean test test-race vet fmt fmt-check cross-build verify \
	fuzz-smoke security snapshot e2e-lima

all: verify build

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/pwnbridge ./cmd/pwnbridge
	ln -sf pwnbridge bin/pb
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o bin/pwnbridge-agent-linux-amd64 ./cmd/pwnbridge-agent

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w cmd internal

fmt-check:
	test -z "$$(gofmt -l cmd internal)"

cross-build:
	mkdir -p bin/cross
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -o bin/cross/pwnbridge-darwin-arm64 ./cmd/pwnbridge
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -trimpath -o bin/cross/pwnbridge-darwin-amd64 ./cmd/pwnbridge
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o bin/cross/pwnbridge-agent-linux-amd64 ./cmd/pwnbridge-agent

verify: fmt-check
	$(GO) mod verify
	$(GO) test ./...
	$(GO) vet ./...
	$(MAKE) cross-build

fuzz-smoke:
	$(GO) test ./internal/config -run '^$$' -fuzz FuzzStrictProjectTOML -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/protocol -run '^$$' -fuzz FuzzDecode -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/shell -run '^$$' -fuzz FuzzMarker -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/syncer -run '^$$' -fuzz FuzzMutagenHealthJSON -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/cli -run '^$$' -fuzz FuzzIgnoreParser -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/workspace -run '^$$' -fuzz FuzzWorkspaceSlug -fuzztime=$(FUZZTIME)

security:
	$(GO) run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -quiet -exclude=$(GOSEC_EXCLUDES) ./...
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) -db $(VULNDB) ./...

snapshot:
	$(GO) run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION) release --snapshot --clean

e2e-lima: build
	: "$${PWNBRIDGE_E2E_SSH_CONFIG:?set PWNBRIDGE_E2E_SSH_CONFIG}"
	test/e2e/lima.sh
	test/e2e/lima-shell.sh
	test/e2e/lima-mosh.sh
	test/e2e/lima-disconnect.sh
	test/e2e/lima-gdb.sh
	test/e2e/lima-gdb-tui.sh
	test/e2e/lima-pwntools-dev.sh
	test/e2e/lima-pwndbg.sh
	test/e2e/lima-container.sh
	test/e2e/lima-container-gdb.sh
	test/e2e/lima-remote-mux.sh
	test/e2e/lima-no-forward.sh
	test/e2e/lima-stop.sh

clean:
	rm -rf bin dist coverage packaging/release/generated
