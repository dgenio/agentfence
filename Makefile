# AgentFence developer Makefile.
# Single source of truth for build, test, lint, and release-check commands.
# CI (.github/workflows/ci.yml) calls `make ci`; contributors should run the
# same target locally before pushing.

GO         ?= go
BINARY     ?= agentfence
PKG        ?= ./cmd/agentfence
COVERAGE   ?= coverage.out
VERSION    ?= dev
LDFLAGS    ?= -X main.Version=$(VERSION)

FUZZTIME   ?= 30s

# Static-analysis / security tooling (#110, #177). Overridable so CI or a
# contributor can point at a pinned binary. Install hints are in CONTRIBUTING.md.
GOLANGCI    ?= golangci-lint
GOSEC       ?= gosec
GOVULNCHECK ?= govulncheck

.PHONY: all build test test-race vet fmt fmt-check lint golangci sec vuln examples doc-check demo ci cover release-check clean help fuzz completions man docker

# Container image coordinates (issues #104/#149).
IMAGE      ?= ghcr.io/dgenio/agentfence
IMAGE_TAG  ?= $(VERSION)

all: ci

## help: List available targets.
help:
	@echo "Targets:"
	@echo "  build         Build the agentfence binary (output: ./$(BINARY))."
	@echo "  test          Run unit tests."
	@echo "  test-race     Run unit tests with the race detector and write $(COVERAGE)."
	@echo "  vet           Run go vet on all packages."
	@echo "  fmt           Format all Go files in place with gofmt."
	@echo "  fmt-check     Fail if any Go files need formatting (used in CI)."
	@echo "  lint          Run fmt-check, vet, golangci-lint, and gosec."
	@echo "  golangci      Run golangci-lint ($(GOLANGCI))."
	@echo "  sec           Run gosec security analysis ($(GOSEC))."
	@echo "  vuln          Run govulncheck dependency vulnerability scan ($(GOVULNCHECK))."
	@echo "  examples      Build and validate every file under examples/."
	@echo "  doc-check     Verify documented commands exist and doc links resolve."
	@echo "  demo          Build and run 'agentfence demo'."
	@echo "  ci            Run the full pre-push gate: fmt-check, vet, test-race."
	@echo "  cover         Run test-race and open an HTML coverage report."
	@echo "  fuzz          Run each fuzz target for FUZZTIME (default $(FUZZTIME))."
	@echo "  completions   Generate bash/zsh/fish completions into ./completions."
	@echo "  man           Generate the agentfence(1) man page into ./manpages."
	@echo "  docker        Build the container image ($(IMAGE):$(IMAGE_TAG))."
	@echo "  release-check Validate .goreleaser.yml (requires 'goreleaser' on PATH)."
	@echo "  clean         Remove built artifacts."

## build: Build the agentfence binary.
build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

## test: Run all unit tests (no race detector).
test:
	$(GO) test ./...

## test-race: Run all unit tests with -race and write coverage to $(COVERAGE).
test-race:
	$(GO) test -race -coverprofile=$(COVERAGE) ./...
	$(GO) tool cover -func=$(COVERAGE) | tail -n 1

## vet: Run go vet on all packages.
vet:
	$(GO) vet ./...

## fmt: Apply gofmt formatting in place.
fmt:
	gofmt -w .

## fmt-check: Fail if any Go file would be reformatted by gofmt.
fmt-check:
	@out=$$(gofmt -l . | grep -v '^vendor/' || true); \
	if [ -n "$$out" ]; then \
		echo "gofmt: the following files need formatting:"; \
		echo "$$out"; \
		exit 1; \
	fi

## lint: Run fmt-check, vet, golangci-lint, and gosec (the full static gate).
##       golangci-lint and gosec must be on PATH (see CONTRIBUTING.md).
lint: fmt-check vet golangci sec

## golangci: Run golangci-lint with the committed .golangci.yml config.
golangci:
	$(GOLANGCI) run ./...

## sec: Run gosec security analysis. Intentional findings are annotated inline
##      with `// #nosec <rule> -- <reason>`; new findings fail.
sec:
	$(GOSEC) -quiet ./...

## vuln: Run govulncheck against the module's dependencies.
vuln:
	$(GOVULNCHECK) ./...

## examples: Build the binary and validate every file under examples/ (#181).
examples: build
	AGENTFENCE=./$(BINARY) bash scripts/check-examples.sh

## doc-check: Verify documented commands exist and internal doc links resolve (#165).
doc-check: build
	python3 scripts/check-doc-claims.py --binary ./$(BINARY)

## demo: Build the binary and run the demo command.
demo: build
	./$(BINARY) demo

## ci: Run the full pre-push gate: fmt-check, vet, test-race.
ci: fmt-check vet test-race

## cover: Run tests with coverage and open an HTML report.
cover: test-race
	$(GO) tool cover -html=$(COVERAGE)

## fuzz: Run every Go fuzz target sequentially for FUZZTIME each (default 30s).
##       Set FUZZTIME=2s for a quick smoke run; longer values (e.g. 5m) for
##       overnight runs. Go's native fuzzer only fuzzes one target per
##       invocation, so we iterate explicitly.
fuzz:
	$(GO) test -run=- -fuzz=FuzzParsePolicy   -fuzztime=$(FUZZTIME) ./internal/policy
	$(GO) test -run=- -fuzz=FuzzParseToolCall -fuzztime=$(FUZZTIME) ./internal/policy
	$(GO) test -run=- -fuzz=FuzzMatchesGlob   -fuzztime=$(FUZZTIME) ./internal/engine
	$(GO) test -run=- -fuzz=FuzzRedactArguments -fuzztime=$(FUZZTIME) ./internal/redact

## completions: Generate shell completion scripts from the CLI into ./completions.
completions:
	@mkdir -p completions
	$(GO) run $(PKG) completion bash > completions/$(BINARY).bash
	$(GO) run $(PKG) completion zsh  > completions/$(BINARY).zsh
	$(GO) run $(PKG) completion fish > completions/$(BINARY).fish

## man: Generate the agentfence(1) man page from the CLI into ./manpages.
man:
	@mkdir -p manpages
	$(GO) run $(PKG) man > manpages/$(BINARY).1

## docker: Build the container image from the source Dockerfile.
docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		-t $(IMAGE):$(IMAGE_TAG) .

## release-check: Validate .goreleaser.yml without producing a release.
release-check:
	goreleaser check

## clean: Remove built binaries, coverage, and generated artifacts.
clean:
	rm -f $(BINARY) $(COVERAGE)
	rm -rf completions manpages
