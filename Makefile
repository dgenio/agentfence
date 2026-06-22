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

.PHONY: all build test test-race vet fmt fmt-check lint demo ci cover release-check clean help fuzz completions man docker

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
	@echo "  lint          Run vet + fmt-check."
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

## lint: Run vet and fmt-check.
lint: vet fmt-check

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
