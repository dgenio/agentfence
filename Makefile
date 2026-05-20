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

.PHONY: all build test test-race vet fmt fmt-check lint demo ci cover release-check clean help

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

## release-check: Validate .goreleaser.yml without producing a release.
release-check:
	goreleaser check

## clean: Remove built binaries and coverage artifacts.
clean:
	rm -f $(BINARY) $(COVERAGE)
