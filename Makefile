# ristgo — pure-Go RIST (VSF TR-06). Project conventions live in CLAUDE.md.
#
# Targets are guarded so they work both before any Go packages exist (early
# scaffolding: `go vet`/`go test` exit non-zero on a module with no packages)
# and after the internal/ tree lands.

GO ?= go
MODULE := github.com/zsiec/ristgo

.PHONY: test lint bench build check-deps check-flow-imports interop

test:
	@if [ -z "$$($(GO) list ./... 2>/dev/null)" ]; then \
		echo "test: no Go packages yet — skipping"; \
	else \
		echo "$(GO) test -race -count=1 -timeout 120s ./..."; \
		$(GO) test -race -count=1 -timeout 120s ./...; \
	fi

lint:
	@fmt=$$(gofmt -l .); \
	if [ -n "$$fmt" ]; then \
		echo "lint: gofmt required for:"; echo "$$fmt"; exit 1; \
	fi
	@if [ -z "$$($(GO) list ./... 2>/dev/null)" ]; then \
		echo "lint: gofmt clean; no Go packages yet — skipping go vet"; \
	else \
		echo "$(GO) vet ./..."; \
		$(GO) vet ./...; \
	fi

bench:
	@if [ -z "$$($(GO) list ./... 2>/dev/null)" ]; then \
		echo "bench: no Go packages yet — skipping"; \
	else \
		echo "$(GO) test -bench=. -benchmem ./..."; \
		$(GO) test -bench=. -benchmem ./...; \
	fi

build:
	$(GO) build ./...

# interop: run the libRIST reference-tool interop suite (Simple profile, 4
# role/direction combos behind //go:build interop). Requires the libRIST CLI
# tools — set RISTGO_LIBRIST_TOOLS to their directory, or build them with
# `meson setup build && ninja -C build` in ~/dev/librist (the suite t.Skips
# gracefully when the tools are absent, e.g. in CI).
interop:
	$(GO) test -tags interop -run TestInterop -v -count=1 -timeout 300s ./...

# check-deps: the module dependency graph may contain only this module,
# golang.org/x/crypto, and the Go standard library. (PLAN.md: deps rule.)
# golang.org/x/sys is allowed solely as a transitive dependency of x/crypto:
# x/crypto/chacha20poly1305 -> chacha20 imports x/sys/cpu for CPU-feature
# detection on amd64 (it does not appear on arm64). It is not a dependency we
# choose directly, and stays within the x/crypto family.
check-deps:
	@out=$$($(GO) list -deps -f '{{if and (not .Standard) .Module}}{{.Module.Path}}{{end}}' ./... 2>/dev/null) \
		|| { echo "check-deps: FAIL — go list -deps ./... failed"; exit 1; }; \
	bad=$$(printf '%s\n' "$$out" | grep . | sort -u \
		| grep -v -x -e '$(MODULE)' -e 'golang.org/x/crypto' -e 'golang.org/x/sys' || true); \
	if [ -n "$$bad" ]; then \
		echo "check-deps: FAIL — forbidden module dependencies:"; \
		echo "$$bad"; \
		exit 1; \
	fi; \
	echo "check-deps: OK (std + $(MODULE) + golang.org/x/crypto [+ x/sys via x/crypto] only)"

# check-flow-imports: the deterministic core internal/flow may depend only on
# internal/{seq,clock,rtt,wire} and the standard library. (PLAN.md: hard
# guardrail — keeps the core profile-agnostic and deterministic forever.)
check-flow-imports:
	@if [ ! -d internal/flow ]; then \
		echo "check-flow-imports: SKIP — internal/flow does not exist yet"; \
		exit 0; \
	fi; \
	deps=$$($(GO) list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./internal/flow) \
		|| { echo "check-flow-imports: FAIL — go list -deps ./internal/flow failed"; exit 1; }; \
	bad=$$(printf '%s\n' "$$deps" | grep . \
		| grep -v -x \
			-e '$(MODULE)/internal/flow' \
			-e '$(MODULE)/internal/seq' \
			-e '$(MODULE)/internal/clock' \
			-e '$(MODULE)/internal/rtt' \
			-e '$(MODULE)/internal/wire' || true); \
	if [ -n "$$bad" ]; then \
		echo "check-flow-imports: FAIL — internal/flow may import only internal/{seq,clock,rtt,wire} + std, but depends on:"; \
		echo "$$bad"; \
		exit 1; \
	fi; \
	echo "check-flow-imports: OK (internal/flow imports only internal/{seq,clock,rtt,wire} + std)"
