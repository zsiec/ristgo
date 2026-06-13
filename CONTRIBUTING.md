# Contributing to ristgo

ristgo is in early development; expect the internals to move quickly. Before
writing any code, read **[CLAUDE.md](CLAUDE.md)** — it is the project
conventions file (architecture guardrails, style rules, test taxonomy,
authoritative protocol defaults) and is binding for all contributions.

## The gauntlet

Every change must pass all of the following before it is considered done:

```bash
gofmt -l .                                  # must print nothing
go vet ./...
go test -race -count=1 -timeout 120s ./...
go build ./...
make check-deps                             # stdlib + x/crypto only
make check-flow-imports                     # internal/flow import gate
```

Or equivalently:

```bash
make build lint test check-deps check-flow-imports
```

## Ground rules (details in CLAUDE.md)

- Dependencies: Go standard library + `golang.org/x/crypto` only.
- `internal/flow` is sans-I/O and may import only
  `internal/{seq,clock,rtt,wire}` + std — CI enforces this.
- Doc comments on every exported symbol; errors prefixed `"rist: "`;
  table-driven tests; no panics in library code.
- New functionality ships with tests (aim ~2:1 test:source in critical
  internal packages).

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
