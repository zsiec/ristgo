# Contributing to ristgo

ristgo is a pure-Go RIST implementation. Contributions are welcome; the
conventions below — architecture guardrails, style, and test discipline — are
binding for all changes. See the [package documentation](https://pkg.go.dev/github.com/zsiec/ristgo)
for the API and design overview.

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

## Ground rules

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
