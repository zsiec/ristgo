# ristgo

A pure-Go implementation of the **RIST** (Reliable Internet Stream Transport)
protocol, the VSF TR-06 family of technical recommendations.

> **Status: feature-complete, pre-1.0.** The full RIST stack is implemented and
> tested — all three profiles, SMPTE 2022-7 bonding, source adaptation, and a
> pure-Go DTLS transport — and interoperates with libRIST and OpenSSL. The
> public API is small and stable in shape, but no compatibility guarantees are
> made before a tagged 1.0; expect occasional changes.

RIST is the broadcast industry's open standard for reliable, low-latency video
transport over lossy IP networks. ristgo is the sibling of
[srtgo](https://github.com/zsiec/srtgo) (a pure-Go SRT stack by the same author)
and fills a real gap: the reference RIST implementation is the C library
[libRIST](https://code.videolan.org/rist/librist), and there was no native-Go
alternative. ristgo offers a small, io-native `Sender`/`Receiver` API over a
deterministic, sans-I/O protocol core — so the timing-critical parts (ARQ,
reordering, the SMPTE 2022-7 multipath merge, RTT/NACK cadence) are exhaustively
testable on a fake clock — with **zero runtime dependencies beyond the standard
library and `golang.org/x/crypto`**.

## Install

```
go get github.com/zsiec/ristgo
```

Requires Go 1.24+.

## Quick start

`Dial` a sender, `Listen` for a receiver. Both take a `context.Context`
(cancelling it closes the session) and functional options.

Sender — read MPEG-TS from stdin, transmit to a receiver (Simple profile):

```go
tx, err := ristgo.Dial(ctx, "127.0.0.1:5000")
if err != nil {
	log.Fatal(err)
}
defer tx.Close()

buf := make([]byte, 1316) // 7 MPEG-TS cells per RTP packet
for {
	n, err := io.ReadFull(os.Stdin, buf)
	if n > 0 {
		if _, err := tx.Write(buf[:n]); err != nil {
			log.Fatal(err)
		}
	}
	if err != nil {
		break
	}
}
```

Receiver — recover the stream and write it to stdout:

```go
rx, err := ristgo.Listen(ctx, ":5000")
if err != nil {
	log.Fatal(err)
}
defer rx.Close()

buf := make([]byte, 4096)
for {
	n, err := rx.Read(buf)
	if n > 0 {
		os.Stdout.Write(buf[:n])
	}
	if err != nil {
		break
	}
}
```

Runnable versions are in [`examples/sender`](examples/sender),
[`examples/receiver`](examples/receiver), and
[`examples/bonded-sender`](examples/bonded-sender); each accepts a plain
`host:port` or a `rist://host:port?profile=…&secret=…&…` URL.

### Profiles, encryption, bonding

Configure with options (or `WithConfig` for the full [`Config`](https://pkg.go.dev/github.com/zsiec/ristgo#Config)):

```go
// Main profile with PSK encryption:
tx, _ := ristgo.Dial(ctx, "host:5000",
	ristgo.WithProfile(ristgo.ProfileMain),  // GRE tunnel; ProfileAdvanced for TR-06-3
	ristgo.WithSecret("shared-passphrase"),  // PSK AES-CTR
	ristgo.WithAESKeyBits(256))

// DTLS transport security (Main profile) — alternative to a secret:
rx, _ := ristgo.Listen(ctx, ":5000",
	ristgo.WithProfile(ristgo.ProfileMain),
	ristgo.WithDTLS(ristgo.DTLSConfig{PSK: []byte("shared-dtls-key")})) // or CertPEM/KeyPEM + PeerFingerprint

// SMPTE 2022-7 bonding: feed several paths from one source.
bx, _ := ristgo.DialBonded(ctx, []string{"a.example:5000", "b.example:5000"})
```

Prefer a struct? The config-based constructors are still available and take the
same `Config` underneath:

```go
cfg := ristgo.DefaultConfig()
cfg.Profile = ristgo.ProfileMain
cfg.Secret = "shared-passphrase"
tx, _ := ristgo.NewSender("host:5000", cfg) // or ristgo.Dial(ctx, "host:5000", ristgo.WithConfig(cfg))
```

Either form accepts a `rist://host:port?profile=…&secret=…` URL whose query
parameters override the config.

## Features

Everything below is implemented and tested.

| Feature | Profile | Spec |
|---|---|---|
| RTP media + compound RTCP (SR/RR/SDES) | Simple | TR-06-1 |
| ARQ: Range NACK (default) + Bitmask NACK, retransmit via SSRC-LSB toggle | Simple | TR-06-1 / RFC 4585 |
| RTT echo + adaptive NACK-retry timing | Simple | TR-06-1 |
| GRE-over-UDP single-port tunnel | Main | TR-06-2 |
| PSK encryption (AES-CTR, PBKDF2-HMAC-SHA256) | Main / Advanced | TR-06-2 |
| EAP-SRP (SRP-SHA256) authentication | Main | TR-06-2 |
| Null-packet deletion + 32-bit extended-seq NACK | Main | TR-06-2 |
| DTLS 1.2 transport security (pure Go: PSK + ECDHE-ECDSA) | Main | TR-06-2 §6 |
| Advanced header + control messages | Advanced | TR-06-3 |
| AEAD (AES-GCM / ChaCha20-Poly1305) | Advanced | TR-06-3 |
| LZ4 payload compression | Advanced | TR-06-3 |
| SMPTE 2022-7 bonding / seamless multipath reconstruction | all | TR-06-1..3 |
| Source adaptation (Link Quality Messages → encoder-rate callback) | all | TR-06-4 Part 1 |

## Architecture

- **`internal/flow`** — a pure, deterministic state machine for ARQ, reorder,
  dedup, RTT/NACK cadence, and the 2022-7 multipath merge. It never reads a
  clock, opens a socket, or starts a goroutine; time enters only as explicit
  arguments and effects leave as returned values. One profile-agnostic core
  serves every profile and bonding.
- **`internal/session`** (with `socket`/`peer`) — the goroutine host: it owns
  the real clock, the timer wheel, and the I/O, drives `flow`, and performs the
  returned effects on the wire.
- **`internal/wire`** — the narrow waist: the normalized `MediaPacket`/`Feedback`
  types every profile codec encodes and decodes through, so the core only ever
  sees 32-bit sequence numbers.

## Interoperability

- **libRIST** (v0.2.18-rc1) — Simple, Main, and Advanced profiles, both
  directions, clear and encrypted, verified for bit-exact recovery and lossy
  ARQ. See the `//go:build interop` suites (they skip gracefully when the libRIST
  tools are absent).
- **OpenSSL** — the DTLS layer is validated against `openssl s_server`/`s_client
  -dtls1_2` in both roles for both cipher suites (libRIST has no DTLS of its own).

## Testing

Table-driven unit tests; `*_coverage_test.go` edge-hunting; fuzz on `internal/seq`
and every wire codec; a seeded fake-clock N-path network simulator
(`internal/simtest`) asserting the four invariants (no duplicate delivered,
in-order output, nothing past deadline, completeness under recoverable loss);
UDP-loopback e2e with SHA-256 integrity; and libRIST/OpenSSL interop. Everything
runs under `go test -race`. See the `Makefile` (`make test`, `lint`, `bench`,
`check-deps`).

## Documentation

- **[pkg.go.dev/github.com/zsiec/ristgo](https://pkg.go.dev/github.com/zsiec/ristgo)** —
  API reference, the architecture overview, and runnable examples.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — conventions and the test gauntlet.
- **[NOTICE.md](NOTICE.md)** — third-party attributions (pion/rtp, pion/rtcp, LZ4).
- **`docs/spec/`** — the VSF TR-06 PDF set (the protocol source of truth).

## License

MIT — see [LICENSE](LICENSE). Third-party attributions are recorded in
[NOTICE.md](NOTICE.md).
