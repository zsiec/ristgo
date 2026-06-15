# ristgo

A pure-Go implementation of the **RIST** (Reliable Internet Stream Transport)
protocol, the VSF TR-06 family of technical recommendations.

> **Status: feature-complete, pre-1.0.** The full RIST stack is implemented and
> tested, covering all three profiles, SMPTE 2022-7 bonding, source adaptation,
> and a pure-Go DTLS transport, and it interoperates with libRIST and OpenSSL.
> The public API is small and stable in shape. No compatibility guarantees are
> made before a tagged 1.0, so expect occasional changes.

RIST is an open standard for reliable, low-latency transport of live media over
lossy IP networks. The reference implementation is the C library
[libRIST](https://code.videolan.org/rist/librist); ristgo is a native-Go
alternative that targets the same wire format. It exposes a small, io-native
`Sender`/`Receiver` API over a deterministic, sans-I/O protocol core, so the
timing-critical parts (ARQ, reordering, the SMPTE 2022-7 multipath merge, RTT
and NACK cadence) are testable on a fake clock.

The dependency set beyond the standard library is the Go team's
`golang.org/x/crypto` and `golang.org/x/net` (the latter for IP multicast: group
membership, multicast TTL, and interface selection, which the standard library
does not expose). There are no third-party or pion dependencies.

## Install

```
go get github.com/zsiec/ristgo
```

Requires Go 1.24+.

## Quick start

`Dial` a sender, `Listen` for a receiver. Both take a `context.Context`
(cancelling it closes the session) and functional options.

Sender, reading MPEG-TS from stdin and transmitting to a receiver (Simple
profile):

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

Receiver, recovering the stream and writing it to stdout:

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
[`examples/bonded-sender`](examples/bonded-sender). Each accepts a plain
`host:port` or a `rist://host:port?profile=...&secret=...&...` URL.

### Profiles, encryption, bonding

Configure with options (or `WithConfig` for the full [`Config`](https://pkg.go.dev/github.com/zsiec/ristgo#Config)):

```go
// Main profile with PSK encryption:
tx, _ := ristgo.Dial(ctx, "host:5000",
	ristgo.WithProfile(ristgo.ProfileMain), // GRE tunnel; ProfileAdvanced for TR-06-3
	ristgo.WithSecret("shared-passphrase"), // PSK AES-CTR
	ristgo.WithAESKeyBits(256))

// DTLS transport security (Main profile), an alternative to a secret:
rx, _ := ristgo.Listen(ctx, ":5000",
	ristgo.WithProfile(ristgo.ProfileMain),
	ristgo.WithDTLS(ristgo.DTLSConfig{PSK: []byte("shared-dtls-key")})) // or CertPEM/KeyPEM + PeerFingerprint

// SMPTE 2022-7 bonding: feed several paths from one source (full duplication).
bx, _ := ristgo.DialBonded(ctx, []string{"a.example:5000", "b.example:5000"})

// Weighted load-share: split the stream across paths instead of duplicating it.
// Per-path weights (0 keeps a path on full 2022-7 duplication), or a uniform
// weight via WithWeight for an even split. Change a weight at runtime with
// bx.SetWeight(path, weight).
lb, _ := ristgo.NewBondedSenderPeers([]ristgo.BondedPeer{
	{Addr: "a.example:5000", Weight: 3}, // ~75% of the packets
	{Addr: "b.example:5000", Weight: 1}, // ~25%
}, ristgo.DefaultConfig())
```

Prefer a struct? The config-based constructors are still available and take the
same `Config` underneath:

```go
cfg := ristgo.DefaultConfig()
cfg.Profile = ristgo.ProfileMain
cfg.Secret = "shared-passphrase"
tx, _ := ristgo.NewSender("host:5000", cfg) // or ristgo.Dial(ctx, "host:5000", ristgo.WithConfig(cfg))
```

Either form accepts a `rist://host:port?profile=...&secret=...` URL whose query
parameters override the config.

### Connection roles

By default `Dial` creates a `Sender` (it connects out) and `Listen` creates a
`Receiver` (it binds and waits). The protocol role can be decoupled from the
connection direction:

- `DialReceiver` / `ListenSender`: a `Receiver` that connects out to a listening
  sender (pull mode), or a `Sender` that binds and waits for a receiver to
  connect. The config-based forms are `NewReceiverCaller` and
  `NewListenerSender`.
- `NewOneWaySender` / `NewOneWayReceiver`: one-way transport with no return
  channel. The sender retains no retransmit history and emits no RTCP; the
  receiver emits no RTCP and requests no retransmissions. An unrecoverable gap is
  skipped at playout rather than recovered. Use this for satellite, broadcast, or
  strictly asymmetric paths.

### Stream multiplexing (several flows on one port)

A `MultiReceiver` binds one port and demultiplexes the several media flows that
arrive on it into independent `Receiver`s, one per flow. Call `Accept` in a loop:

```go
mrx, _ := ristgo.NewMultiReceiver(":5000", cfg)
for {
	rx, err := mrx.Accept() // blocks until a new flow appears
	if err != nil {
		break
	}
	go handle(rx) // rx is a Receiver for one flow, with its own Stats and SSRC
}
```

Each flow has independent ARQ recovery and delivery. The Simple profile
demultiplexes by RTP SSRC; the Main and Advanced profiles (cleartext or PSK)
demultiplex by source address, matching libRIST's per-flow model. Proven
interoperable with libRIST (several `ristsender` instances into one
`MultiReceiver`).

### Large payloads (Advanced profile)

`WithFragmentSize` splits a `Write` larger than the configured size into
fragments, each an independently recoverable sequence, reassembled by the
receiver. This raises the per-`Write` limit above `MaxMediaPayload` and composes
with bonding. libRIST does not implement fragmentation or reassembly, so this is
a ristgo to ristgo capability.

```go
tx, _ := ristgo.Dial(ctx, "host:5000",
	ristgo.WithProfile(ristgo.ProfileAdvanced),
	ristgo.WithFragmentSize(1316))
```

## Features

Everything below is implemented and tested.

| Feature | Profile | Spec |
|---|---|---|
| RTP media + compound RTCP (SR/RR/SDES) | Simple | TR-06-1 |
| ARQ: Range NACK (default) + Bitmask NACK, retransmit via SSRC-LSB toggle | Simple | TR-06-1, RFC 4585 |
| RTT echo + adaptive NACK-retry timing | Simple | TR-06-1 |
| GRE-over-UDP single-port tunnel | Main | TR-06-2 |
| PSK encryption (AES-CTR, PBKDF2-HMAC-SHA256) | Main, Advanced | TR-06-2 |
| EAP-SRP (SRP-SHA256) authentication and key-as-passphrase keying | Main | TR-06-2 |
| Null-packet deletion + 32-bit extended-seq NACK | Main | TR-06-2 |
| Out-of-band side channel, full-IP passthrough / stream IP preservation (WriteOOB/ReadOOB) | Main, Advanced | TR-06-2 |
| DTLS 1.2 transport security (pure Go: PSK + ECDHE-ECDSA) | Main | TR-06-2 §6 |
| Advanced header + control messages | Advanced | TR-06-3 |
| AEAD (AES-GCM, ChaCha20-Poly1305) | Advanced | TR-06-3 |
| LZ4 payload compression | Advanced | TR-06-3 |
| Payload fragmentation and reassembly (per-fragment ARQ) | Advanced | TR-06-3 |
| Stream multiplexing (MultiReceiver: N flows demultiplexed per port) | all | TR-06-1..3 |
| SMPTE 2022-7 bonding, seamless multipath reconstruction | all | TR-06-1..3 |
| Weighted load-share bonding (per-path weights, runtime SetWeight) | all | libRIST weight |
| Source adaptation (Link Quality Messages, encoder-rate callback) | all | TR-06-4 Part 1 |
| IP multicast (group membership, multicast TTL, egress interface, source filter) | all | n/a |
| Reversed-role transport (caller-receive, listener-send) | all | n/a |
| One-way / no-return-channel transport | all | n/a |

## Architecture

The stack is three layers around a narrow waist.

- **`internal/flow`**: a pure, deterministic state machine for ARQ, reorder,
  dedup, RTT and NACK cadence, and the 2022-7 multipath merge. It never reads a
  clock, opens a socket, or starts a goroutine; time enters only as explicit
  arguments and effects leave as returned values. One profile-agnostic core
  serves every profile and bonding.
- **`internal/session`** (with `socket` and `peer`): the goroutine host. It owns
  the real clock, the timer wheel, and the I/O, drives `flow`, and performs the
  returned effects on the wire.
- **`internal/wire`**: the narrow waist. The normalized `MediaPacket` and
  `Feedback` types every profile codec encodes and decodes through, so the core
  only ever sees 32-bit sequence numbers.

## Interoperability

- **libRIST** (v0.2.18-rc1): Simple, Main, and Advanced profiles, both
  directions, clear and encrypted, verified for bit-exact recovery and lossy
  ARQ. See the `//go:build interop` suites, which skip gracefully when the
  libRIST tools are absent.
- **OpenSSL**: the DTLS layer is validated against `openssl s_server`/`s_client
  -dtls1_2` in both roles for both cipher suites (libRIST has no DTLS of its
  own).

## Testing

Table-driven unit tests, `*_coverage_test.go` edge-hunting, fuzz on
`internal/seq` and every wire codec, a seeded fake-clock N-path network
simulator (`internal/simtest`) asserting the four invariants (no duplicate
delivered, in-order output, nothing past deadline, completeness under
recoverable loss), UDP-loopback e2e with SHA-256 integrity, and libRIST and
OpenSSL interop. Everything runs under `go test -race`. See the `Makefile`
(`make test`, `lint`, `bench`, `check-deps`).

## Documentation

- **[pkg.go.dev/github.com/zsiec/ristgo](https://pkg.go.dev/github.com/zsiec/ristgo)**:
  API reference, the architecture overview, and runnable examples.
- **[CONTRIBUTING.md](CONTRIBUTING.md)**: conventions and the test gauntlet.
- **[NOTICE.md](NOTICE.md)**: third-party attributions (pion/rtp, pion/rtcp, LZ4).
- **`docs/spec/`**: the VSF TR-06 PDF set (the protocol source of truth).

## License

MIT, see [LICENSE](LICENSE). Third-party attributions are recorded in
[NOTICE.md](NOTICE.md).
