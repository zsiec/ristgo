# ristgo

A pure-Go implementation of the **RIST** (Reliable Internet Stream Transport)
protocol, the VSF TR-06 family of technical recommendations.

> **Status: feature-complete, pre-1.0.** The full RIST stack is implemented and
> tested, covering all three profiles, SMPTE 2022-7 bonding, SMPTE ST 2022-1 and
> ST 2022-5 FEC, source adaptation, and a pure-Go DTLS transport, and it
> interoperates with libRIST and OpenSSL.
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

### Out-of-band tunnel (Main, Advanced)

`WriteOOB`/`ReadOOB` carry an opaque datagram alongside the media flow, bypassing
ARQ. The payload rides a GRE full frame (protocol type `0x0800`), byte-identical to
libRIST's out-of-band data, so a complete IP packet survives the tunnel intact
(stream IP preservation). `WriteOOBTyped`/`ReadOOBTyped` set and read the GRE
protocol type (an EtherType), so a receiver can dispatch by encapsulated protocol.
The default `OOBProtocolIP` (0x0800) interoperates with libRIST; any other EtherType
tunnels an arbitrary protocol between two ristgo peers (libRIST drops protocol types
it does not recognize).

```go
tx.WriteOOBTyped(0x86DD, ipv6Frame)           // tunnel IPv6 (ristgo to ristgo)
n, proto, _ := rx.ReadOOBTyped(buf)           // dispatch on the protocol tag
// proto == ristgo.OOBProtocolIP for libRIST and default WriteOOB
```

### Forward error correction (SMPTE ST 2022-1 and ST 2022-5)

`WithFEC` adds 2-D (row + column) XOR FEC over the media: the sender emits FEC
packets for each row and column of an L×D matrix, and the receiver recovers any
single loss per row or column with no NACK round trip, complementing ARQ. The
decoder is driven by each FEC packet's own sequence base, so it recovers correctly
even if the first packet of the stream is lost and makes no block-alignment
assumption (it interoperates with a traffic-shaping, non-block-aligned sender).

```go
tx, _ := ristgo.Dial(ctx, "host:5000", ristgo.WithFEC(10, 5)) // 10x5 matrix, ST 2022-1
// ristgo.WithColumnOnlyFEC()    for 1-D column-only (half the overhead)
// ristgo.WithFEC2022_5(20, 10)  for the high-bit-rate ST 2022-5 format
```

FEC works on every profile. The Simple and Main profiles carry standard ST 2022-1
FEC over the RTP payload on two dedicated UDP ports (the media port plus 2 for
column, plus 4 for row), the form that interoperates with any ST 2022-1 receiver.
The Advanced profile instead carries FEC in-band as control messages on the data
port (TR-06-3 §5.3.5), computed over the full encrypted datagram so it composes with
payload fragmentation and PSK encryption. `FECConfig.Carriage` selects between them
when both apply; the default is in-band for Advanced and separate ports otherwise.

`FECConfig.Variant` selects the wire format: ST 2022-1 (the default, L×D ≤ 100) or the
high-bit-rate ST 2022-5 (SMPTE ST 2022-5:2013 §7.3, a 16-bit base and 10-bit matrix
dimensions, L×D ≤ 6000) for interop with ST 2022-5 / ST 2022-6 equipment.
`Stats.FECRecovered` counts packets reconstructed by FEC.

FEC is configured programmatically (`WithFEC` / `WithFEC2022_5`), not through the
`rist://` URL. It composes with link bonding: a bonded sender fans its FEC across
every path, and the receiver recovers a packet lost on every path at once, the
correlated loss SMPTE 2022-7 duplication alone cannot cover.

### Source-adaptive bitrate (TR-06-4 Part 1)

The receiver measures link quality and reports it to the sender, whose AIMD
controller turns sustained loss into an encoder-rate target delivered through a
callback. Use it to back an encoder off a congested link and probe back up when it
clears.

```go
// Receiver: emit Link Quality Messages.
rx, _ := ristgo.Listen(ctx, ":5000", ristgo.WithSourceAdaptation())

// Sender: drive the encoder from the reported quality, within bounds.
tx, _ := ristgo.Dial(ctx, "host:5000",
	ristgo.WithMinBitrate(2000), ristgo.WithMaxBitrate(8000), // kbps
	ristgo.WithRateAdapt(func(targetKbps int) {
		encoder.SetBitrate(targetKbps) // your encoder
	}))
```

### IP multicast

A multicast group address makes the receiver join the group and the sender egress
to it (the standard library's `net.UDPConn` cannot, so this uses `golang.org/x/net`).
Set the hop limit for routed delivery, the egress/join interface, or source-specific
multicast (SSM) via `Config`.

```go
rx, _ := ristgo.Listen(ctx, "239.1.2.3:5004") // auto-joins the group
// Receiver Config options: MulticastSource (source-specific multicast),
// Interface (the join interface).

cfg := ristgo.DefaultConfig()
cfg.MulticastTTL = 16 // routed delivery (default 1 = local link only)
tx, _ := ristgo.NewSender("239.1.2.3:5004", cfg)
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
| Any-protocol encapsulation: typed GRE tunnel by EtherType (WriteOOBTyped/ReadOOBTyped) | Main, Advanced | libRIST GRE |
| DTLS 1.2 transport security (pure Go: PSK + ECDHE-ECDSA) | Main | TR-06-2 §6 |
| Advanced header + control messages | Advanced | TR-06-3 |
| AEAD (AES-GCM, ChaCha20-Poly1305) | Advanced | TR-06-3 |
| LZ4 payload compression | Advanced | TR-06-3 |
| Payload fragmentation and reassembly (per-fragment ARQ) | Advanced | TR-06-3 |
| Stream multiplexing (MultiReceiver: N flows demultiplexed per port) | all | TR-06-1..3 |
| SMPTE 2022-7 bonding, seamless multipath reconstruction | all | TR-06-1..3 |
| Weighted load-share bonding (per-path weights, runtime SetWeight) | all | libRIST weight |
| Forward error correction (SMPTE ST 2022-1 and ST 2022-5, 2-D XOR; separate-port + Advanced in-band carriage) | all | TR-06-2 §8.4, TR-06-3 §5.3.5 |
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
