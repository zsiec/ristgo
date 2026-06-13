# ristgo

A pure Go implementation of the **RIST** (Reliable Internet Stream Transport)
protocol, as specified by the VSF TR-06 family of technical recommendations.

> **Status: early development — not yet usable.** There is no public API yet;
> the repository currently contains scaffolding and planning documents.

RIST is the broadcast industry's open standard for reliable, low-latency video
transport over lossy IP networks. ristgo is the sibling project of
[srtgo](https://github.com/zsiec/srtgo) (a pure-Go SRT stack by the same
author) and fills a real gap: today the only production RIST implementation is
the C library [libRIST](https://code.videolan.org/rist/librist), and there is
no native-Go (or native-Rust) alternative. ristgo aims for a small, io-native
`Sender`/`Receiver` API, a deterministic sans-I/O protocol core that makes the
timing-critical parts (ARQ, reordering, SMPTE 2022-7 multipath merge)
exhaustively testable on a fake clock, zero runtime dependencies beyond the
standard library and `golang.org/x/crypto`, and interoperability validated
against libRIST.

## Documentation

- **[PLAN.md](PLAN.md)** — architecture, wire-format reference, and the phased
  implementation roadmap.
- **[ORCHESTRATION.md](ORCHESTRATION.md)** — current build progress and
  workpackage status.
- **[CLAUDE.md](CLAUDE.md)** — project conventions (style, testing, guardrails).

## Planned features

| Feature | Profile | Spec | Status |
|---|---|---|---|
| RTP media + compound RTCP (SR/RR/SDES) | Simple | TR-06-1 | planned |
| ARQ: Range NACK (default) + Bitmask NACK, retransmit via SSRC LSB toggle | Simple | TR-06-1 / RFC 4585 | planned |
| RTT echo + adaptive NACK retry timing | Simple | TR-06-1 | planned |
| GRE-over-UDP single-port tunnel | Main | TR-06-2 | planned |
| PSK encryption (AES-CTR, PBKDF2-HMAC-SHA256) | Main | TR-06-2 | planned |
| EAP-SRP (SRP-SHA256) authentication | Main | TR-06-2 | planned |
| Null-packet deletion + 32-bit extended-seq NACK | Main | TR-06-2 | planned |
| DTLS transport security (pure Go) | Main | TR-06-2 | planned (later track) |
| Advanced header, AEAD (AES-GCM / ChaCha20-Poly1305) | Advanced | TR-06-3 | planned |
| LZ4 payload compression + per-fragment ARQ | Advanced | TR-06-3 | planned |
| SMPTE 2022-7 bonding / seamless multipath reconstruction | all | TR-06-1..3 | planned |
| Source adaptation (Link Quality Messages → encoder rate) | all | TR-06-4 Part 1 | planned |

## License

MIT — see [LICENSE](LICENSE). Third-party attributions are recorded in
[NOTICE.md](NOTICE.md).
