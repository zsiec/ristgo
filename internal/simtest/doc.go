// Package simtest provides deterministic network-simulator primitives for
// driving the sans-I/O flow core in tests: a seeded PRNG, an impairment
// Link, and a declarative TimerWheel. They are a Go port of srtrust's
// simulator module (crates/srt-protocol/tests/sim/mod.rs), extended with
// per-datagram duplication (DupProb) for SMPTE 2022-7 work.
//
// Each piece is independently correct and reproducible from a seed, driven
// by an explicit fake clock (clock.Timestamp):
//
//   - Rng — a tiny SplitMix64 PRNG, so the simulator needs no external
//     randomness and its loss/jitter/duplication decisions replay
//     identically from a seed.
//   - Link — one directional link applying an optional deterministic drop
//     filter, independent per-datagram loss, duplication, and base delay
//     plus uniform jitter (which can reorder), scheduling deliveries on
//     the fake clock.
//   - TimerWheel — the I/O side of the core's declarative timers: it obeys
//     SetTimer/ClearTimer effects and reports the earliest deadline.
//
// These compose into the N-path Fabric (built once internal/flow exists),
// where stepping jumps the fake clock to the next deadline across every
// link and wheel — zero sleeps, zero sockets, zero flake. This package must
// never open a socket or sleep; it does not import the time package at all.
package simtest
