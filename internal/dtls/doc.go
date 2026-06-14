// Package dtls implements a minimal, pure-Go DTLS 1.2 (RFC 6347) transport for
// the RIST Main profile's optional transport security (VSF TR-06-2 §6). It is
// the pure-Go fill for the transport-security seam: the host can wrap the
// Main-profile UDP datagram flow (GRE-framed media + RTCP) in DTLS records,
// protecting the whole tunnel rather than only the GRE payload (as PSK-AES-CTR
// does).
//
// # Interop status — read this first
//
// libRIST v0.2.18-rc1 does NOT implement DTLS (its README lists it as planned;
// its only Main-profile security is EAP-SRP + PSK-AES-CTR, which ristgo already
// ships). There is therefore NO libRIST interop oracle for this code. Instead it
// is validated three ways:
//
//   - Self-interop: a ristgo client and ristgo server complete the handshake and
//     exchange protected application data over an in-memory pipe (conn_test.go),
//     for both cipher suites.
//   - External interop: against the OpenSSL DTLS CLI (`openssl s_server/s_client
//     -dtls1_2`), behind //go:build interop with a graceful skip when openssl is
//     absent (interop_test.go) — a real, independent DTLS 1.2 implementation.
//   - Known-answer tests: the TLS 1.2 PRF (RFC 5246 §5) and the AES-128-GCM
//     record AEAD against published vectors (prf_test.go, cipher_test.go).
//
// # Scope
//
// DTLS 1.2 only (ProtocolVersion {254, 253}). Two cipher suites, both with
// AES-128-GCM (RFC 5288) record protection and SHA-256 as the PRF/Finished hash:
//
//   - TLS_PSK_WITH_AES_128_GCM_SHA256 (0x00A8, RFC 5487) — pre-shared key, no
//     certificates, reusing the Main-profile shared secret.
//   - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B, RFC 5289) — ephemeral
//     ECDH on P-256 (crypto/ecdh) authenticated by an ECDSA-P256 certificate
//     (self-signed by default; crypto/x509 + cert.go), with optional peer
//     certificate verification / SHA-256 fingerprint pinning.
//
// Both roles (client and server) are implemented, including the stateless
// HelloVerifyRequest cookie exchange (RFC 6347 §4.2.1), handshake-message
// fragmentation/reassembly and flight retransmission (§4.2.4), the
// extended_master_secret extension (RFC 7627), and the anti-replay window
// (§4.1.2.6). Renegotiation, session resumption, and DTLS 1.3 are out of scope.
//
// # Dependencies
//
// Standard library (crypto/aes, crypto/cipher, crypto/ecdh, crypto/ecdsa,
// crypto/x509, crypto/sha256, crypto/hmac, crypto/rand) plus
// golang.org/x/crypto/cryptobyte for TLS-style encoding — all within the
// project's stdlib + x/crypto allowlist, so the package compiles in the default
// build and is covered by the standard race/fuzz gauntlet. It is runtime opt-in
// via the public Config, not a build tag.
package dtls
