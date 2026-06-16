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
//     exchange protected application data over an in-memory pipe, for every
//     supported cipher suite (allsuites_test.go).
//   - External interop: against the OpenSSL DTLS CLI (`openssl s_server/s_client
//     -dtls1_2`), behind //go:build interop with a graceful skip when openssl is
//     absent (interop_test.go) — a real, independent DTLS 1.2 implementation,
//     exercised for every suite in both client and server roles.
//   - Known-answer tests: the TLS 1.2 P_SHA256 and P_SHA384 PRFs (RFC 5246 §5)
//     and the AES-GCM record AEAD against published vectors (prf_test.go,
//     cipher_test.go).
//
// # Scope
//
// DTLS 1.2 only (ProtocolVersion {254, 253}). All five TR-06-2 §6.2
// mandatory-to-implement cipher suites are supported, plus the PSK suite RIST
// uses, with per-suite enable/disable via Config.DisabledSuites (the §6.2 SHALL):
//
//   - TLS_PSK_WITH_AES_128_GCM_SHA256 (0x00A8, RFC 5487) — pre-shared key, no
//     certificates, reusing the Main-profile shared secret.
//   - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B) and
//     TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02C, RFC 5289) — ephemeral ECDH
//     on P-256 authenticated by an ECDSA-P256 certificate.
//   - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F) and
//     TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030, RFC 5289) — ephemeral ECDH
//     authenticated by an RSA certificate.
//   - TLS_RSA_WITH_NULL_SHA256 (0x003B, RFC 5246) — RSA key transport with a NULL
//     cipher and an HMAC-SHA256 MAC: integrity only, NO confidentiality. Mandatory
//     to support, but OFF by default (a confidentiality-free suite must not be
//     reachable just because a certificate was configured); enable it explicitly via
//     Config.AllowNullCipher when an unencrypted-but-authenticated transport is a
//     deliberate requirement.
//
// The PRF/transcript hash is SHA-256 or SHA-384 per the suite; AES-128 and AES-256
// GCM record protection and the NULL+HMAC record layer are all implemented.
// Certificates may be ECDSA P-256 or RSA (self-signed by default; crypto/x509 +
// cert.go), with optional peer verification / SHA-256 fingerprint pinning.
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
// crypto/rsa, crypto/x509, crypto/sha256, crypto/sha512, crypto/hmac,
// crypto/rand) plus golang.org/x/crypto/cryptobyte for TLS-style encoding — all within the
// project's stdlib + x/crypto allowlist, so the package compiles in the default
// build and is covered by the standard race/fuzz gauntlet. It is runtime opt-in
// via the public Config, not a build tag.
package dtls
