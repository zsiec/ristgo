package dtls

// Protocol constants for the handshake: cipher suites, extensions, named groups,
// signature algorithms, and the compression byte. Values are the IANA TLS
// registry assignments used unchanged by DTLS 1.2.

// HandshakeType (RFC 5246 §7.4; RFC 6347 §4.3.2 adds hello_verify_request).
type handshakeType uint8

const (
	typeHelloRequest       handshakeType = 0
	typeClientHello        handshakeType = 1
	typeServerHello        handshakeType = 2
	typeHelloVerifyRequest handshakeType = 3
	typeCertificate        handshakeType = 11
	typeServerKeyExchange  handshakeType = 12
	typeCertificateRequest handshakeType = 13
	typeServerHelloDone    handshakeType = 14
	typeCertificateVerify  handshakeType = 15
	typeClientKeyExchange  handshakeType = 16
	typeFinished           handshakeType = 20
)

// Cipher suites (the two this package supports), AES-128-GCM + SHA-256.
//
// Deferred deviation from RFC 7525 §4.2 / RFC 8422 mandatory-to-implement set
// (finding L7): of the five suites RFC 7525 §6.2 recommends, only
// ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 is implemented (plus the PSK suite RIST
// actually uses). The omissions are deliberate:
//
//   - ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 is NOT a clean extension of the
//     existing machinery: it changes BOTH the bulk key length (AES-256) and the
//     PRF/Finished/transcript hash (SHA-384). The PRF (prf/pHash) and the
//     handshake transcript hash (transcriptHash) are fixed to SHA-256 and woven
//     through the master-secret/EMS derivation, CertificateVerify, and both
//     Finished computations; parametrizing the hash would touch the entire key
//     schedule and every transcript consumer in both handshake drivers. Given no
//     interop oracle (see below), AES-128-GCM/SHA-256 — itself a recommended,
//     128-bit-secure AEAD suite — is the single supported GCM strength.
//   - The ECDHE_RSA_* and DHE_RSA_* suites need an RSA certificate/signature
//     path distinct from the ECDSA one and are out of scope.
//
// There is no interop cost: libRIST ships no DTLS, so there is no reference peer
// whose suite list ristgo must match; the supported suites are validated against
// OpenSSL (see doc.go). Adding AES-256-GCM/SHA-384 is tracked as future work
// behind a hash-parametrized PRF and transcript.
const (
	tlsPSKWithAES128GCMSHA256        uint16 = 0x00A8 // RFC 5487
	tlsECDHEECDSAWithAES128GCMSHA256 uint16 = 0xC02B // RFC 5289
)

// Extension types (RFC 5246, RFC 4492/8422, RFC 7627).
const (
	extSupportedGroups      uint16 = 10 // elliptic_curves / supported_groups
	extECPointFormats       uint16 = 11
	extSignatureAlgorithms  uint16 = 13
	extExtendedMasterSecret uint16 = 23
	extRenegotiationInfo    uint16 = 0xFF01
)

// Named group: only secp256r1 (P-256) is offered (RFC 8422 §5.1.1).
const namedGroupSecp256r1 uint16 = 23

// EC point format: uncompressed only (RFC 8422 §5.1.2).
const ecPointUncompressed uint8 = 0

// Signature scheme: ecdsa_secp256r1_sha256 (RFC 8446 §4.2.3 value, valid as the
// TLS 1.2 SignatureAndHashAlgorithm {hash=sha256(4), sig=ecdsa(3)}).
const (
	sigSchemeECDSAP256SHA256 uint16 = 0x0403
	hashAlgSHA256            uint8  = 4
	sigAlgECDSA              uint8  = 3
)

// compressionNull is the only compression method (RFC 5246 §6.1).
const compressionNull uint8 = 0

// randomLen is the size of the client/server Random (RFC 5246 §7.4.1.2).
const randomLen = 32

// maxCookieLen bounds an inbound HelloVerifyRequest cookie (RFC 6347 §4.2.1:
// cookie is opaque<0..2^8-1>).
const maxCookieLen = 255

// alertLevel / alertDescription (RFC 5246 §7.2) — only what we emit/recognize.
type alertLevel uint8

const (
	alertWarning alertLevel = 1
	alertFatal   alertLevel = 2
)

const (
	alertCloseNotify      uint8 = 0
	alertHandshakeFailure uint8 = 40
	alertBadCertificate   uint8 = 42
	alertDecryptError     uint8 = 51
	alertUnsupportedExt   uint8 = 110
	alertNoAlert          uint8 = 255
)
