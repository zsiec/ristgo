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

// Cipher suites. The five TR-06-2 §6.2 mandatory-to-implement suites are all
// supported (see suiteTable), plus the PSK suite RIST itself uses. The
// PRF/transcript hash is parametrized per suite (SHA-256 or SHA-384, see
// cipherSuiteInfo.newHash), AES-128 and AES-256 GCM are both wired, and there is
// an RSA certificate/signature path alongside the ECDSA one and an RSA
// key-transport + NULL-cipher (integrity-only) path for RSA_WITH_NULL_SHA256.
// RSA_WITH_NULL_SHA256 provides NO confidentiality; it is mandatory to *support*
// but is OFF by default and reachable only via Config.AllowNullCipher (so a
// certificate config cannot silently enable a cleartext session), and like every
// suite can also be turned off per the user's policy (the §6.2 disable knob). The
// supported set is validated against OpenSSL
// (see the interop test); libRIST ships no DTLS, so there is no reference peer
// whose suite list ristgo must match.
const (
	tlsPSKWithAES128GCMSHA256        uint16 = 0x00A8 // RFC 5487
	tlsRSAWithNULLSHA256             uint16 = 0x003B // RFC 5246 — integrity only
	tlsECDHEECDSAWithAES128GCMSHA256 uint16 = 0xC02B // RFC 5289
	tlsECDHEECDSAWithAES256GCMSHA384 uint16 = 0xC02C // RFC 5289
	tlsECDHERSAWithAES128GCMSHA256   uint16 = 0xC02F // RFC 5289
	tlsECDHERSAWithAES256GCMSHA384   uint16 = 0xC030 // RFC 5289
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

// Signature schemes: the TLS 1.2 SignatureAndHashAlgorithm pairs {hash, sig}
// (RFC 5246 §7.4.1.4.1), encoded hash<<8 | sig. ristgo offers ECDSA and RSA
// (PKCS#1 v1.5) over SHA-256 and SHA-384, so a peer's certificate of either type
// and either suite hash can be authenticated. It signs its own messages with the
// SHA-256 variant for its certificate's key type (always a valid choice for the
// supported suites); it accepts either hash on the verify path so an OpenSSL peer
// that prefers SHA-384 still interoperates.
const (
	sigSchemeECDSAP256SHA256 uint16 = 0x0403 // {sha256(4), ecdsa(3)}
	sigSchemeECDSAP256SHA384 uint16 = 0x0503 // {sha384(5), ecdsa(3)}
	sigSchemeRSAPKCS1SHA256  uint16 = 0x0401 // {sha256(4), rsa(1)}
	sigSchemeRSAPKCS1SHA384  uint16 = 0x0501 // {sha384(5), rsa(1)}

	hashAlgSHA256 uint8 = 4
	hashAlgSHA384 uint8 = 5
	sigAlgRSA     uint8 = 1
	sigAlgECDSA   uint8 = 3
)

// offeredSignatureAlgorithms is the signature_algorithms extension ristgo sends:
// ECDSA and RSA over both SHA-256 and SHA-384, so a peer may authenticate with an
// ECDSA-P256 or RSA certificate and sign under either suite's hash.
var offeredSignatureAlgorithms = []uint16{
	sigSchemeECDSAP256SHA256, sigSchemeECDSAP256SHA384,
	sigSchemeRSAPKCS1SHA256, sigSchemeRSAPKCS1SHA384,
}

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
