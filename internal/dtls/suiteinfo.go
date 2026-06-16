package dtls

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// cipherSuiteInfo describes one cipher suite: its key-exchange and authentication
// methods, the bulk-cipher key length, the PRF/transcript hash, and (for the NULL
// suite) the MAC length. It is the table the handshake drivers consult instead of
// branching on the raw suite id, so adding a suite is a table row plus the key
// exchange / record-protection code its (kx, aead) pair needs — not a new branch
// in every transcript/PRF/Finished consumer.
//
// The supported set is exactly TR-06-2 §6.2's mandatory five plus the PSK suite
// RIST itself uses:
//
//	0xC02B ECDHE_ECDSA_AES_128_GCM_SHA256   (RFC 5289)
//	0xC02C ECDHE_ECDSA_AES_256_GCM_SHA384   (RFC 5289)
//	0xC02F ECDHE_RSA_AES_128_GCM_SHA256     (RFC 5289)
//	0xC030 ECDHE_RSA_AES_256_GCM_SHA384     (RFC 5289)
//	0x003B RSA_WITH_NULL_SHA256             (RFC 5246) — integrity only, no confidentiality
//	0x00A8 PSK_WITH_AES_128_GCM_SHA256      (RFC 5487)
type cipherSuiteInfo struct {
	id   uint16
	kx   kxMethod
	auth authMethod

	// keyLen is the bulk-cipher key length: 16 (AES-128), 32 (AES-256), or 0
	// (NULL — no encryption).
	keyLen int
	// macLen is the HMAC output/key length for a MAC-only (NULL) suite: 32 for
	// SHA-256. It is 0 for an AEAD suite, which carries no separate MAC key.
	macLen int
	// aead selects AES-GCM record protection (true) vs NULL-cipher-with-HMAC
	// (false). With NULL, records are authenticated by an appended HMAC but not
	// encrypted.
	aead bool

	// newHash is the suite's hash, used for the PRF (P_hash), the handshake
	// transcript hash, the Finished verify_data, and extended_master_secret. It is
	// SHA-256 for the *_SHA256 suites and SHA-384 for the *_SHA384 suites.
	newHash func() hash.Hash
}

// kxMethod is a key-exchange method.
type kxMethod uint8

const (
	kxECDHE kxMethod = iota // ephemeral ECDH on P-256 (forward secret)
	kxRSA                   // RSA key transport (client encrypts the pre-master)
	kxPSK                   // pre-shared key
)

// authMethod is how the server (and optionally client) authenticates.
type authMethod uint8

const (
	authNone  authMethod = iota // PSK: the shared key is the authenticator
	authECDSA                   // ECDSA P-256 certificate
	authRSA                     // RSA certificate
)

// suiteTable is the supported cipher suites, in server-preference order
// (strongest/forward-secret first; the NULL integrity-only suite last). selectSuite
// and the client's offered-list builder both derive from this table filtered by
// what the config can do and what the user has not disabled.
var suiteTable = []cipherSuiteInfo{
	{id: tlsECDHEECDSAWithAES256GCMSHA384, kx: kxECDHE, auth: authECDSA, keyLen: 32, aead: true, newHash: sha512.New384},
	{id: tlsECDHERSAWithAES256GCMSHA384, kx: kxECDHE, auth: authRSA, keyLen: 32, aead: true, newHash: sha512.New384},
	{id: tlsECDHEECDSAWithAES128GCMSHA256, kx: kxECDHE, auth: authECDSA, keyLen: 16, aead: true, newHash: sha256.New},
	{id: tlsECDHERSAWithAES128GCMSHA256, kx: kxECDHE, auth: authRSA, keyLen: 16, aead: true, newHash: sha256.New},
	{id: tlsPSKWithAES128GCMSHA256, kx: kxPSK, auth: authNone, keyLen: 16, aead: true, newHash: sha256.New},
	{id: tlsRSAWithNULLSHA256, kx: kxRSA, auth: authRSA, keyLen: 0, macLen: 32, aead: false, newHash: sha256.New},
}

// lookupSuite returns the descriptor for a suite id, or ok=false if unsupported.
func lookupSuite(id uint16) (cipherSuiteInfo, bool) {
	for _, s := range suiteTable {
		if s.id == id {
			return s, true
		}
	}
	return cipherSuiteInfo{}, false
}
