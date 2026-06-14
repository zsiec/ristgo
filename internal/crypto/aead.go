// AEAD support for the RIST Advanced Profile (VSF TR-06-3 §8) PSK modes.
//
// INTEROP STATUS — READ THIS FIRST.
//
// libRIST v0.2.18-rc1 implements ONLY the Main-compatible AES-CTR mode for the
// Advanced Profile (PSK mode 1, RIST_ADV_PSK_AES_CTR). The three
// authenticated modes added here —
//
//   - mode 3 RIST_ADV_PSK_AES_CTR_HMAC      (AES-CTR + HMAC-SHA256)
//   - mode 4 RIST_ADV_PSK_AES_GCM           (AES-GCM)
//   - mode 5 RIST_ADV_PSK_CHACHA20_POLY1305 (ChaCha20-Poly1305)
//
// — have NO byte-exact reference: libRIST does not implement them, so there is
// no captured-on-the-wire interop oracle to validate against. This file is a
// spec-best-effort implementation of TR-06-3 §8 with the under-specified parts
// resolved by the most defensible interpretation, each flagged below. The
// CIPHER primitives themselves (AES-GCM, ChaCha20-Poly1305, AES-CTR, HMAC-SHA256)
// ARE validated against published standard vectors in aead_test.go (NIST GCM
// and RFC 8439) — that part is certain. What is interop-unvalidated is the RIST
// framing around them: nonce construction, AAD scope, and HMAC-key choice.
//
// INTERPRETED CONSTRUCTIONS (all "interop-unvalidated; pending a reference or
// the full TR-06-3 §5.2.5 detail"):
//
//  1. The 12-byte AEAD nonce (GCM / ChaCha20-Poly1305). TR-06-3 §8 / Figure 19
//     specifies only the 128-bit AES-CTR IV as [IV field (4 B, big-endian) |
//     12 zero bytes] (the same construction as Main / crypto.BuildIV). It does
//     NOT specify a 12-byte AEAD nonce. We bind BOTH the key epoch and the
//     per-packet counter into the nonce: 12-byte nonce = [PSK Nonce (4 B) |
//     IV field (4 B, big-endian) | 4 zero bytes] (aeadNonce). Folding the PSK
//     Nonce into the nonce — not only into the PBKDF2 key derivation — makes
//     every key epoch structurally distinct in the nonce as well, so two epochs
//     can never collide on (key, nonce) even if their per-packet IV ranges
//     overlap. The 4-byte IV field increments per packet, so within one epoch
//     every (key, nonce) pair is unique — the non-negotiable uniqueness
//     requirement for both GCM and ChaCha20-Poly1305. INTERPRETED.
//
//     SAFE-BY-CONSTRUCTION: SealAdvanced is a stateless primitive and takes iv4
//     as an opaque counter, so it cannot enforce non-wrap itself. Use
//     AdvancedSealer (this package) for the production send path: it owns the IV
//     counter and returns ErrIVExhausted rather than letting the IV field wrap
//     within one PSK Nonce, forcing the host to rotate the nonce (re-derive the
//     key) instead of silently reusing a (key, nonce) pair — which under GCM or
//     ChaCha20-Poly1305 is catastrophic (tag forgery via authentication-key
//     recovery plus keystream reuse, materially worse than the AES-CTR case).
//
//  2. The AEAD AAD scope / the AES-CTR-HMAC authenticated region. TR-06-3
//     §8/§8.1 says authentication covers the whole RTP packet (first byte of the
//     RTP header to the last byte of payload) with the 16-byte Hash field
//     zeroed. In AEAD terms that is: AAD = the cleartext header bytes with the
//     Hash field zeroed; encrypted region = AEAD plaintext/ciphertext. This
//     package deliberately does NOT know the packet layout: the caller (the
//     future Advanced session codec, WP7c) supplies the exact header bytes —
//     with the Hash field already zeroed — as aad, and the encrypted region as
//     plaintext. Wiring the packet regions is the codec's job, not this
//     package's. INTERPRETED scope, faithful primitive.
//
//     CALLER CONTRACT (security-load-bearing): the PSK Nonce and IV fields are
//     part of that cleartext header, so the codec MUST include them in aad. For
//     GCM/ChaCha the 12-byte nonce is bound into the tag, so a changed IV is
//     detected regardless; but for AES-CTR-HMAC (mode 3) the IV is authenticated
//     ONLY by virtue of being in aad — the HMAC here covers aad || ciphertext
//     and nothing else. A codec that omits the IV field from aad would let an
//     attacker shift the AES-CTR keystream undetected on mode 3. Always put the
//     full cleartext header (Hash zeroed) in aad.
//
//  3. The AES-CTR-HMAC HMAC key. TR-06-3 §8.1 does not name a separate
//     authentication key. Rather than reuse the AES-CTR key as the HMAC key (a
//     key-separation anti-pattern), we derive an INDEPENDENT HMAC-SHA256 key by
//     expanding the AES-CTR key with a distinct label (deriveMACKey, an
//     HKDF-Expand-style step). The order is encrypt-then-MAC (§8.1: "encryption
//     shall be applied before authentication"): HMAC input = aad || ciphertext,
//     then truncate the 32-byte HMAC to the 16-byte Hash field. INTERPRETED —
//     mode 3 is unimplemented by libRIST, so this two-key construction is
//     ristgo-internal until a reference or the full §5.2.5 detail fixes it.
//
// Key derivation is the one CERTAIN piece of the framing: PBKDF2-HMAC-SHA256
// over the passphrase salted by the 4-byte PSK Nonce, 1024 iterations, derived
// length keyBits/8 — identical to Main (TR-06-3 §8.3; reuses DeriveKey).
//
// Like the rest of this package the code is sans-I/O and deterministic: given
// (password/key, nonce, IV, aad, plaintext) the output is a pure function. No
// clock, socket, goroutine, or crypto/rand draw happens here — nonce/IV
// management belongs to the session host.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Sentinel errors specific to the Advanced AEAD modes. They extend the package
// var block in psk.go; test for them with errors.Is.
var (
	// ErrAuthFailed is returned by OpenAdvanced when the authentication tag or
	// HMAC does not verify — a tampered ciphertext, AAD, or hash, or the wrong
	// key. The plaintext is never returned in this case; the recovered bytes are
	// discarded before the error is surfaced (TR-06-3 §8.1 authenticate-on-open).
	ErrAuthFailed = errors.New("rist: crypto: AEAD authentication failed")

	// ErrUnknownPSKMode is returned by SealAdvanced and OpenAdvanced when the
	// PSK mode is not one of the three authenticated Advanced modes this file
	// handles (3 AES-CTR-HMAC, 4 AES-GCM, 5 ChaCha20-Poly1305). Mode 1 plain
	// AES-CTR is handled by the Main path (Encrypt/Decrypt), not here.
	ErrUnknownPSKMode = errors.New("rist: crypto: unsupported Advanced PSK mode")

	// ErrChaChaKeySize is returned when ChaCha20-Poly1305 is requested with a
	// key size other than 256 bits. ChaCha20-Poly1305 has only a 256-bit key
	// variant (RFC 8439); a 128-bit request is a configuration error.
	ErrChaChaKeySize = errors.New("rist: crypto: ChaCha20-Poly1305 requires a 256-bit key")

	// ErrIVExhausted is returned by AdvancedSealer.Seal when the 32-bit IV field
	// would wrap within the current PSK Nonce. Continuing would reuse a
	// (key, nonce) pair — catastrophic for AES-GCM and ChaCha20-Poly1305 — so the
	// sealer refuses and the host must rotate the PSK Nonce (re-derive the key
	// with fresh randomness, which is the host's job: this package is sans-I/O)
	// and build a new AdvancedSealer before sealing again.
	ErrIVExhausted = errors.New("rist: crypto: Advanced PSK IV field exhausted; rotate the PSK Nonce")
)

// PSKMode identifies one of the RIST Advanced Profile PSK encryption modes.
// The values mirror the 3-bit PSK field of the profile-defined header
// (RIST_ADV_PSK_*); only the authenticated modes handled by this
// file are named here.
type PSKMode uint8

const (
	// PSKModeAESCTRHMAC is RIST_ADV_PSK_AES_CTR_HMAC: AES-CTR
	// encryption followed by HMAC-SHA256 authentication, the 32-byte HMAC
	// truncated to the 16-byte Hash field.
	PSKModeAESCTRHMAC PSKMode = 3

	// PSKModeAESGCM is RIST_ADV_PSK_AES_GCM: AES-GCM, the 16-byte
	// GCM tag carried in the Hash field (not appended to the wire ciphertext).
	PSKModeAESGCM PSKMode = 4

	// PSKModeChaCha20Poly1305 is RIST_ADV_PSK_CHACHA20_POLY1305:
	// ChaCha20-Poly1305 with a 256-bit key, the 16-byte Poly1305 tag carried in
	// the Hash field.
	PSKModeChaCha20Poly1305 PSKMode = 5
)

const (
	// HashSize is the length of the Advanced PSK Hash field in bytes
	// (RIST_ADV_PSK_HASH_SIZE = 16). It holds the GCM tag, the Poly1305
	// tag, or the truncated HMAC depending on the mode.
	HashSize = 16

	// aeadNonceSize is the 12-byte nonce length both crypto/cipher's GCM and
	// chacha20poly1305 use by default (the standard 96-bit AEAD nonce).
	aeadNonceSize = 12

	// gcmTagSize is the AES-GCM authentication tag length: 16 bytes, matching
	// HashSize so the tag fits the Hash field exactly.
	gcmTagSize = 16
)

// aeadNonce builds the INTERPRETED 12-byte AEAD nonce for GCM and
// ChaCha20-Poly1305: the 4-byte PSK Nonce (the key epoch) in bytes [0:4], the
// 4-byte IV field big-endian in [4:8], then four zero bytes. Binding the PSK
// Nonce into the nonce — not only into the PBKDF2 key derivation — makes every
// key epoch structurally distinct, so two epochs can never present the same
// (key, nonce) pair even if their per-packet IV ranges overlap. Within one
// epoch the per-packet IV field supplies uniqueness; AdvancedSealer enforces
// that the IV field cannot wrap within an epoch.
//
// INTERPRETED (interop-unvalidated; pending a reference or the full TR-06-3
// §5.2.5 detail): TR-06-3 specifies only the 16-byte AES-CTR IV, not the
// 12-byte AEAD nonce.
func aeadNonce(nonce4 [NonceSize]byte, iv4 uint32) [aeadNonceSize]byte {
	var n [aeadNonceSize]byte
	copy(n[0:NonceSize], nonce4[:])
	binary.BigEndian.PutUint32(n[NonceSize:NonceSize+4], iv4)
	return n
}

// SealAdvanced encrypts plaintext under the given Advanced PSK mode and returns
// the wire ciphertext (without any appended tag) plus the 16-byte value for the
// PSK Hash field.
//
// The AES key (and, for mode 3, the HMAC key) is derived from password and the
// 4-byte PSK Nonce via DeriveKey (PBKDF2-HMAC-SHA256, 1024 iterations,
// TR-06-3 §8.3). keyBits is 128 or 256 for AES modes; ChaCha20-Poly1305
// requires 256. nonce4 is the PSK Nonce field (the PBKDF2 salt, also the
// odd/even passphrase marker carrier) and must be non-zero. iv4 is the 4-byte
// IV field, which the caller increments per packet; it forms the AEAD nonce
// (aeadNonce) / the AES-CTR IV (BuildIV). aad is the authenticated-but-not-
// encrypted region — for RIST, the cleartext header bytes with the Hash field
// zeroed (see the package interop note, interpretation 2).
//
// For modes 4 and 5 the returned hash is the 16-byte AEAD tag; the ciphertext
// is tag-free (RIST carries the tag in the Hash field, not appended). For
// mode 3 the ciphertext is the AES-CTR keystream output and the hash is the
// encrypt-then-MAC HMAC-SHA256(aad || ciphertext) truncated to 16 bytes.
func SealAdvanced(mode PSKMode, password []byte, keyBits int, nonce4 [NonceSize]byte, iv4 uint32, aad, plaintext []byte) (ciphertext []byte, hash [HashSize]byte, err error) {
	if isZeroNonce(nonce4) {
		return nil, hash, ErrZeroNonce
	}
	key, err := deriveAEADKey(mode, password, nonce4, keyBits)
	if err != nil {
		return nil, hash, err
	}
	switch mode {
	case PSKModeAESCTRHMAC:
		macKey := deriveMACKey(key)
		ct, cerr := ctrXOR(key, BuildIV(iv4), plaintext)
		if cerr != nil {
			return nil, hash, cerr
		}
		hash = hmacTag(macKey, aad, ct)
		return ct, hash, nil
	case PSKModeAESGCM:
		return sealGCM(key, aeadNonce(nonce4, iv4), aad, plaintext)
	case PSKModeChaCha20Poly1305:
		return sealChaCha(key, aeadNonce(nonce4, iv4), aad, plaintext)
	default:
		return nil, hash, ErrUnknownPSKMode
	}
}

// OpenAdvanced reverses SealAdvanced: it re-derives the key(s), verifies the tag
// or HMAC in constant time, and only then returns the recovered plaintext. On
// any authentication failure it returns ErrAuthFailed and a nil plaintext — the
// recovered bytes are never leaked (TR-06-3 §8.1: authenticate before use). A
// zero nonce4 is rejected with ErrZeroNonce, matching the Main receive path.
//
// The arguments mirror SealAdvanced. ciphertext is the wire ciphertext (tag-
// free); hash is the 16-byte value read from the PSK Hash field. aad must be
// the identical authenticated region the sender used (the header bytes with the
// Hash field zeroed).
func OpenAdvanced(mode PSKMode, password []byte, keyBits int, nonce4 [NonceSize]byte, iv4 uint32, aad, ciphertext []byte, hash [HashSize]byte) (plaintext []byte, err error) {
	if isZeroNonce(nonce4) {
		return nil, ErrZeroNonce
	}
	key, err := deriveAEADKey(mode, password, nonce4, keyBits)
	if err != nil {
		return nil, err
	}
	switch mode {
	case PSKModeAESCTRHMAC:
		// Encrypt-then-MAC means verify-then-decrypt: recompute the HMAC over the
		// ciphertext (with the independent MAC key) and compare in constant time
		// before touching the keystream.
		macKey := deriveMACKey(key)
		want := hmacTag(macKey, aad, ciphertext)
		if subtle.ConstantTimeCompare(want[:], hash[:]) != 1 {
			return nil, ErrAuthFailed
		}
		return ctrXOR(key, BuildIV(iv4), ciphertext)
	case PSKModeAESGCM:
		return openGCM(key, aeadNonce(nonce4, iv4), aad, ciphertext, hash)
	case PSKModeChaCha20Poly1305:
		return openChaCha(key, aeadNonce(nonce4, iv4), aad, ciphertext, hash)
	default:
		return nil, ErrUnknownPSKMode
	}
}

// AdvancedSealer is a stateful, single-epoch wrapper around SealAdvanced that
// owns the per-packet IV field and makes the security-load-bearing
// (key, nonce)-uniqueness requirement structural rather than a caller
// obligation. It issues a fresh, monotonically increasing IV field for each
// Seal and refuses with ErrIVExhausted once the 32-bit IV field would wrap
// within the current PSK Nonce — so the wrap-without-rotation foot-gun (a
// repeated nonce under GCM/ChaCha) cannot happen silently. Construct one sealer
// per PSK Nonce epoch; on ErrIVExhausted the host rotates the PSK Nonce
// (re-derives the key) and builds a fresh sealer.
//
// It is sans-I/O and is NOT safe for concurrent use; the session host must
// serialize Seal calls from its single send goroutine.
type AdvancedSealer struct {
	mode      PSKMode
	password  []byte
	keyBits   int
	nonce4    [NonceSize]byte
	iv        uint32 // next IV field to issue
	exhausted bool   // the last representable IV has been issued
}

// NewAdvancedSealer creates a sealer for one PSK Nonce epoch. startIV is the
// first IV field value to issue (typically 0); successive Seal calls issue
// startIV, startIV+1, … and the sealer refuses once the field reaches its
// maximum, never wrapping the 32-bit counter within the epoch.
func NewAdvancedSealer(mode PSKMode, password []byte, keyBits int, nonce4 [NonceSize]byte, startIV uint32) *AdvancedSealer {
	return &AdvancedSealer{mode: mode, password: password, keyBits: keyBits, nonce4: nonce4, iv: startIV}
}

// Seal encrypts plaintext with the next IV field and returns the wire
// ciphertext, the 16-byte Hash-field value, and the IV field used — which the
// codec writes into the packet header so the receiver can OpenAdvanced. It
// returns ErrIVExhausted instead of reusing a nonce once the IV field is spent;
// the host must then rotate the PSK Nonce and build a new sealer. aad and the
// per-mode semantics are exactly those of SealAdvanced.
func (s *AdvancedSealer) Seal(aad, plaintext []byte) (ciphertext []byte, hash [HashSize]byte, iv4 uint32, err error) {
	if s.exhausted {
		return nil, hash, 0, ErrIVExhausted
	}
	iv4 = s.iv
	ct, h, serr := SealAdvanced(s.mode, s.password, s.keyBits, s.nonce4, iv4, aad, plaintext)
	if serr != nil {
		return nil, hash, 0, serr
	}
	if s.iv == ^uint32(0) {
		s.exhausted = true // issued the last representable IV; the next call must rotate
	} else {
		s.iv++
	}
	return ct, h, iv4, nil
}

// deriveAEADKey derives the symmetric key for the given Advanced PSK mode from
// the passphrase and the 4-byte PSK Nonce (PBKDF2-HMAC-SHA256, TR-06-3 §8.3,
// via DeriveKey). It centralizes the per-mode key-size rules: AES modes accept
// 128 or 256 bits; ChaCha20-Poly1305 requires 256.
func deriveAEADKey(mode PSKMode, password []byte, nonce4 [NonceSize]byte, keyBits int) ([]byte, error) {
	if mode == PSKModeChaCha20Poly1305 && keyBits != KeySize256 {
		return nil, ErrChaChaKeySize
	}
	return DeriveKey(password, nonce4[:], keyBits)
}

// macKeyLabel domain-separates the AES-CTR-HMAC authentication key from the
// encryption key in deriveMACKey.
var macKeyLabel = []byte("rist-adv-aes-ctr-hmac-auth-key")

// deriveMACKey derives the independent HMAC-SHA256 authentication key for
// AES-CTR-HMAC mode by expanding the AES-CTR encryption key with a distinct
// label (an HKDF-Expand-style step). Reusing one key for both the cipher and the
// MAC is a key-separation anti-pattern; this keeps them independent (recovering
// the MAC key does not reveal the cipher key, and vice versa). Mode 3 is not
// implemented by libRIST and is interop-unvalidated, so this two-key
// construction is ristgo-internal until a spec or interop oracle fixes the
// intended derivation.
func deriveMACKey(encKey []byte) []byte {
	mac := hmac.New(sha256.New, encKey)
	mac.Write(macKeyLabel)
	return mac.Sum(nil)
}

// hmacTag computes the AES-CTR-HMAC authentication value: HMAC-SHA256 over
// aad || ciphertext keyed by the independent MAC key (deriveMACKey), truncated
// to the 16-byte Hash field (encrypt-then-MAC; see the package interop note,
// interpretation 3).
func hmacTag(key, aad, ciphertext []byte) [HashSize]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(aad)
	mac.Write(ciphertext)
	full := mac.Sum(nil)
	var hash [HashSize]byte
	copy(hash[:], full[:HashSize])
	return hash
}

// ctrXOR applies AES-CTR with the given key and 16-byte IV over src, returning a
// fresh slice. It reuses this package's ctrState engine so the keystream is
// byte-identical to the Main AES-CTR path (psk.go) and to crypto/cipher.NewCTR.
// CTR is symmetric, so this serves both seal and open. It returns
// ErrInvalidKeySize for a non-AES key length rather than ever emitting a zero
// keystream — which, in the seal direction, would silently leak the plaintext.
func ctrXOR(key []byte, iv [ivSize]byte, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		// Current callers pass a DeriveKey output (always a valid 16/24/32-byte
		// key), so this is unreachable today; returning the error rather than a
		// zero keystream keeps the primitive safe for any future caller.
		return nil, ErrInvalidKeySize
	}
	state := ctrState{block: block}
	return state.crypt(iv, nil, src), nil
}

// sealGCM is the AES-GCM seal primitive, exported within the package for direct
// KAT testing against NIST GCM vectors. It returns the ciphertext with the
// 16-byte tag SPLIT OUT into hash (RIST carries the tag in the Hash field, not
// appended to the wire ciphertext).
func sealGCM(key []byte, nonce [aeadNonceSize]byte, aad, plaintext []byte) (ciphertext []byte, hash [HashSize]byte, err error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, hash, err
	}
	// Seal appends the tag; split it back off into the Hash field.
	sealed := aead.Seal(nil, nonce[:], plaintext, aad)
	ctLen := len(sealed) - gcmTagSize
	copy(hash[:], sealed[ctLen:])
	return sealed[:ctLen:ctLen], hash, nil
}

// openGCM is the AES-GCM open primitive: it re-joins the wire ciphertext and
// the tag from the Hash field, then verifies-and-decrypts. A tag mismatch maps
// to ErrAuthFailed with no plaintext leaked.
func openGCM(key []byte, nonce [aeadNonceSize]byte, aad, ciphertext []byte, hash [HashSize]byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(ciphertext)+gcmTagSize)
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, hash[:]...)
	pt, err := aead.Open(nil, nonce[:], sealed, aad)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return pt, nil
}

// newGCM builds an AES-GCM AEAD with the standard 12-byte nonce and 16-byte tag
// from the derived key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalidKeySize
	}
	return cipher.NewGCM(block)
}

// sealChaCha is the ChaCha20-Poly1305 seal primitive, exported within the
// package for direct KAT testing against RFC 8439 §2.8.2. Like sealGCM it splits
// the 16-byte Poly1305 tag out into the Hash field.
func sealChaCha(key []byte, nonce [aeadNonceSize]byte, aad, plaintext []byte) (ciphertext []byte, hash [HashSize]byte, err error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, hash, ErrChaChaKeySize
	}
	sealed := aead.Seal(nil, nonce[:], plaintext, aad)
	ctLen := len(sealed) - chacha20poly1305.Overhead
	copy(hash[:], sealed[ctLen:])
	return sealed[:ctLen:ctLen], hash, nil
}

// openChaCha is the ChaCha20-Poly1305 open primitive: re-join ciphertext + tag,
// verify-and-decrypt, map a tag mismatch to ErrAuthFailed with no plaintext.
func openChaCha(key []byte, nonce [aeadNonceSize]byte, aad, ciphertext []byte, hash [HashSize]byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, ErrChaChaKeySize
	}
	sealed := make([]byte, 0, len(ciphertext)+chacha20poly1305.Overhead)
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, hash[:]...)
	pt, err := aead.Open(nil, nonce[:], sealed, aad)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return pt, nil
}
