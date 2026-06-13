// Package crypto implements the RIST Main-profile pre-shared-key (PSK)
// payload encryption: PBKDF2-HMAC-SHA256 key derivation salted by the 4-byte
// GRE nonce, followed by AES-CTR over the GRE payload. It is byte-exact with
// libRIST v0.2.18-rc1 (src/crypto/psk.c, src/rist-private.h).
//
// The design is sans-I/O and deterministic in the host's hands: this package
// never reads a clock, opens a socket, or spawns a goroutine. The only
// non-determinism is nonce generation, which draws from crypto/rand at
// construction and on key rotation; everything else (key derivation, IV
// construction, the AES-CTR keystream) is a pure function of its inputs and is
// unit-tested in isolation.
//
// Wire facts, all confirmed against libRIST source and cited inline:
//
//   - Key derivation is PBKDF2-HMAC-SHA256 over the passphrase, salted by the
//     4-byte GRE nonce, with 1024 iterations and a derived length of
//     keyBits/8 (psk.c:102-119; RIST_PBKDF2_HMAC_SHA256_ITERATIONS,
//     rist-private.h:56).
//   - The 16-byte AES-CTR IV is the 32-bit GRE sequence number, big-endian, in
//     bytes [0:4], then twelve zero bytes (psk.c:227-233, with copy_offset==0
//     for the only runtime GRE version, >=1). AES-CTR increments the low bytes
//     of the IV, so the per-packet seq sits high and never collides with the
//     block counter (gre.h:51-53).
//   - Encrypt and decrypt are the identical AES-CTR XOR-stream operation
//     (psk.c:196-225).
//   - The 4-byte nonce is a random non-zero uint32; bit 7 of nonce[0] marks the
//     odd/even passphrase (set for odd, clear for even). A zero nonce is never
//     emitted and never accepted for decryption (psk.c:235-275).
//   - The key rotates — a fresh nonce and re-derived key — when the user's
//     keyRotation threshold of encrypted packets is reached, or when the
//     packet counter would exhaust RIST_AES_KEY_REUSE_TIMES (UINT32_MAX,
//     rist-private.h:57) (psk.c:302-313). A receiver re-derives whenever the
//     inbound nonce differs from the one it last keyed on (psk.c:277-287).
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Sentinel errors returned by this package. Callers should test for them with
// errors.Is; returned errors may wrap these with additional context.
var (
	// ErrInvalidKeySize is returned by NewKey and DeriveKey when the
	// requested key size is not 128 or 256 bits. Only these two sizes are
	// representable on the RIST wire: the GRE header signals key length with a
	// single H bit (0 => 128, 1 => 256; rist-common.c:2993). libRIST's
	// derivation backend also accepts 192, but it can never be signalled.
	ErrInvalidKeySize = errors.New("rist: crypto: key size must be 128 or 256 bits")

	// ErrEmptyPassword is returned by NewKey when the passphrase is empty.
	ErrEmptyPassword = errors.New("rist: crypto: empty passphrase")

	// ErrNegativeRotation is returned by NewKey when keyRotation is negative.
	// Zero means "rotate only at counter exhaustion" (the library default);
	// a positive value rotates after that many encrypted packets.
	ErrNegativeRotation = errors.New("rist: crypto: negative key rotation")

	// ErrInvalidNonceLength is returned by DeriveKey when the nonce salt is
	// not exactly NonceSize bytes. The Key and Decryptor paths pass a
	// fixed-size [NonceSize]byte and never trigger it; it guards the exported
	// DeriveKey helper against a wrong-length salt.
	ErrInvalidNonceLength = errors.New("rist: crypto: nonce must be 4 bytes")

	// ErrZeroNonce is returned by Decrypt when the inbound GRE nonce is zero.
	// A zero nonce never comes from a legitimate sender, so it is refused
	// rather than used to key the cipher (psk.c:271-275).
	ErrZeroNonce = errors.New("rist: crypto: zero nonce rejected")

	// ErrKeyReuseExhausted is returned by Decryptor.Decrypt once more than
	// reuseLimit packets have been decrypted under one unchanging nonce —
	// defense-in-depth mirroring libRIST's receive-side refusal when
	// used_times exceeds RIST_AES_KEY_REUSE_TIMES (psk.c:289-292). A
	// conformant sender rotates its nonce long before this, which re-derives
	// the key and resets the counter, so it fires only against a peer that
	// never rotates.
	ErrKeyReuseExhausted = errors.New("rist: crypto: AES key reuse limit exhausted")

	// ErrCSPRNG wraps a failure to read from crypto/rand during nonce
	// generation. libRIST fails closed here (psk.c:236-258); so do we, by
	// surfacing the error to the caller instead of running AES under a
	// predictable nonce.
	ErrCSPRNG = errors.New("rist: crypto: CSPRNG unavailable")
)

const (
	// KeySize128 selects a 128-bit (16-byte) AES key.
	KeySize128 = 128

	// KeySize256 selects a 256-bit (32-byte) AES key.
	KeySize256 = 256

	// NonceSize is the length in bytes of the GRE nonce that salts key
	// derivation (psk.c:104, sizeof(key->gre_nonce)).
	NonceSize = 4

	// ivSize is the AES-CTR initialization-vector length: one AES block
	// (psk.c:30, AES_BLOCK_SIZE).
	ivSize = aes.BlockSize

	// pbkdf2Iterations is RIST_PBKDF2_HMAC_SHA256_ITERATIONS
	// (rist-private.h:56): the PBKDF2 iteration count salting key derivation.
	pbkdf2Iterations = 1024

	// reuseLimit is RIST_AES_KEY_REUSE_TIMES (rist-private.h:57): the maximum
	// number of packets encrypted under one nonce before the key must rotate
	// regardless of the user's keyRotation knob. It is effectively unbounded.
	reuseLimit = uint32(0xFFFFFFFF)

	// nonceBBitByte is the index of the nonce byte carrying the odd/even
	// passphrase marker (psk.c:262-264).
	nonceBBitByte = 0

	// nonceBBitMask isolates bit 7 of nonceBBitByte, the odd/even marker
	// (psk.c:262, UNSET_BIT(..., 7) / SET_BIT(..., 7)).
	nonceBBitMask = 1 << 7

	// maxPasswordLen is libRIST's effective PBKDF2 passphrase bound:
	// sizeof(key->password)-1. The passphrase lives in a fixed
	// uint8_t password[128] (psk.h:48) and PBKDF2 runs over password_len bytes,
	// which is strnlen-bounded to the first NUL and capped at 127 (psk.c:38,327).
	maxPasswordLen = 127
)

// DeriveKey derives an AES key from a passphrase and the 4-byte GRE nonce
// salt using PBKDF2-HMAC-SHA256 with RIST's fixed 1024-iteration count
// (psk.c:102-119). keyBits must be 128 or 256; nonce4 must be exactly
// NonceSize bytes. The returned slice has length keyBits/8.
//
// This is a pure function exported for unit testing against published
// PBKDF2-HMAC-SHA256 test vectors so the derivation is independently anchored.
func DeriveKey(password, nonce4 []byte, keyBits int) ([]byte, error) {
	if keyBits != KeySize128 && keyBits != KeySize256 {
		return nil, ErrInvalidKeySize
	}
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	if len(nonce4) != NonceSize {
		return nil, ErrInvalidNonceLength
	}
	// libRIST runs PBKDF2 over key->password for key->password_len bytes,
	// where password_len is the passphrase truncated at the first NUL and
	// capped at 127 (the fixed uint8_t password[128]; psk.h:48, psk.c:38
	// strnlen, psk.c:327 >127 reject). Reproduce that bound so a passphrase
	// with an embedded NUL, or longer than 127 bytes, derives the identical
	// AES key libRIST would (the public Config caps Secret at 127 already, but
	// this keeps the primitive faithful for any caller).
	return pbkdf2.Key(sha256.New, string(boundPassword(password)), nonce4, pbkdf2Iterations, keyBits/8)
}

// boundPassword reproduces libRIST's effective PBKDF2 passphrase: the bytes up
// to the first NUL, then capped at maxPasswordLen (psk.c:38 strnlen, psk.c:327
// >127 reject).
func boundPassword(password []byte) []byte {
	if i := bytes.IndexByte(password, 0); i >= 0 {
		password = password[:i]
	}
	if len(password) > maxPasswordLen {
		password = password[:maxPasswordLen]
	}
	return password
}

// BuildIV constructs the 16-byte AES-CTR initialization vector for a GRE
// packet sequence number: the sequence number big-endian in bytes [0:4],
// then twelve zero bytes (psk.c:227-233, copy_offset==0 for GRE version >=1).
// AES-CTR increments the low bytes, so the per-packet seq in the high bytes
// gives every packet a disjoint keystream window (gre.h:51-53).
func BuildIV(seq uint32) [ivSize]byte {
	var iv [ivSize]byte
	binary.BigEndian.PutUint32(iv[0:4], seq)
	return iv
}

// ctrState is the reusable AES-CTR engine shared by the stateful Key (send)
// and Decryptor (receive) paths. It caches the derived cipher.Block and a
// per-engine keystream scratch block so that, once a key is derived, applying
// the cipher to a packet allocates nothing: the per-call cipher.NewCTR
// allocation of the stdlib stream is avoided by computing the counter-mode
// keystream directly from the cached block (counterCrypt). The keystream is
// byte-identical to crypto/cipher's NewCTR for this IV layout (the full
// 16-byte IV is the big-endian counter, incremented per block), asserted
// directly against the stdlib stream in TestCTRMatchesStdlib.
type ctrState struct {
	block cipher.Block
	ks    [ivSize]byte // reusable keystream block scratch
	ctr   [ivSize]byte // reusable counter scratch (kept off the stack so the
	// interface call to block.Encrypt does not force a per-call heap escape)
}

// Key is a stateful PSK encryptor for one direction of a Main-profile flow.
// It owns the current nonce, the AES cipher derived from it, and the count of
// packets encrypted under it, rotating the nonce and re-deriving when the
// rotation threshold or the reuse limit is reached. It is not safe for
// concurrent use; the host serializes access on a single send path.
type Key struct {
	password    []byte
	keyBits     int
	keyRotation uint32 // 0 = rotate only at reuse-limit exhaustion
	odd         bool

	nonce     [NonceSize]byte
	ctr       ctrState
	usedTimes uint32
}

// NewKey constructs a Key for the given passphrase, AES key size (128 or 256
// bits), and rotation threshold, generating an initial non-zero nonce with
// the correct odd/even B-bit and deriving the first AES key. keyRotation is
// the number of packets to encrypt under one nonce before rotating; 0 selects
// the library default of rotating only when the packet counter would exhaust.
// odd selects which of the two passphrase keys this is (the B-bit marker,
// psk.c:262-264).
func NewKey(password []byte, keyBits, keyRotation int, odd bool) (*Key, error) {
	if keyBits != KeySize128 && keyBits != KeySize256 {
		return nil, ErrInvalidKeySize
	}
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	if keyRotation < 0 {
		return nil, ErrNegativeRotation
	}
	k := &Key{
		password:    append([]byte(nil), password...),
		keyBits:     keyBits,
		keyRotation: uint32(keyRotation),
		odd:         odd,
	}
	if err := k.rekey(); err != nil {
		return nil, err
	}
	return k, nil
}

// Nonce returns the 4-byte GRE nonce currently in force. The host writes it
// into the GRE Key/Nonce field of every packet Encrypt produces under it
// (gre.h:42-49).
func (k *Key) Nonce() [NonceSize]byte {
	return k.nonce
}

// rekey generates a fresh non-zero nonce with the correct B-bit, derives the
// AES cipher from it, and resets the used-times counter (psk.c:235-265,312).
func (k *Key) rekey() error {
	nonce, err := generateNonce(k.odd)
	if err != nil {
		return err
	}
	block, err := deriveBlock(k.password, nonce[:], k.keyBits)
	if err != nil {
		return err
	}
	k.nonce = nonce
	k.ctr.block = block
	k.usedTimes = 0
	return nil
}

// rotateDue reports whether the next Encrypt must rotate the nonce before
// using it: the counter would exhaust the reuse limit, or the user's rotation
// threshold (when positive) has been reached (psk.c:306).
func (k *Key) rotateDue() bool {
	if uint64(k.usedTimes)+1 > uint64(reuseLimit) {
		return true
	}
	return k.keyRotation > 0 && k.usedTimes >= k.keyRotation
}

// Encrypt encrypts len(src) payload bytes for GRE sequence number seq under
// the current (or freshly rotated) key, appending the ciphertext to dst and
// returning the extended slice. Pass dst[:0] to reuse a buffer with no
// allocation once warmed, or a full-length dst aliasing src for in-place
// encryption.
//
// On entry it rotates the nonce and re-derives the key if the rotation
// threshold or reuse limit is due; the caller reads the nonce in force via
// Nonce after the call. AES-CTR is symmetric, so this is the same XOR-stream
// operation as Decrypt (psk.c:302-323).
func (k *Key) Encrypt(seq uint32, dst, src []byte) ([]byte, error) {
	if k.rotateDue() {
		if err := k.rekey(); err != nil {
			return dst, err
		}
	}
	out := k.ctr.crypt(BuildIV(seq), dst, src)
	k.usedTimes++
	return out, nil
}

// Decryptor is the receive-side counterpart of Key: a stateful PSK decryptor
// that re-derives the AES key whenever the inbound GRE nonce differs from the
// one it last keyed on (psk.c:277-287). It holds no rotation policy of its
// own — the sender drives rotation — and is not safe for concurrent use.
type Decryptor struct {
	password []byte
	keyBits  int

	nonce     [NonceSize]byte
	ctr       ctrState
	hasNonce  bool
	usedTimes uint64 // packets decrypted under the current nonce (reuse guard)
}

// NewDecryptor constructs a Decryptor for the given passphrase and AES key
// size (128 or 256 bits). It derives no key until the first packet arrives;
// the inbound nonce on that packet selects the key (and, via its B-bit, the
// odd/even passphrase, which the caller resolves before choosing which
// Decryptor to use).
func NewDecryptor(password []byte, keyBits int) (*Decryptor, error) {
	if keyBits != KeySize128 && keyBits != KeySize256 {
		return nil, ErrInvalidKeySize
	}
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	return &Decryptor{
		password: append([]byte(nil), password...),
		keyBits:  keyBits,
	}, nil
}

// Decrypt decrypts len(src) payload bytes carried under the given inbound GRE
// nonce and sequence number, appending the plaintext to dst and returning the
// extended slice. A zero nonce is rejected with ErrZeroNonce (psk.c:271-275).
// If the nonce differs from the one last keyed on, the AES key is re-derived
// before decrypting (psk.c:277-287). AES-CTR is symmetric, so this is the
// same XOR-stream operation as Key.Encrypt.
func (d *Decryptor) Decrypt(nonce [NonceSize]byte, seq uint32, dst, src []byte) ([]byte, error) {
	if isZeroNonce(nonce) {
		return dst, ErrZeroNonce
	}
	if !d.hasNonce || nonce != d.nonce {
		// Assign the field first, then derive from d.nonce[:]: slicing the
		// value parameter (nonce[:]) would force the whole parameter onto the
		// heap on every call (escape analysis is conservative across the cold
		// rekey branch), defeating the 0-alloc warm path. Slicing the heap
		// field instead keeps the steady-state call allocation-free.
		d.nonce = nonce
		block, err := deriveBlock(d.password, d.nonce[:], d.keyBits)
		if err != nil {
			d.hasNonce = false
			return dst, err
		}
		d.ctr.block = block
		d.hasNonce = true
		d.usedTimes = 0
	}
	// Defense-in-depth: refuse once the packet count under this nonce passes
	// the reuse limit (psk.c:289-292). A conformant sender rotates its nonce —
	// re-deriving the key and resetting this counter — long before here.
	if d.usedTimes > uint64(reuseLimit) {
		return dst, ErrKeyReuseExhausted
	}
	out := d.ctr.crypt(BuildIV(seq), dst, src)
	d.usedTimes++
	return out, nil
}

// Decrypt is a stateless convenience for one-shot decryption: it derives the
// key from the passphrase and nonce and decrypts in a single call, with no
// retained state. Prefer Decryptor for a receive path that processes many
// packets, so the key is re-derived only on nonce changes.
func Decrypt(password []byte, keyBits int, nonce [NonceSize]byte, seq uint32, dst, src []byte) ([]byte, error) {
	if isZeroNonce(nonce) {
		return dst, ErrZeroNonce
	}
	block, err := deriveBlock(password, nonce[:], keyBits)
	if err != nil {
		return dst, err
	}
	state := ctrState{block: block}
	return state.crypt(BuildIV(seq), dst, src), nil
}

// deriveBlock derives the AES key and wraps it in a cipher.Block. It centralizes
// DeriveKey + aes.NewCipher so Key, Decryptor, and the one-shot path agree.
func deriveBlock(password, nonce4 []byte, keyBits int) (cipher.Block, error) {
	derived, err := DeriveKey(password, nonce4, keyBits)
	if err != nil {
		return nil, err
	}
	return aes.NewCipher(derived)
}

// crypt applies AES-CTR with the cached block and the given IV over src,
// appending the result to dst and returning the extended slice. CTR mode is
// symmetric, so this serves both encrypt and decrypt. When dst has capacity
// for len(src) more bytes (e.g. dst[:0] of a warmed buffer) no allocation
// occurs: the keystream is generated block-by-block into the reusable ks
// scratch and XORed in place, so unlike crypto/cipher.NewCTR there is no
// per-call stream allocation. A full-length dst aliasing src is permitted.
//
// The IV is the full 16-byte big-endian counter; it is incremented by one per
// AES block. With BuildIV placing the 32-bit packet sequence number in the
// high four bytes and zeros below, the block counter occupies the low bytes
// and a single packet's keystream never collides with the next packet's
// (gre.h:51-53). This is byte-identical to crypto/cipher.NewCTR for this IV
// layout, asserted directly against the stdlib stream in TestCTRMatchesStdlib
// (and anchored to OpenSSL's aes-ctr output by the golden vectors).
func (s *ctrState) crypt(iv [ivSize]byte, dst, src []byte) []byte {
	n := len(dst)
	dst = growSlice(dst, len(src))
	out := dst[n:]
	s.ctr = iv
	for off := 0; off < len(src); off += ivSize {
		s.block.Encrypt(s.ks[:], s.ctr[:])
		s.incrCounter()
		end := off + ivSize
		if end > len(src) {
			end = len(src)
		}
		for j := off; j < end; j++ {
			out[j] = src[j] ^ s.ks[j-off]
		}
	}
	return dst
}

// incrCounter increments the 16-byte big-endian AES-CTR counter by one,
// matching crypto/cipher's CTR carry order.
func (s *ctrState) incrCounter() {
	for i := ivSize - 1; i >= 0; i-- {
		s.ctr[i]++
		if s.ctr[i] != 0 {
			break
		}
	}
}

// growSlice extends buf by size bytes, reallocating only when capacity is
// insufficient. The added bytes are not zeroed (the caller overwrites them).
// Mirrors internal/rtp.growSlice so the hot path is 0-alloc once warmed.
func growSlice(buf []byte, size int) []byte {
	n := len(buf)
	if cap(buf)-n >= size {
		return buf[: n+size : cap(buf)]
	}
	grown := make([]byte, n+size)
	copy(grown, buf)
	return grown
}

// generateNonce draws a random non-zero 32-bit nonce from crypto/rand and
// stamps the odd/even B-bit into bit 7 of nonce[0] (psk.c:235-265). A zero
// draw is retried; persistent failure surfaces ErrCSPRNG (fail closed,
// psk.c:236-258).
func generateNonce(odd bool) ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	for attempts := 0; attempts < 8; attempts++ {
		if _, err := rand.Read(nonce[:]); err != nil {
			return [NonceSize]byte{}, errors.Join(ErrCSPRNG, err)
		}
		// Apply the B-bit before the zero check so a value that is non-zero
		// only because of the marker bit is still rejected here, matching
		// libRIST's order (it checks nonce_val before setting the bit;
		// psk.c:248,262). We clear then optionally set, then test the raw
		// four bytes.
		if binary.BigEndian.Uint32(nonce[:]) != 0 {
			setBBit(&nonce, odd)
			return nonce, nil
		}
	}
	return [NonceSize]byte{}, ErrCSPRNG
}

// setBBit clears bit 7 of nonce[0] and, for the odd passphrase, sets it
// (psk.c:262-264).
func setBBit(nonce *[NonceSize]byte, odd bool) {
	nonce[nonceBBitByte] &^= nonceBBitMask
	if odd {
		nonce[nonceBBitByte] |= nonceBBitMask
	}
}

// isZeroNonce reports whether all four nonce bytes are zero (psk.c:272).
func isZeroNonce(nonce [NonceSize]byte) bool {
	return binary.BigEndian.Uint32(nonce[:]) == 0
}
