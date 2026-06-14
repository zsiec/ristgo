package dtls

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// The TLS 1.2 pseudo-random function (RFC 5246 §5), used by DTLS 1.2 unchanged.
// Every cipher suite this package supports uses SHA-256, so the PRF is fixed to
// P_SHA256 rather than parameterized by the suite's hash.

// PRF labels (RFC 5246 §8.1, §7.4.9; RFC 7627 §4).
const (
	labelMasterSecret         = "master secret"
	labelExtendedMasterSecret = "extended master secret"
	labelKeyExpansion         = "key expansion"
	labelClientFinished       = "client finished"
	labelServerFinished       = "server finished"
)

// prf computes PRF(secret, label, seed) truncated to length bytes, with the hash
// fixed to SHA-256: PRF = P_SHA256(secret, label || seed) (RFC 5246 §5).
func prf(secret []byte, label string, seed []byte, length int) []byte {
	labelAndSeed := make([]byte, 0, len(label)+len(seed))
	labelAndSeed = append(labelAndSeed, label...)
	labelAndSeed = append(labelAndSeed, seed...)
	return pHash(sha256.New, secret, labelAndSeed, length)
}

// pHash is the P_hash construction (RFC 5246 §5):
//
//	A(0) = seed
//	A(i) = HMAC_hash(secret, A(i-1))
//	P_hash = HMAC(secret, A(1)+seed) || HMAC(secret, A(2)+seed) || ...
//
// truncated to length bytes.
func pHash(newHash func() hash.Hash, secret, seed []byte, length int) []byte {
	out := make([]byte, 0, length)

	// a holds A(i); start at A(1) = HMAC(secret, A(0)=seed).
	a := hmacSum(newHash, secret, seed)
	for len(out) < length {
		// HMAC(secret, A(i) || seed).
		h := hmac.New(newHash, secret)
		h.Write(a)
		h.Write(seed)
		out = h.Sum(out)
		// A(i+1) = HMAC(secret, A(i)).
		a = hmacSum(newHash, secret, a)
	}
	return out[:length]
}

// hmacSum returns HMAC_hash(key, data).
func hmacSum(newHash func() hash.Hash, key, data []byte) []byte {
	h := hmac.New(newHash, key)
	h.Write(data)
	return h.Sum(nil)
}

// masterSecret derives the 48-byte master secret from the pre-master secret and
// the client/server randoms (RFC 5246 §8.1).
func masterSecret(preMaster, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)
	return prf(preMaster, labelMasterSecret, seed, masterSecretLength)
}

// extendedMasterSecret derives the 48-byte master secret using the session hash
// (the running handshake transcript hash through ClientKeyExchange) instead of
// the raw randoms (RFC 7627 §4). It is used when both peers advertised the
// extended_master_secret extension.
func extendedMasterSecret(preMaster, sessionHash []byte) []byte {
	return prf(preMaster, labelExtendedMasterSecret, sessionHash, masterSecretLength)
}

// finishedVerifyData computes the 12-byte Finished verify_data over the
// handshake transcript hash (RFC 5246 §7.4.9). label is labelClientFinished or
// labelServerFinished depending on which side's Finished this is.
func finishedVerifyData(master []byte, label string, transcript []byte) []byte {
	return prf(master, label, transcript, finishedVerifyDataLength)
}

const (
	// masterSecretLength is the fixed master-secret size (RFC 5246 §8.1).
	masterSecretLength = 48
	// finishedVerifyDataLength is the Finished verify_data size for all suites
	// here (RFC 5246 §7.4.9: verify_data_length defaults to 12).
	finishedVerifyDataLength = 12
)
