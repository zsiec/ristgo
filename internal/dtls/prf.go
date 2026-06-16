package dtls

import (
	"crypto/hmac"
	"hash"
)

// The TLS 1.2 pseudo-random function (RFC 5246 §5), used by DTLS 1.2 unchanged.
// It is parametrized by the negotiated suite's hash (newHash): P_SHA256 for the
// *_SHA256 suites, P_SHA384 for the *_SHA384 suites.

// PRF labels (RFC 5246 §8.1, §7.4.9; RFC 7627 §4).
const (
	labelMasterSecret         = "master secret"
	labelExtendedMasterSecret = "extended master secret"
	labelKeyExpansion         = "key expansion"
	labelClientFinished       = "client finished"
	labelServerFinished       = "server finished"
)

// prf computes PRF(secret, label, seed) truncated to length bytes for the suite's
// hash: PRF = P_hash(secret, label || seed) (RFC 5246 §5).
func prf(newHash func() hash.Hash, secret []byte, label string, seed []byte, length int) []byte {
	labelAndSeed := make([]byte, 0, len(label)+len(seed))
	labelAndSeed = append(labelAndSeed, label...)
	labelAndSeed = append(labelAndSeed, seed...)
	return pHash(newHash, secret, labelAndSeed, length)
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
func masterSecret(newHash func() hash.Hash, preMaster, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)
	return prf(newHash, preMaster, labelMasterSecret, seed, masterSecretLength)
}

// extendedMasterSecret derives the 48-byte master secret using the session hash
// (the running handshake transcript hash through ClientKeyExchange) instead of
// the raw randoms (RFC 7627 §4). It is used when both peers advertised the
// extended_master_secret extension.
func extendedMasterSecret(newHash func() hash.Hash, preMaster, sessionHash []byte) []byte {
	return prf(newHash, preMaster, labelExtendedMasterSecret, sessionHash, masterSecretLength)
}

// finishedVerifyData computes the 12-byte Finished verify_data over the
// handshake transcript hash (RFC 5246 §7.4.9). label is labelClientFinished or
// labelServerFinished depending on which side's Finished this is.
func finishedVerifyData(newHash func() hash.Hash, master []byte, label string, transcript []byte) []byte {
	return prf(newHash, master, label, transcript, finishedVerifyDataLength)
}

const (
	// masterSecretLength is the fixed master-secret size (RFC 5246 §8.1).
	masterSecretLength = 48
	// finishedVerifyDataLength is the Finished verify_data size for all suites
	// here (RFC 5246 §7.4.9: verify_data_length defaults to 12).
	finishedVerifyDataLength = 12
)
