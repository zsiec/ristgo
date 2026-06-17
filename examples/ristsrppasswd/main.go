// Command ristsrppasswd generates an EAP-SRP verifier line for the RIST Main
// profile, in the same format as libRIST's ristsrppasswd tool:
//
//	username:base64(verifier):base64(salt):3:1
//
// The trailing fields are the SRP hash version (3 = RFC 5054 PAD-compliant,
// EAPOL v3) and the correct-hashing flag (1). The line is what an EAP-SRP
// authenticator's verifier lookup consumes to authenticate a user without
// storing the plaintext password. The verifier is v = g^x mod N with
// x = H(salt | H(username ":" password)); minimal big-endian bytes, matching
// libRIST, so the files are interchangeable.
//
// Usage:
//
//	ristsrppasswd <username> <password> [salt-hex]
//
// A 32-byte random salt is generated unless an explicit hex salt is given (the
// explicit form is deterministic, for testing / reproducible provisioning).
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/zsiec/ristgo/internal/srp"
)

func main() {
	if len(os.Args) != 3 && len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s <username> <password> [salt-hex]\n", os.Args[0])
		os.Exit(2)
	}
	username, password := os.Args[1], os.Args[2]

	salt := make([]byte, 32) // libRIST uses a 32-byte random salt
	if len(os.Args) == 4 {
		s, err := hex.DecodeString(os.Args[3])
		if err != nil || len(s) == 0 {
			fmt.Fprintf(os.Stderr, "ristsrppasswd: invalid salt hex\n")
			os.Exit(2)
		}
		salt = s
	} else if _, err := rand.Read(salt); err != nil {
		fmt.Fprintf(os.Stderr, "ristsrppasswd: CSPRNG unavailable: %v\n", err)
		os.Exit(1)
	}

	verifier := srp.MakeVerifier(srp.DefaultGroup(), username, password, salt)
	if len(verifier) == 0 {
		fmt.Fprintf(os.Stderr, "ristsrppasswd: could not create verifier (empty credentials?)\n")
		os.Exit(1)
	}
	b64 := base64.StdEncoding
	fmt.Printf("%s:%s:%s:3:1\n", username, b64.EncodeToString(verifier), b64.EncodeToString(salt))
}
