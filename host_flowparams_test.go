package ristgo

import (
	"errors"
	"testing"
)

// TestBuildMainFlowParamsFailsClosed pins the fail-closed invariant every Main
// receiver path relies on (single-flow and multiplexed): when EAP-SRP credentials
// are configured and the per-flow salt/key derivation fails, buildMainFlowParams
// returns an error so the caller drops the flow, rather than handing back params
// with a nil authenticator. A nil authenticator would leave the session authed by
// default and deliver unauthenticated media (fail open) -- the exact regression the
// factory error handling exists to prevent.
func TestBuildMainFlowParamsFailsClosed(t *testing.T) {
	orig := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("forced rand failure") }
	defer func() { randRead = orig }()

	cfg := DefaultConfig()
	cfg.Profile = ProfileMain
	cfg.Username = "rist"
	cfg.Password = "secret"

	mp, err := buildMainFlowParams(cfg)
	if err == nil {
		t.Fatal("buildMainFlowParams returned a nil error on a salt-derivation failure; a flow would be installed fail-open")
	}
	if mp != nil {
		t.Fatal("buildMainFlowParams returned non-nil params on failure; want nil so no session is built")
	}
}

// TestBuildMainFlowParamsInstallsAuthenticator verifies that configuring EAP-SRP
// credentials yields a non-nil authenticator, so the session gates delivery on the
// handshake instead of defaulting open.
func TestBuildMainFlowParamsInstallsAuthenticator(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Profile = ProfileMain
	cfg.Username = "rist"
	cfg.Password = "secret"

	mp, err := buildMainFlowParams(cfg)
	if err != nil {
		t.Fatalf("buildMainFlowParams: %v", err)
	}
	if mp.EAPServer == nil {
		t.Fatal("EAP credentials configured but EAPServer is nil; the session would start authed (fail open)")
	}
}

// TestBuildMainFlowParamsCleartextNoAuthenticator documents the legitimately-open
// case: with no credentials and no secret a Main flow is cleartext and unauthed by
// design, so EAPServer and the PSK key state are both nil.
func TestBuildMainFlowParamsCleartextNoAuthenticator(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Profile = ProfileMain

	mp, err := buildMainFlowParams(cfg)
	if err != nil {
		t.Fatalf("buildMainFlowParams: %v", err)
	}
	if mp.EAPServer != nil {
		t.Fatal("no credentials configured but EAPServer is non-nil")
	}
	if mp.SendKey != nil || mp.RecvKey != nil {
		t.Fatal("no secret configured but PSK key state was installed")
	}
}

// TestBuildMainFlowParamsFreshKeysPerFlow pins per-flow PSK isolation: each call
// mints its own stateful key/decryptor, so two demultiplexed flows never share one
// cipher. A shared crypto.Key would race and reuse IVs across distinct encrypted
// streams (the bonded-path bug the factory rework closed).
func TestBuildMainFlowParamsFreshKeysPerFlow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Profile = ProfileMain
	cfg.Secret = "ristgo-psk-secret"
	cfg.AESKeyBits = 128

	a, err := buildMainFlowParams(cfg)
	if err != nil {
		t.Fatalf("buildMainFlowParams a: %v", err)
	}
	b, err := buildMainFlowParams(cfg)
	if err != nil {
		t.Fatalf("buildMainFlowParams b: %v", err)
	}
	if a.SendKey == nil || b.SendKey == nil {
		t.Fatal("PSK secret configured but SendKey is nil")
	}
	if a.SendKey == b.SendKey {
		t.Fatal("two flows share one SendKey instance; per-flow cipher state must be independent")
	}
	if a.RecvKey == b.RecvKey {
		t.Fatal("two flows share one RecvKey instance; per-flow cipher state must be independent")
	}
}
