package ristgo_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	ristgo "github.com/zsiec/ristgo"
)

// splitMergeConfig returns a fast config for profile with split=auto on the sender
// and merge=pairs on the receiver (the same Config drives both ends in these tests).
func splitMergeConfig(profile ristgo.Profile, secret string) ristgo.Config {
	cfg := ristgo.DefaultConfig()
	cfg.Profile = profile
	cfg.BufferMin = 120 * time.Millisecond
	cfg.BufferMax = 120 * time.Millisecond
	cfg.Secret = secret
	cfg.SplitMode = ristgo.SplitAuto
	cfg.MergeMode = ristgo.MergePairs
	return cfg
}

// runSplitMerge streams N TS-aligned chunks through a split sender to a merge
// receiver and asserts every chunk arrives once, whole, and byte-exact — i.e. the
// pair was recombined (an unmerged stream would surface half-size reads). dialPort
// chooses the receiver address family per profile.
func runSplitMerge(t *testing.T, cfg ristgo.Config, addr string) {
	t.Helper()
	const n = 64
	const chunk = 7 * 188 // 1316, TS-aligned so split=auto uses the MPEG-TS boundary

	rx, err := ristgo.NewReceiver(addr, cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	chunks := make([][]byte, n)
	for i := range chunks {
		c := make([]byte, chunk)
		if _, err := rand.Read(c); err != nil {
			t.Fatalf("rand: %v", err)
		}
		c[0] = 0x47 // MPEG-TS sync byte
		chunks[i] = c
	}

	done := make(chan error, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 4096)
		for i := 0; i < n; i++ {
			m, rerr := rx.Read(buf)
			if rerr != nil {
				done <- fmt.Errorf("read %d: %w", i, rerr)
				return
			}
			// A merged pair is one whole chunk; a half-size read means the merge did
			// not recombine the split pair.
			if m != chunk {
				done <- fmt.Errorf("read %d returned %d bytes, want %d (split pair not merged)", i, m, chunk)
				return
			}
			if !bytes.Equal(buf[:m], chunks[i]) {
				done <- fmt.Errorf("read %d payload mismatch", i)
				return
			}
		}
		done <- nil
	}()

	tx.SetWriteDeadline(time.Now().Add(10 * time.Second))
	for i := 0; i < n; i++ {
		if _, werr := tx.Write(chunks[i]); werr != nil {
			t.Fatalf("write %d: %v", i, werr)
		}
		time.Sleep(2 * time.Millisecond)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("split/merge round trip: %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("timed out waiting for the merged stream")
	}
}

func TestE2ESplitMergeSimple(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeEvenPort(t))
	runSplitMerge(t, splitMergeConfig(ristgo.ProfileSimple, ""), addr)
}

func TestE2ESplitMergeMain(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	runSplitMerge(t, splitMergeConfig(ristgo.ProfileMain, ""), addr)
}

func TestE2ESplitMergeMainAES(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	cfg := splitMergeConfig(ristgo.ProfileMain, "split-secret")
	cfg.AESKeyBits = 256
	runSplitMerge(t, cfg, addr)
}

func TestE2ESplitMergeAdvanced(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	runSplitMerge(t, splitMergeConfig(ristgo.ProfileAdvanced, ""), addr)
}

func TestE2ESplitMergeBondedMain(t *testing.T) {
	const n = 64
	const chunk = 7 * 188
	pA := freeEvenPort(t)
	pB := freeEvenPort(t)
	for pB == pA || pB == pA+1 {
		pB = freeEvenPort(t)
	}
	addrs := []string{fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)}
	cfg := splitMergeConfig(ristgo.ProfileMain, "")

	rx, err := ristgo.NewBondedReceiver(addrs, cfg)
	if err != nil {
		t.Fatalf("NewBondedReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewBondedSender(addrs, cfg)
	if err != nil {
		t.Fatalf("NewBondedSender: %v", err)
	}
	defer tx.Close()

	chunks := make([][]byte, n)
	for i := range chunks {
		c := make([]byte, chunk)
		if _, err := rand.Read(c); err != nil {
			t.Fatalf("rand: %v", err)
		}
		c[0] = 0x47
		chunks[i] = c
	}

	done := make(chan error, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(15 * time.Second))
		buf := make([]byte, 4096)
		for i := 0; i < n; i++ {
			m, rerr := rx.Read(buf)
			if rerr != nil {
				done <- fmt.Errorf("read %d: %w", i, rerr)
				return
			}
			if m != chunk || !bytes.Equal(buf[:m], chunks[i]) {
				done <- fmt.Errorf("bonded read %d: %d bytes (merge or dedup failed)", i, m)
				return
			}
		}
		done <- nil
	}()

	tx.SetWriteDeadline(time.Now().Add(15 * time.Second))
	for i := 0; i < n; i++ {
		if _, werr := tx.Write(chunks[i]); werr != nil {
			t.Fatalf("bonded write %d: %v", i, werr)
		}
		time.Sleep(3 * time.Millisecond)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("bonded split/merge round trip: %v", err)
		}
	case <-time.After(18 * time.Second):
		t.Fatal("timed out waiting for the bonded merged stream")
	}
}

// runMergeAuto streams n split chunks through a merge=auto receiver and asserts the
// steady-state invariant: merge=auto stays dormant until the sender advertises
// pair-split (the keepalive L bit), so before it engages a pair may arrive as two
// orphan halves and after it engages the pair merges — but the concatenated output
// byte stream always equals the concatenated input, and at least one whole chunk
// merges (proving auto engaged). Tolerates startup orphans.
func runMergeAuto(t *testing.T, cfg ristgo.Config, addr string) {
	t.Helper()
	const n = 64
	const chunk = 7 * 188
	cfg.MergeMode = ristgo.MergeAuto

	rx, err := ristgo.NewReceiver(addr, cfg)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	defer rx.Close()
	tx, err := ristgo.NewSender(addr, cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer tx.Close()

	want := make([]byte, 0, n*chunk)
	chunks := make([][]byte, n)
	for i := range chunks {
		c := make([]byte, chunk)
		if _, err := rand.Read(c); err != nil {
			t.Fatalf("rand: %v", err)
		}
		c[0] = 0x47
		chunks[i] = c
		want = append(want, c...)
	}

	done := make(chan error, 1)
	go func() {
		rx.SetReadDeadline(time.Now().Add(12 * time.Second))
		buf := make([]byte, 4096)
		got := make([]byte, 0, len(want))
		mergedAny := false
		for len(got) < len(want) {
			m, rerr := rx.Read(buf)
			if rerr != nil {
				done <- fmt.Errorf("read: %w", rerr)
				return
			}
			if m == chunk {
				mergedAny = true // a full pair recombined
			}
			got = append(got, buf[:m]...)
		}
		if !bytes.Equal(got, want) {
			done <- fmt.Errorf("merge=auto byte stream diverged")
			return
		}
		if !mergedAny {
			done <- fmt.Errorf("merge=auto never engaged (no pair merged off the L bit)")
			return
		}
		done <- nil
	}()

	tx.SetWriteDeadline(time.Now().Add(12 * time.Second))
	for i := 0; i < n; i++ {
		if _, werr := tx.Write(chunks[i]); werr != nil {
			t.Fatalf("write %d: %v", i, werr)
		}
		time.Sleep(3 * time.Millisecond)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("merge=auto: %v", err)
		}
	case <-time.After(14 * time.Second):
		t.Fatal("timed out")
	}
}

func TestE2EMergeAutoMain(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	runMergeAuto(t, splitMergeConfig(ristgo.ProfileMain, ""), addr)
}

func TestE2EMergeAutoAdvanced(t *testing.T) {
	// The Advanced session advertises pair-split via a GRE-substrate keepalive (gated
	// on split being active); the receiver reads its L bit and enables merge=auto.
	addr := fmt.Sprintf("127.0.0.1:%d", freeMainPort(t))
	runMergeAuto(t, splitMergeConfig(ristgo.ProfileAdvanced, ""), addr)
}
