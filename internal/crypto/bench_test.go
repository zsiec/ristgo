package crypto

import "testing"

// benchPayload is a representative RIST media payload: seven 188-byte MPEG-TS
// cells, the typical RTP-over-GRE encrypted body.
var benchPayload = make([]byte, 7*188)

// TestEncryptZeroAlloc is the allocation gate for the warmed encrypt hot path:
// encrypting into a reused dst[:0] buffer with sufficient capacity must not
// allocate.
func TestEncryptZeroAlloc(t *testing.T) {
	k, err := NewKey([]byte("bench-secret"), KeySize128, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 0, len(benchPayload))
	var seq uint32
	if allocs := testing.AllocsPerRun(1000, func() {
		seq++
		out, err := k.Encrypt(seq, dst[:0], benchPayload)
		if err != nil {
			t.Fatal(err)
		}
		_ = out
	}); allocs != 0 {
		t.Errorf("Key.Encrypt (warmed dst) allocates %v times per op, want 0", allocs)
	}
}

// TestDecryptZeroAlloc is the allocation gate for the warmed decrypt hot path:
// the Decryptor reuses its derived key (no rekey when the nonce is stable) and
// writes into a reused dst[:0] buffer, so it must not allocate.
func TestDecryptZeroAlloc(t *testing.T) {
	k, err := NewKey([]byte("bench-secret"), KeySize128, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := k.Encrypt(1, nil, benchPayload)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDecryptor([]byte("bench-secret"), KeySize128)
	if err != nil {
		t.Fatal(err)
	}
	nonce := k.Nonce()
	// Prime the Decryptor so the first measured run does not re-derive.
	if _, err := d.Decrypt(nonce, 1, nil, ct); err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 0, len(ct))
	if allocs := testing.AllocsPerRun(1000, func() {
		out, err := d.Decrypt(nonce, 1, dst[:0], ct)
		if err != nil {
			t.Fatal(err)
		}
		_ = out
	}); allocs != 0 {
		t.Errorf("Decryptor.Decrypt (warmed) allocates %v times per op, want 0", allocs)
	}
}

func BenchmarkEncrypt128(b *testing.B) {
	benchmarkEncrypt(b, KeySize128)
}

func BenchmarkEncrypt256(b *testing.B) {
	benchmarkEncrypt(b, KeySize256)
}

func benchmarkEncrypt(b *testing.B, keyBits int) {
	k, err := NewKey([]byte("bench-secret"), keyBits, 0, false)
	if err != nil {
		b.Fatal(err)
	}
	dst := make([]byte, 0, len(benchPayload))
	b.SetBytes(int64(len(benchPayload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := k.Encrypt(uint32(i), dst[:0], benchPayload)
		if err != nil {
			b.Fatal(err)
		}
		_ = out
	}
}

func BenchmarkDeriveKey256(b *testing.B) {
	password := []byte("bench-secret")
	nonce := []byte{0x12, 0x34, 0x56, 0x78}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DeriveKey(password, nonce, KeySize256); err != nil {
			b.Fatal(err)
		}
	}
}
