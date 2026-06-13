package adv

import "testing"

// FuzzParseControl feeds arbitrary bytes to ParseControl and every per-index
// body parser. None may panic; on a successful ParseControl the body must lie
// within the input.
func FuzzParseControl(f *testing.F) {
	seeds := [][]byte{
		nil,
		{0x00},
		{0x00, 0x00, 0x00},
		BuildNackBitmask(nil, NackBitmask{MediaSSRC: 1, PSS: 2, BLP: 3}),
		BuildNackRange(nil, NackRange{MediaSSRC: 1, PSS: 2, NALP: 3}),
		BuildRTTEchoRequest(nil, RTTEchoFromTimestamp(1, 2, 0)),
		BuildKeepalive(nil, Keepalive{Caps: KeepaliveCapI}),
		BuildPSKNonce(nil, PSKNonce{KeyBits: 256}),
		BuildControl(nil, CIUnsupported, make([]byte, 16)),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		ci, body, err := ParseControl(data)
		if err != nil {
			return
		}
		if len(body) > len(data) {
			t.Fatalf("body longer than input: %d > %d", len(body), len(data))
		}
		// Dispatch to every body parser regardless of CI — none may panic on a
		// body of any length.
		_, _ = ParseNackBitmask(body)
		_, _ = ParseNackRange(body)
		_, _ = ParseRTTEcho(body)
		_, _ = ParseKeepalive(body)
		_, _ = ParsePSKNonce(body)

		// A well-formed body for the announced CI must round-trip its Missing
		// expansion without panicking (the decode cap bounds the allocation).
		switch ci {
		case CINackBitmask:
			if n, e := ParseNackBitmask(body); e == nil {
				_ = n.Missing()
			}
		case CINackRange:
			if n, e := ParseNackRange(body); e == nil {
				_ = n.Missing()
			}
		}
	})
}
