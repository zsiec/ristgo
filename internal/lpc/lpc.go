// Package lpc implements the LZ4 block-format codec used by the RIST Advanced
// Profile for payload compression (Layer Payload Compression, LPC=1 = LZ4;
// libRIST src/proto/adv.h:210, RIST_ADV_LPC_LZ4).
//
// libRIST compresses and decompresses Advanced-Profile payloads with the raw
// LZ4 *block* format (NOT the LZ4 frame format): the send path calls
// LZ4_compress_default (src/udp.c) and the receive path calls
// LZ4_decompress_safe with an external, known decompressed bound
// (src/rist-common.c:2855, bound RIST_MAX_PACKET_SIZE). The block carries no
// length header, no magic number, and no checksum — the decompressor relies on
// the caller-supplied output bound to detect overruns. This package mirrors
// that: Compress emits a raw LZ4 block and Decompress decodes one against a
// maximum-output bound.
//
// # LZ4 block format
//
// A block is a sequence of "sequences". Each sequence is:
//
//	token byte: high nibble = literal length, low nibble = (match length − 4)
//	[extra literal-length bytes, if the high nibble is 15: each 0..255 is
//	 added to the literal length until a byte < 255 is seen]
//	literals: that many raw bytes, copied verbatim to the output
//	2-byte little-endian match offset (a distance back into the output)
//	[extra match-length bytes, if the low nibble is 15: same 255-continuation
//	 rule, added to the base match length of (low nibble + 4)]
//	a back-reference copy of (match length) bytes from (output − offset)
//
// The match length is MINMATCH (4) plus the low nibble plus any extras, so the
// shortest encodable match is 4 bytes. The final sequence in a block is
// literals-only: it has a token and literals but no offset and no match, and
// the block ends immediately after those literals. Match offsets are 1..65535
// and must refer back into the already-produced output. A back-reference may
// overlap the bytes it is producing (offset < match length), which yields a
// run-length expansion; Decompress copies one byte at a time so overlap works.
//
// This implementation ports the published LZ4 block format (the algorithm of
// Yann Collet's reference lz4, BSD 2-Clause; see NOTICE.md). The match finder
// is the simple LZ4 "fast" single-table variant — its parameters affect only
// compression ratio, never decodability: every block this package emits is a
// valid LZ4 block decodable by libRIST, and Decompress decodes any valid LZ4
// block including those libRIST produces.
//
// # Purity and safety
//
// The package is pure: it does no I/O, reads no clock, spawns no goroutine, and
// never panics. Malformed, truncated, or hostile input to Decompress returns an
// error and never reads or writes out of bounds (a fuzz target enforces this).
package lpc

import (
	"encoding/binary"
	"errors"
)

// Sentinel errors returned by Decompress. Callers should test for them with
// errors.Is; returned errors may wrap these with additional context.
var (
	// ErrCorrupt is returned by Decompress when the block is malformed: a
	// length field or offset runs past the input, or a literal/match copy
	// would read before the start of the produced output. It never indicates
	// a bug in this package, only a bad block.
	ErrCorrupt = errors.New("rist: lpc: corrupt LZ4 block")

	// ErrOutputTooLarge is returned by Decompress when the decoded output
	// would exceed the caller-supplied maxOut bound. Because the LZ4 block
	// format carries no decompressed length, the caller must supply the
	// bound (libRIST uses RIST_MAX_PACKET_SIZE; src/rist-common.c:2857).
	ErrOutputTooLarge = errors.New("rist: lpc: decompressed output exceeds maximum")
)

const (
	// minMatch is the LZ4 MINMATCH: the shortest encodable match length. The
	// match-length nibble encodes (length − minMatch).
	minMatch = 4

	// lastLiterals is the number of trailing input bytes that the LZ4 block
	// format requires to be emitted as literals (a match may not end inside
	// the final 5 bytes), and mfLimit is the position past which the match
	// finder stops looking for new matches. These are reference-lz4 invariants
	// that keep emitted blocks decodable.
	lastLiterals = 5
	mfLimit      = minMatch + lastLiterals

	// minLength is the smallest input the match finder will scan; shorter
	// inputs are emitted as a single literals-only sequence.
	minLength = mfLimit + 1

	// hashLog sizes the match-finder hash table (1<<hashLog entries). 12 gives
	// a 4096-entry / 16 KB table: ample for RIST's MTU-bounded payloads (the
	// Advanced-Profile LPC input is at most one packet) while small enough to
	// keep Compress off the heap. (Reference lz4 scales the table to the input;
	// it never affects decodability, only ratio.)
	hashLog = 12
	// hashTableSize is the number of entries in the match-finder hash table.
	hashTableSize = 1 << hashLog

	// runMask is the maximum value a length nibble can hold before extra
	// continuation bytes are required, and the value those bytes continue on.
	runMask = 15
	// maxOffset is the largest representable match offset (the 2-byte LE
	// offset field), so back-references reach at most 65535 bytes back.
	maxOffset = 65535
)

// CompressBound returns the maximum number of bytes a block produced by
// Compress can occupy for an input of n bytes. It matches LZ4_compressBound:
// n + n/255 + 16. The result is 0 for a negative n (LZ4 treats oversized or
// negative inputs as uncompressible).
func CompressBound(n int) int {
	if n < 0 {
		return 0
	}
	return n + n/255 + 16
}

// Compress appends the LZ4-block encoding of src to dst and returns the
// extended slice. The returned block is a valid LZ4 block: Decompress and
// libRIST's LZ4_decompress_safe both decode it back to src. Compress never
// fails for any src (the empty input encodes as a single empty literals-only
// sequence, a single zero token byte).
//
// dst may be nil. To reuse a buffer across calls, pass dst[:0] with capacity at
// least CompressBound(len(src)).
func Compress(dst, src []byte) ([]byte, error) {
	// Reserve worst-case capacity once so the literal/match emit loop never
	// reallocates mid-block.
	if cap(dst)-len(dst) < CompressBound(len(src)) {
		grown := make([]byte, len(dst), len(dst)+CompressBound(len(src)))
		copy(grown, dst)
		dst = grown
	}

	// Inputs too short to host a match are emitted as a single literals-only
	// sequence. This also covers the empty input.
	if len(src) < minLength {
		return emitLastLiterals(dst, src), nil
	}

	var table [hashTableSize]int32
	// Sentinel: -1 means "no position recorded for this hash yet". Distinguishing
	// the empty slot from real position 0 avoids a false match at the start.
	for i := range table {
		table[i] = -1
	}

	// anchor marks the first not-yet-emitted literal byte. ip is the current
	// scan position. matchLimit is the last position a match may end at: the
	// final lastLiterals bytes must stay literals.
	anchor := 0
	ip := 0
	matchLimit := len(src) - lastLiterals
	// The match finder reads a 4-byte word at ip+1 when advancing, so it must
	// stop mfLimit bytes from the end.
	searchLimit := len(src) - mfLimit

	// Prime the table with the first position.
	table[hash(load32(src, ip))] = int32(ip)
	ip++

	for ip <= searchLimit {
		h := hash(load32(src, ip))
		ref := int(table[h])
		table[h] = int32(ip)

		// A candidate matches only if it is in range, references the same
		// 4-byte word, and lies within the 65535-byte offset window.
		if ref < 0 || ip-ref > maxOffset || load32(src, ref) != load32(src, ip) {
			ip++
			continue
		}

		// Extend the match forward as far as the data and matchLimit allow.
		mEnd := ip + minMatch
		rEnd := ref + minMatch
		for mEnd < matchLimit && src[mEnd] == src[rEnd] {
			mEnd++
			rEnd++
		}
		matchLen := mEnd - ip

		// Emit the literals run [anchor, ip) followed by the match token.
		litLen := ip - anchor
		dst = emitSequence(dst, src[anchor:ip], litLen, ip-ref, matchLen)

		// Advance past the match and reset the literal anchor.
		ip = mEnd
		anchor = ip

		// Record a hash for the position just before the new ip so an
		// immediately following overlapping repeat is still discoverable, then
		// resume scanning from ip at the top of the loop, where ref is read
		// fresh. (We must NOT overwrite table[hash(ip)] here, or the next
		// iteration would read its own position back as the candidate and emit
		// a zero offset.)
		if ip-1 >= 0 && ip-1 <= searchLimit {
			table[hash(load32(src, ip-1))] = int32(ip - 1)
		}
	}

	// Whatever is left after the last match is the trailing literals run.
	return emitLastLiterals(dst, src[anchor:]), nil
}

// emitSequence appends one full LZ4 sequence: the token, any extra
// literal-length bytes, the literal bytes, the 2-byte offset, and any extra
// match-length bytes. litLen is len(literals); offset is the match distance;
// matchLen is the full match length (>= minMatch).
func emitSequence(dst, literals []byte, litLen, offset, matchLen int) []byte {
	mtok := matchLen - minMatch

	// Token: literal-length nibble in the high nibble, match nibble in the low.
	var token byte
	if litLen >= runMask {
		token = runMask << 4
	} else {
		token = byte(litLen) << 4
	}
	if mtok >= runMask {
		token |= runMask
	} else {
		token |= byte(mtok)
	}
	dst = append(dst, token)

	// Extra literal-length bytes (255-continuation), then the literals.
	if litLen >= runMask {
		dst = appendLength(dst, litLen-runMask)
	}
	dst = append(dst, literals...)

	// Little-endian offset.
	dst = append(dst, byte(offset), byte(offset>>8))

	// Extra match-length bytes (255-continuation).
	if mtok >= runMask {
		dst = appendLength(dst, mtok-runMask)
	}
	return dst
}

// emitLastLiterals appends a literals-only terminating sequence: a token whose
// match nibble is 0 (and is ignored, there being no match) and whose literal
// nibble plus continuation bytes encode len(literals), followed by the
// literals. The empty input produces a single 0x00 token.
func emitLastLiterals(dst, literals []byte) []byte {
	litLen := len(literals)
	if litLen >= runMask {
		dst = append(dst, runMask<<4)
		dst = appendLength(dst, litLen-runMask)
	} else {
		dst = append(dst, byte(litLen)<<4)
	}
	return append(dst, literals...)
}

// appendLength appends the LZ4 variable-length continuation encoding of n
// (n >= 0): full 0xFF bytes for each 255, then the remainder. A remainder of 0
// after some 0xFF bytes still emits a trailing 0x00, exactly as reference lz4
// does, so the decoder's "stop on byte < 255" rule terminates.
func appendLength(dst []byte, n int) []byte {
	for n >= 255 {
		dst = append(dst, 255)
		n -= 255
	}
	return append(dst, byte(n))
}

// Decompress decodes the LZ4 block in src, appending the decoded bytes to dst,
// and returns the extended slice. At most maxOut bytes are produced: if the
// block would decode to more than maxOut bytes, Decompress returns
// ErrOutputTooLarge. Because the LZ4 block format carries no length, the caller
// supplies maxOut as the decompressed bound — mirroring libRIST, which passes
// RIST_MAX_PACKET_SIZE to LZ4_decompress_safe (src/rist-common.c:2857).
//
// Decompress never panics and never reads or writes out of bounds. Any
// malformed block — a truncated length or literal run, an offset that points
// before the produced output, or a match that overruns the input or the bound —
// returns ErrCorrupt (or ErrOutputTooLarge). A negative maxOut is treated as 0.
//
// An empty src is a valid empty block and decodes to no bytes (dst unchanged).
func Decompress(dst, src []byte, maxOut int) ([]byte, error) {
	if maxOut < 0 {
		maxOut = 0
	}
	// outStart is where this block's output begins; back-references may not
	// reach before it. Pre-grow dst by maxOut so the copy loop never grows the
	// slice and back-references stay within a stable backing array.
	outStart := len(dst)
	if cap(dst)-outStart < maxOut {
		grown := make([]byte, outStart, outStart+maxOut)
		copy(grown, dst)
		dst = grown
	}
	out := dst[:outStart]

	sp := 0 // read cursor into src
	n := len(src)

	for sp < n {
		token := src[sp]
		sp++

		// --- literals ---
		litLen := int(token >> 4)
		if litLen == runMask {
			extra, adv, ok := readLength(src, sp)
			if !ok {
				return dst[:outStart], ErrCorrupt
			}
			litLen += extra
			sp += adv
		}
		// The literals must be present in src and fit under maxOut.
		if litLen < 0 || litLen > n-sp {
			return dst[:outStart], ErrCorrupt
		}
		if len(out)-outStart+litLen > maxOut {
			return dst[:outStart], ErrOutputTooLarge
		}
		out = append(out, src[sp:sp+litLen]...)
		sp += litLen

		// The last sequence is literals-only and ends the block exactly here.
		if sp == n {
			break
		}
		// If there are bytes left, a full 2-byte offset must follow.
		if sp+2 > n {
			return dst[:outStart], ErrCorrupt
		}

		// --- match ---
		offset := int(binary.LittleEndian.Uint16(src[sp:]))
		sp += 2
		if offset == 0 {
			// Offset 0 is invalid: it has no back-reference target and
			// reference lz4 rejects it. (libRIST's LZ4_decompress_safe would
			// fail the same block.)
			return dst[:outStart], ErrCorrupt
		}

		matchLen := int(token&runMask) + minMatch
		if int(token&runMask) == runMask {
			extra, adv, ok := readLength(src, sp)
			if !ok {
				return dst[:outStart], ErrCorrupt
			}
			matchLen += extra
			sp += adv
		}

		// The match source must lie within this block's already-produced
		// output: matchPos >= outStart.
		matchPos := len(out) - offset
		if matchPos < outStart {
			return dst[:outStart], ErrCorrupt
		}
		if len(out)-outStart+matchLen > maxOut {
			return dst[:outStart], ErrOutputTooLarge
		}

		// Copy the back-reference one byte at a time so an overlapping match
		// (offset < matchLen) expands correctly. The bound check above
		// guarantees the appends stay within the pre-grown capacity.
		for i := 0; i < matchLen; i++ {
			out = append(out, out[matchPos+i])
		}

		// A valid LZ4 block always terminates with a literals-only sequence
		// (handled by the sp==n break after the literals above). Reaching the
		// end of the input immediately after a match means the block has no
		// literals terminator — it is malformed, and libRIST's
		// LZ4_decompress_safe rejects it (lz4.c: ip+length != iend). Without
		// this check the loop would fall out cleanly and wrongly accept it.
		if sp == n {
			return dst[:outStart], ErrCorrupt
		}
	}

	return out, nil
}

// readLength decodes an LZ4 variable-length continuation field starting at
// src[sp]: it sums 0xFF bytes until a byte < 255 (which is also summed),
// returning the total, the number of bytes consumed, and whether the field was
// complete within src (false if the bytes ran out before a terminating byte).
func readLength(src []byte, sp int) (total, advance int, ok bool) {
	n := len(src)
	for {
		if sp >= n {
			return 0, 0, false
		}
		b := src[sp]
		sp++
		advance++
		total += int(b)
		if b != 255 {
			return total, advance, true
		}
	}
}

// hash maps a 4-byte little-endian word to a match-finder table index using the
// reference-lz4 32-bit multiplicative hash.
func hash(v uint32) uint32 {
	const prime = 2654435761
	return (v * prime) >> (32 - hashLog)
}

// load32 reads four bytes at offset i as a little-endian uint32. Callers
// guarantee i+4 <= len(b) (the scan limits keep reads in range).
func load32(b []byte, i int) uint32 {
	return binary.LittleEndian.Uint32(b[i:])
}
