package session

import (
	"encoding/binary"
	"fmt"

	"github.com/zsiec/ristgo/internal/adv"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/crypto"
	"github.com/zsiec/ristgo/internal/lpc"
	"github.com/zsiec/ristgo/internal/wire"
)

// This file is the Advanced-profile (VSF TR-06-3:2024) codec strategy: the
// single-UDP-port, RTP-based analog of the Main-profile codec in codec_main.go.
// It translates between the flow core's normalized wire.MediaPacket /
// wire.Feedback values and Advanced-profile datagrams, framing through
// internal/adv (the byte-exact header + control-message codec), internal/crypto
// (AES-CTR payload encryption), and internal/lpc (LZ4 payload compression). It
// is byte-exact with libRIST v0.2.18-rc1.
//
// # Single-port multiplex
//
// Advanced profile carries media AND control over one UDP port as plain RTP
// (V=2, PT=127, 1 MHz clock) followed by the 4-byte profile-defined extension.
// There is no GRE framing. Media packets carry enc_type=DIRECT
// (5) on the even (protected) base SSRC; control messages carry enc_type=CONTROL
// (4) on the odd (unprotected) base SSRC. The receive demux is the encapsulation
// Type field, not a port.
//
// # Sequence numbers
//
// The Advanced wire sequence is natively 32-bit — the low 16 bits in the RTP
// header and the high 16 in the profile extension's seq_ext (adv.SplitSeq /
// adv.JoinSeq). The flow core already speaks 32-bit sequences, so there is NO
// widening on this path (unlike Simple/Main, which widen a 16-bit RTP seq). NACK
// control messages likewise carry full 32-bit sequences, so inbound NACKs need
// no nackRef.
//
// # Encryption and compression (order)
//
// On send the payload is compressed THEN encrypted; on receive
// it is decrypted THEN decompressed. Encryption is
// AES-CTR over the PAYLOAD ONLY (not the header) — libRIST's mode-1 deviation
// from the TR-06-3 after-IV scope — with the IV = the 32-bit sequence as the
// big-endian counter MSBs followed by 12 zero bytes (crypto.BuildIV, identical
// to the Main path's gre_version>=1 IV), the nonce in the psk_nonce field, and
// the sequence echoed in the psk_iv field. Compression is LZ4 raw-block with no
// length prefix, applied only when it shrinks the payload (lpc_mode = LZ4).
//
// # Receive source-time
//
// libRIST discards the wire timestamp on receive and stamps arrival time.
// ristgo instead reconstructs SourceTime from the 1 MHz
// RTP timestamp (one tick == one microsecond), widened by rollover counting like
// the Simple/Main codecs, so a retransmit and its original reconstruct to the
// same (Seq, SourceTime) pair — preserving the flow core's dedup invariant. This
// is strictly more faithful than libRIST and fully interoperable (the wire bytes
// are unchanged; only ristgo's own use of the field differs).

// advClockShift converts between microseconds and the Advanced-profile RTP
// timestamp. Although TR-06-3 specifies a 1 MHz clock, libRIST computes the
// timestamp as (timestampNTP_u64() * 1e6) >> 16 with an NTP-64 (32.32) clock,
// so the field actually advances by 2^16 per microsecond
// — a 2^16 MHz effective rate, wrapping the 32-bit field every ~65 ms. ristgo
// matches that convention byte-for-byte: timestamp = microseconds << 16 on
// encode, microseconds = timestamp >> 16 on decode. Spacing (the only thing the
// flow core uses the timestamp for) is preserved; libRIST itself discards the
// received timestamp and stamps arrival time, so the exact
// value never needs to match across the wire — only ristgo's own encode/decode
// must round-trip, which this does.
const advClockShift = 16

// maxAdvDecompressed bounds the output of an LZ4 decompression on the receive
// path, matching libRIST's RIST_MAX_PACKET_SIZE (10000) decompress bound exactly
// so a block a libRIST receiver would reject as oversized is rejected here too
// (and a hostile compressed payload cannot force an unbounded allocation).
// Legitimate media payloads are far smaller (LZ4 is applied on send only when it
// shrinks the payload, so the decompressed size never exceeds the original
// ~MTU-sized packet).
const maxAdvDecompressed = 10000

// advCodec is the stateful Advanced-profile codec for one direction of a flow.
// It is the analog of mainCodec, gathered into a struct because the Advanced
// profile carries direction-scoped state: the PSK send Key and receive
// Decryptor, the per-datagram control sequence counter, the media decoder's
// timestamp-widening reference, and the configured flow-id virtual ports. It is
// NOT safe for concurrent use; the host serializes a single send/receive path
// onto it.
type advCodec struct {
	// sendKey is the PSK encryptor, or nil when encryption is disabled. When
	// non-nil, every media payload is AES-CTR encrypted and the psk mode/nonce/iv
	// fields are emitted.
	sendKey *crypto.Key

	// recvKey is the PSK decryptor, or nil when encryption is disabled. It
	// re-derives its AES key whenever the inbound psk_nonce changes, so it
	// follows the peer's nonce rotation without needing the optional PSK
	// future-nonce announcement.
	recvKey *crypto.Decryptor

	// compression enables LZ4 payload compression on the media send path.
	compression bool

	// ssrc is the even base SSRC of this flow. Media uses the protected (even)
	// form, control the unprotected (odd) form.
	ssrc uint32

	// srcPort and dstPort are the reduced-overhead virtual ports encoded into
	// the optional Flow ID field on the media send path (matching libRIST:
	// outer = dst port, inner = src port). Zero on both disables
	// the Flow ID.
	srcPort uint16
	dstPort uint16

	// ctrlSeq is the per-datagram control sequence counter (the unprotected
	// flow's sequence). It increments for every control datagram sent.
	ctrlSeq uint32

	// Source-time reconstruction state (see advSourceMicros). The 32-bit
	// Advanced timestamp wraps every ~65 ms (libRIST's 2^16 MHz effective rate),
	// far inside the recovery window, so the widening reference is extrapolated
	// from the sequence number — anchored at the first packet (tsBase*) and
	// tracking the in-order front (tsRef*) — rather than from arrival order. This
	// keeps a given (seq, timestamp) mapping to the same source time on both a
	// packet's first arrival and any later retransmit, preserving the flow core's
	// (Seq, SourceTime) dedup across the wrap.
	tsStarted   bool
	tsBaseSeq   uint32
	tsBaseTicks int64
	tsRefSeq    uint32
	tsRefTicks  int64
}

// newAdvCodec constructs an Advanced-profile codec. sendKey and recvKey may be
// nil to disable PSK encryption; when non-nil they must derive from the same
// passphrase and key size. compression turns on LZ4 on the media send path.
// ssrc is the even base SSRC; srcPort/dstPort are the Flow ID virtual ports
// (zero disables the Flow ID field).
func newAdvCodec(sendKey *crypto.Key, recvKey *crypto.Decryptor, compression bool, ssrc uint32, srcPort, dstPort uint16) *advCodec {
	return &advCodec{
		sendKey:     sendKey,
		recvKey:     recvKey,
		compression: compression,
		ssrc:        ssrc,
		srcPort:     srcPort,
		dstPort:     dstPort,
	}
}

// advTSFromSource maps an NTP-64 source time to the 32-bit Advanced RTP
// timestamp, matching libRIST's effective 2^16 MHz rate: microseconds shifted
// left by advClockShift, truncated to 32 bits (see advClockShift).
func advTSFromSource(src uint64) uint32 {
	return uint32(uint64(int64(clock.NTPTime(src).Timestamp())) << advClockShift)
}

// encodeAdvMedia encodes a normalized MediaPacket as one Advanced-profile DIRECT
// datagram, appending to dst and returning the extended slice. The payload is
// compressed (when enabled and it shrinks) then encrypted (when a PSK is
// configured), and framed with the protected (even) SSRC, the split 32-bit
// sequence, the 1 MHz timestamp, the R flag for a retransmission, and the
// optional Flow ID. A retransmit and its original differ only in the R flag, so
// they reconstruct to the same (Seq, SourceTime) on decode.
func (c *advCodec) encodeAdvMedia(dst []byte, pkt wire.MediaPacket) ([]byte, error) {
	payload := pkt.Payload
	lpcMode := uint8(adv.LPCNone)

	// Compress first: LZ4 raw block, only when it shrinks the
	// payload, no length prefix on the wire.
	if c.compression && len(payload) > 0 {
		comp, err := lpc.Compress(nil, payload)
		if err == nil && len(comp) < len(payload) {
			payload = comp
			lpcMode = adv.LPCLZ4
		}
	}

	first, last := fragBits(pkt.Frag)
	params := adv.Params{
		Seq:        pkt.Seq,
		Timestamp:  advTSFromSource(pkt.SourceTime),
		SSRC:       adv.SSRCProtected(c.ssrc),
		EncType:    adv.TypeDirect,
		PSKMode:    adv.PSKNone,
		LPCMode:    lpcMode,
		FirstFrag:  first,
		LastFrag:   last,
		Retransmit: pkt.Retransmit,
	}
	if c.srcPort != 0 || c.dstPort != 0 {
		fid := flowIDFromPorts(c.srcPort, c.dstPort)
		params.FlowID = &fid
	}

	// Encrypt the (possibly compressed) payload: AES-CTR mode 1,
	// payload only, IV from the 32-bit sequence, nonce read AFTER Encrypt (the
	// key may rotate on send). The psk_iv field carries the sequence big-endian.
	if c.sendKey != nil {
		ct, err := c.sendKey.Encrypt(pkt.Seq, nil, payload)
		if err != nil {
			return dst, err
		}
		payload = ct
		params.PSKMode = adv.PSKAESCTR
		nonce := c.sendKey.Nonce()
		params.PSKNonce = nonce[:]
		var iv [adv.PSKIVSize]byte
		binary.BigEndian.PutUint32(iv[:], pkt.Seq)
		params.PSKIV = iv[:]
	}

	return adv.Build(dst, params, payload)
}

// fragBits maps a wire fragment role to the Advanced header F (first) and L
// (last) bits (TR-06-3 §5.2.2). FragStandalone is the unfragmented F=L=1 packet.
func fragBits(r wire.FragRole) (first, last bool) {
	switch r {
	case wire.FragFirst:
		return true, false
	case wire.FragMiddle:
		return false, false
	case wire.FragLast:
		return false, true
	default: // FragStandalone
		return true, true
	}
}

// fragRole maps the Advanced header F/L bits back to a wire fragment role.
func fragRole(first, last bool) wire.FragRole {
	switch {
	case first && last:
		return wire.FragStandalone
	case first: // first && !last
		return wire.FragFirst
	case last: // !first && last
		return wire.FragLast
	default: // !first && !last
		return wire.FragMiddle
	}
}

// flowIDFromPorts builds the Advanced Flow ID from the reduced-overhead virtual
// ports, matching libRIST: the outer flow id is the destination
// port and the 12-bit inner flow id is the source port (the IFSID sub-field is
// zero).
func flowIDFromPorts(srcPort, dstPort uint16) adv.FlowID {
	return adv.FlowID{Outer: dstPort, Inner: srcPort & 0x0FFF}
}

// decodeAdv parses one Advanced-profile datagram, demultiplexing on the
// encapsulation Type field. A DIRECT packet returns
// isMedia true with the reconstructed MediaPacket; a CONTROL packet returns
// isMedia false with the decoded feedback list (empty for keepalive/flow-attr/
// psk-nonce, which the host handles via peer liveness and per-packet nonce
// re-derivation). Other encapsulation types and fragments return an error.
// Arbitrary, truncated, or short-ciphertext input returns an error and never
// panics. The returned MediaPacket's Payload owns freshly decrypted/decompressed
// bytes; decoded Feedback owns its slices.
func (c *advCodec) decodeAdv(b []byte) (isMedia bool, pkt wire.MediaPacket, fbs []wire.Feedback, err error) {
	p, err := adv.Parse(b)
	if err != nil {
		return false, wire.MediaPacket{}, nil, err
	}
	return c.decodeParsed(p)
}

// decodeParsed demultiplexes an already-parsed Advanced packet. It is the entry
// point the host uses after parsing the header itself (so it can route Type=8
// GRE-wrapped packets to the GRE substrate without re-parsing). A DIRECT packet
// returns media; a CONTROL packet returns feedback. TypeGREMain (Type=8) is the
// host's responsibility (it unwraps the inner GRE) — decodeParsed reports it as
// an error so a caller that does not special-case it fails loudly rather than
// silently dropping a GRE-wrapped control packet.
func (c *advCodec) decodeParsed(p adv.Parsed) (isMedia bool, pkt wire.MediaPacket, fbs []wire.Feedback, err error) {
	switch p.EncType {
	case adv.TypeControl:
		fbs, err = c.decodeControl(p.Payload)
		return false, wire.MediaPacket{}, fbs, err
	case adv.TypeDirect:
		pkt, err = c.decodeMediaAdv(p)
		return true, pkt, nil, err
	default:
		return false, wire.MediaPacket{}, nil, fmt.Errorf("rist: adv: unsupported encapsulation type %d", p.EncType)
	}
}

// decodeMediaAdv reconstructs a MediaPacket from a parsed DIRECT packet:
// decrypt (AES-CTR mode 1) then decompress (LZ4), then map the native 32-bit
// sequence and the 1 MHz timestamp (widened by rollover counting) to the
// normalized fields. The header F/L bits become MediaPacket.Frag, which the
// flow core carries through and the session reassembles after in-order
// delivery; an unfragmented packet (F=L=1) maps to FragStandalone. A
// retransmit reconstructs to the same (Seq, SourceTime, Frag) as its original.
func (c *advCodec) decodeMediaAdv(p adv.Parsed) (wire.MediaPacket, error) {
	data := p.Payload

	// Decrypt. Only AES-CTR (mode 1) is supported, the
	// sole encryption mode libRIST implements for Advanced; modes 2-5 are
	// rejected exactly as libRIST rejects them.
	switch p.PSKMode {
	case adv.PSKNone:
		if c.recvKey != nil {
			return wire.MediaPacket{}, fmt.Errorf("rist: adv: cleartext payload but a decryptor is configured")
		}
	case adv.PSKAESCTR:
		if c.recvKey == nil {
			return wire.MediaPacket{}, fmt.Errorf("rist: adv: encrypted payload but no decryptor configured")
		}
		if p.PSKNonce == nil || p.PSKIV == nil {
			return wire.MediaPacket{}, fmt.Errorf("rist: adv: AES-CTR payload missing nonce/iv")
		}
		var nonce [crypto.NonceSize]byte
		copy(nonce[:], p.PSKNonce)
		ivSeq := binary.BigEndian.Uint32(p.PSKIV)
		dec, err := c.recvKey.Decrypt(nonce, ivSeq, nil, data)
		if err != nil {
			return wire.MediaPacket{}, err
		}
		data = dec
	default:
		return wire.MediaPacket{}, fmt.Errorf("rist: adv: unsupported PSK mode %d", p.PSKMode)
	}

	// Decompress.
	switch p.LPCMode {
	case adv.LPCNone:
	case adv.LPCLZ4:
		if len(data) > 0 {
			dec, err := lpc.Decompress(nil, data, maxAdvDecompressed)
			if err != nil {
				return wire.MediaPacket{}, err
			}
			data = dec
		}
	default:
		return wire.MediaPacket{}, fmt.Errorf("rist: adv: unsupported LPC mode %d", p.LPCMode)
	}

	// Reconstruct a dedup-stable source time (microseconds) from the native
	// 32-bit sequence and the wrapping timestamp. Only the spacing matters to
	// the flow core's playout/offset-lock; the absolute value is offset-absorbed.
	src := uint64(clock.NTPTimeFromTimestamp(clock.Timestamp(c.advSourceMicros(p.Seq, p.Timestamp))))

	return wire.MediaPacket{
		Seq:        p.Seq,
		SourceTime: src,
		SSRC:       adv.SSRCProtected(p.SSRC),
		Payload:    data,
		Retransmit: p.Retransmit,
		Frag:       fragRole(p.FirstFrag, p.LastFrag),
	}, nil
}

// advSourceMicros reconstructs a dedup-stable source time (microseconds) from
// the Advanced wire sequence and 32-bit timestamp.
//
// The timestamp wraps every ~65 ms (libRIST's 2^16 MHz effective rate), far
// inside the ~1 s recovery window, so a naive rollover counter widened against
// the live arrival front resolves a late retransmit's (byte-identical) timestamp
// into the WRONG epoch — a different source time than the original — which breaks
// the flow core's (Seq, SourceTime) dedup and can poison its newest-source-time
// clock (internal/flow/receiver.go:165,204). Instead the widening reference is
// extrapolated from the sequence number using a rate averaged over the whole
// flow (tsBase -> tsRef): a given (seq, timestamp) therefore maps to the same
// microseconds on a packet's first arrival AND on any later retransmit, because
// both references land within widenTicks's ±32 ms snap window of the same epoch
// as long as the rate stays accurate to ~3% (true for any real media). The
// sequence is native 32-bit; only the timestamp needs epoch reconstruction.
func (c *advCodec) advSourceMicros(seqNum uint32, wireTS uint32) int64 {
	if !c.tsStarted {
		c.tsStarted = true
		c.tsBaseSeq, c.tsBaseTicks = seqNum, int64(wireTS)
		c.tsRefSeq, c.tsRefTicks = seqNum, int64(wireTS)
		return c.tsBaseTicks >> advClockShift
	}
	// Reference = the in-order front extrapolated to this sequence by the
	// flow-averaged rate (ticks per sequence). For an in-order packet the delta
	// is positive; for a retransmit/reorder it is negative, walking the
	// reference back to the packet's true epoch.
	ref := c.tsRefTicks
	if d := int32(c.tsRefSeq - c.tsBaseSeq); d > 0 {
		ticksPerSeq := (c.tsRefTicks - c.tsBaseTicks) / int64(d)
		ref += int64(int32(seqNum-c.tsRefSeq)) * ticksPerSeq
	}
	ticks := widenTicks(wireTS, ref)
	if int32(seqNum-c.tsRefSeq) > 0 { // in-order advance: move the reference forward
		c.tsRefSeq, c.tsRefTicks = seqNum, ticks
	}
	if ticks < 0 {
		ticks = 0 // guard the rare early-stream negative (NTPTime would clamp anyway)
	}
	return ticks >> advClockShift
}

// decodeControl decodes one Type=CONTROL payload's sub-header and body into the
// normalized feedback the flow core consumes. NACK bitmask/range become a
// NackRequest (native 32-bit sequences, no widening); RTT echo request/response
// become the matching wire variants. Keepalive, flow attribute, and PSK
// future-nonce announcements yield no feedback: peer liveness is tracked by the
// host on every inbound datagram, and the decryptor follows nonce rotation from
// each data packet's nonce field. An unknown control index is ignored.
func (c *advCodec) decodeControl(payload []byte) ([]wire.Feedback, error) {
	ci, body, err := adv.ParseControl(payload)
	if err != nil {
		return nil, err
	}
	switch ci {
	case adv.CINackBitmask:
		n, err := adv.ParseNackBitmask(body)
		if err != nil {
			return nil, err
		}
		return []wire.Feedback{wire.NackRequest{SSRC: n.MediaSSRC, Missing: n.Missing()}}, nil
	case adv.CINackRange:
		n, err := adv.ParseNackRange(body)
		if err != nil {
			return nil, err
		}
		return []wire.Feedback{wire.NackRequest{SSRC: n.MediaSSRC, Missing: n.Missing()}}, nil
	case adv.CIRTTEchoReq:
		e, err := adv.ParseRTTEcho(body)
		if err != nil {
			return nil, err
		}
		return []wire.Feedback{wire.RttEchoRequest{Timestamp: e.Timestamp()}}, nil
	case adv.CIRTTEchoResp:
		e, err := adv.ParseRTTEcho(body)
		if err != nil {
			return nil, err
		}
		return []wire.Feedback{wire.RttEchoResponse{Timestamp: e.Timestamp(), ProcessingDelay: e.ProcessingDelay}}, nil
	case adv.CILQMGlobal, adv.CILQMLinkSpecific:
		// Source adaptation (TR-06-4 Part 1): a Type=Control message carrying the
		// 44-byte LQM (Global = whole-flow, Link-Specific = per-path). Cross the
		// waist as wire.LinkQuality for the host's rate controller; a short body is
		// ignored rather than treated as an error.
		var lq wire.LinkQuality
		if len(body) < len(lq.LQM) {
			return nil, nil
		}
		copy(lq.LQM[:], body)
		return []wire.Feedback{lq}, nil
	case adv.CIKeepalive, adv.CIFlowAttr, adv.CIPSKNonce:
		return nil, nil
	default:
		return nil, nil
	}
}

// ctrlSSRC returns the unprotected (odd) base SSRC used for control datagrams.
func (c *advCodec) ctrlSSRC() uint32 { return adv.SSRCUnprotected(c.ssrc) }

// encodeFeedback encodes the drained feedback effects into complete
// Advanced-profile control datagrams — one per message, since libRIST sends and
// reads exactly one entry per control datagram. A NackRequest
// expands to one datagram per NACK entry (range or bitmask per the bitmask
// flag); RTT echo requests/responses and keepalives map to one datagram each.
// ts is the 1 MHz timestamp stamped into each control packet's RTP header
// (informational; the receiver ignores it). Each returned datagram is a fresh
// slice ready to send; the control sequence counter advances once per datagram.
func (c *advCodec) encodeFeedback(fbs []wire.Feedback, bitmask bool, ts uint32) ([][]byte, error) {
	var out [][]byte
	emit := func(payload []byte) error {
		dg, err := c.frameControl(nil, payload, ts)
		if err != nil {
			return err
		}
		out = append(out, dg)
		return nil
	}
	for _, fb := range fbs {
		switch f := fb.(type) {
		case wire.NackRequest:
			if bitmask {
				for _, n := range adv.EncodeBitmaskNACK(f.SSRC, f.Missing) {
					if err := emit(adv.BuildNackBitmask(nil, n)); err != nil {
						return nil, err
					}
				}
			} else {
				for _, n := range adv.EncodeRangeNACK(f.SSRC, f.Missing) {
					if err := emit(adv.BuildNackRange(nil, n)); err != nil {
						return nil, err
					}
				}
			}
		case wire.RttEchoRequest:
			e := adv.RTTEchoFromTimestamp(c.ctrlSSRC(), f.Timestamp, 0)
			if err := emit(adv.BuildRTTEchoRequest(nil, e)); err != nil {
				return nil, err
			}
		case wire.RttEchoResponse:
			e := adv.RTTEchoFromTimestamp(c.ctrlSSRC(), f.Timestamp, f.ProcessingDelay)
			if err := emit(adv.BuildRTTEchoResponse(nil, e)); err != nil {
				return nil, err
			}
		case wire.Keepalive:
			if err := emit(adv.BuildKeepalive(nil, adv.Keepalive{Caps: adv.KeepaliveCapI})); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// frameControl wraps a control payload (CI + Length sub-header + body) in a
// Type=CONTROL Advanced-profile packet on the unprotected (odd) SSRC, appending
// to dst. It mirrors libRIST's control framing: enc_type
// CONTROL, no encryption, no compression, F=L=E=1. The control sequence counter
// advances once per call.
func (c *advCodec) frameControl(dst, payload []byte, ts uint32) ([]byte, error) {
	return c.frameControlFrag(dst, payload, true, true, ts)
}

// frameControlFrag is frameControl with explicit fragment roles: a control message
// larger than the MTU is split across consecutive control packets carrying the
// F/L bits (TR-06-3 §5.2.3), which the receiver reassembles before processing.
func (c *advCodec) frameControlFrag(dst, payload []byte, first, last bool, ts uint32) ([]byte, error) {
	seq := c.ctrlSeq
	c.ctrlSeq++
	params := adv.Params{
		Seq:       seq,
		Timestamp: ts,
		SSRC:      c.ctrlSSRC(),
		EncType:   adv.TypeControl,
		PSKMode:   adv.PSKNone,
		LPCMode:   adv.LPCNone,
		FirstFrag: first,
		LastFrag:  last,
		Expedite:  true,
	}
	return adv.Build(dst, params, payload)
}

// keepaliveDatagram builds one Advanced keep-alive control datagram (CI 0x8000,
// I bit set) on the unprotected SSRC, for the host's liveness ticker. ts is the
// 1 MHz timestamp stamped into the packet header.
func (c *advCodec) keepaliveDatagram(ts uint32) ([]byte, error) {
	return c.frameControl(nil, adv.BuildKeepalive(nil, adv.Keepalive{Caps: adv.KeepaliveCapI}), ts)
}
