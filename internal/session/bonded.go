package session

import (
	"net"

	"github.com/zsiec/ristgo/internal/bonding"
	"github.com/zsiec/ristgo/internal/clock"
	"github.com/zsiec/ristgo/internal/flow"
	"github.com/zsiec/ristgo/internal/peer"
	"github.com/zsiec/ristgo/internal/rtcp"
	"github.com/zsiec/ristgo/internal/socket"
	"github.com/zsiec/ristgo/internal/wire"
)

// This file is the link-bonding / SMPTE 2022-7 host: N network paths feeding one
// flow. It is the Simple-profile bonded analog of the single-path host — the
// 2022-7 merge itself lives in the flow core (one seq-indexed ring deduplicated
// by (Seq, SourceTime)); this host just fans transmissions across the paths and
// feeds every path's arrivals into that one ring.
//
// # Topology
//
// A bonded RECEIVER binds one socket per path (conns[i]); each path learns its
// own sender address and feeds media into the flow with its path index. A
// bonded SENDER uses one socket and a list of remote {media, rtcp} address pairs
// (remotes[i]); it DUPLICATES every media datagram to all of them (full
// redundancy) so identical (Seq, SourceTime) copies arrive on every path and the
// receiver merges them.
//
// # Decoder sharing
//
// Both directions transmit byte-identical RTP on every path, so the receiver
// MUST decode them with ONE shared mediaDecoder (s.mdec): a per-path decoder
// would anchor its sequence/timestamp widening independently and reconstruct
// different (Seq, SourceTime) values for the same packet on different paths,
// defeating the dedup. The loop is single-goroutine, so the shared decoder is
// safe and yields identical normalized packets for identical wire bytes.

// bondInbound is one datagram a per-path reader hands to the event loop, tagged
// with the path it arrived on (for a receiver) and whether it is RTCP.
type bondInbound struct {
	idx    uint8
	isRTCP bool
	data   []byte
	src    *net.UDPAddr
}

// bondState holds the per-path I/O and policy for a bonded session.
type bondState struct {
	group *bonding.Group

	// conns is one socket per path on a receiver, or the single send socket
	// (conns[0]) on a sender.
	conns []*socket.Conn

	// remotes is the sender's per-path {media, rtcp} destination pair; nil on a
	// receiver (which learns each path's peer from inbound traffic).
	remotes [][2]*net.UDPAddr

	// peers tracks each path's learned/known addresses and liveness.
	peers []*peer.Peer
}

// NewBondedReceiver builds a Simple-profile bonded receiver: one socket per
// path, all feeding flow into a single deduplicated ring. group must already
// have a path registered per conn (index = conn index); the constructor
// registers them if empty.
func NewBondedReceiver(conns []*socket.Conn, group *bonding.Group, cfg Config) *Session {
	s := newSession(conns[0], cfg, false)
	s.flow = flow.New(flow.RoleReceiver, cfg.Flow)
	bs := &bondState{group: group, conns: conns, peers: make([]*peer.Peer, len(conns))}
	for i := range conns {
		bs.peers[i] = peer.New(cfg.SessionTimeout)
		group.AddPath(uint8(i), bonding.WeightDuplicate, 0)
	}
	s.bond = bs
	s.bondIn = make(chan bondInbound, 256*len(conns))
	s.start()
	return s
}

// NewBondedSender builds a Simple-profile bonded sender: one socket that
// duplicates every media datagram to each remote {media, rtcp} pair. conn is the
// local ephemeral socket; remotes are the per-path receiver addresses.
func NewBondedSender(conn *socket.Conn, remotes [][2]*net.UDPAddr, group *bonding.Group, cfg Config) *Session {
	s := newSession(conn, cfg, true)
	s.flow = flow.New(flow.RoleSender, cfg.Flow)
	bs := &bondState{group: group, conns: []*socket.Conn{conn}, remotes: remotes, peers: make([]*peer.Peer, len(remotes))}
	for i := range remotes {
		bs.peers[i] = peer.New(cfg.SessionTimeout)
		bs.peers[i].Media = remotes[i][0]
		bs.peers[i].RTCP = remotes[i][1]
		group.AddPath(uint8(i), bonding.WeightDuplicate, 0)
	}
	// The base Session's peer guards (peer.Media/RTCP != nil) gate transmission;
	// point them at path 0 so the keepalive/feedback guards pass.
	s.peer.Media = remotes[0][0]
	s.peer.RTCP = remotes[0][1]
	s.bond = bs
	s.bondIn = make(chan bondInbound, 256)
	s.start()
	return s
}

// startBondReaders launches the per-path reader goroutines. A receiver runs a
// media and an RTCP reader per path socket; a sender runs a single RTCP reader
// on its one socket (it never receives media), and resolves the path by source
// address.
func (s *Session) startBondReaders() {
	if s.sender {
		s.wg.Add(1)
		go s.readBond(0, true, s.bond.conns[0].ReadRTCP)
		return
	}
	for i, c := range s.bond.conns {
		s.wg.Add(2)
		go s.readBond(uint8(i), false, c.ReadMedia)
		go s.readBond(uint8(i), true, c.ReadRTCP)
	}
}

// readBond reads datagrams from one path socket (media or RTCP) and forwards
// them to the loop tagged with the path index.
func (s *Session) readBond(idx uint8, isRTCP bool, read func([]byte) (int, *net.UDPAddr, error)) {
	defer s.wg.Done()
	for {
		buf := make([]byte, maxDatagram)
		n, src, err := read(buf)
		if err != nil {
			return
		}
		select {
		case s.bondIn <- bondInbound{idx: idx, isRTCP: isRTCP, data: buf[:n], src: src}:
		case <-s.done:
			return
		}
	}
}

// handleBondInbound processes one inbound bonded datagram: it resolves the path
// (a sender resolves by source address), refreshes liveness, and routes media
// into the flow with its path index (the merge) or feedback into the flow.
func (s *Session) handleBondInbound(now clock.Timestamp, bi bondInbound) {
	idx := bi.idx
	if s.sender {
		var ok bool
		if idx, ok = s.bondPathForSrc(bi.src); !ok {
			return // a datagram from an unknown source; ignore
		}
	}
	if int(idx) >= len(s.bond.peers) {
		return
	}
	p := s.bond.peers[idx]
	p.Observe(now)
	s.peer.Observe(now)
	s.bond.group.Observe(idx, now)

	if bi.isRTCP {
		p.LearnRTCP(bi.src)
		if fbs, err := decodeFeedback(bi.data, s.highestSent); err == nil {
			for _, fb := range fbs {
				s.flow.FeedFeedback(now, fb)
			}
		}
		return
	}
	// Media (receiver only): decode with the SHARED decoder so identical wire
	// bytes from any path reconstruct to the same (Seq, SourceTime), then feed
	// the flow with this path's index. The dedup merges the copies.
	p.LearnMedia(bi.src)
	if pkt, err := s.mdec.decode(bi.data); err == nil {
		s.flow.Feed(now, idx, pkt)
		s.observeRx(now, pkt)
	}
}

// bondPathForSrc resolves a sender's inbound source address (a receiver path's
// RTCP socket) to its path index.
func (s *Session) bondPathForSrc(src *net.UDPAddr) (uint8, bool) {
	if src == nil {
		return 0, false
	}
	for i, r := range s.bond.remotes {
		if udpAddrEqual(src, r[1]) {
			return uint8(i), true
		}
	}
	return 0, false
}

// udpAddrEqual reports whether two UDP addresses share IP and port.
func udpAddrEqual(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}

// sendBondMedia duplicates one encoded media datagram to every path (full 2022-7
// redundancy). It encodes once and writes the identical bytes to each path's
// media destination.
func (s *Session) sendBondMedia(now clock.Timestamp, pkt wire.MediaPacket) {
	s.mediaBuf = s.mediaBuf[:0]
	b, err := encodeMedia(s.mediaBuf, pkt)
	if err != nil {
		s.logf("bond: encode media seq %d: %v", pkt.Seq, err)
		return
	}
	s.mediaBuf = b
	for i := range s.bond.remotes {
		if err := s.bond.conns[0].WriteMedia(b, s.bond.remotes[i][0]); err != nil {
			s.logf("bond: write media path %d: %v", i, err)
		}
	}
	s.lastTx = now
}

// sendBondFeedback transmits drained feedback. A receiver sends one compound
// RTCP on the NACK-peer-selected live path (bonding.SelectNackPath); a sender
// sends its RTT-echo feedback on every path so each path's liveness/RTT is
// exercised.
func (s *Session) sendBondFeedback(fbs []wire.Feedback, now clock.Timestamp) {
	var lead rtcp.Packet
	if s.sender {
		lead = rtcp.SenderReport{
			SSRC:    s.cfg.SSRC,
			NTP:     uint64(clock.NTPTimeFromTimestamp(now)),
			RTPTime: uint32(rtpTicksFromMicros(int64(now))),
		}
	} else {
		lead = s.receiverReport()
	}
	s.rtcpBuf = s.rtcpBuf[:0]
	b, err := encodeFeedback(s.rtcpBuf, lead, s.cfg.SSRC, s.cfg.CNAME, fbs, s.cfg.Bitmask)
	if err != nil {
		s.logf("bond: encode feedback: %v", err)
		return
	}
	s.rtcpBuf = b

	if s.sender {
		// Send on every path's RTCP destination so RTT echoes and SDES reach
		// each receiver path (so each learns the sender's RTCP return address).
		for i := range s.bond.remotes {
			if err := s.bond.conns[0].WriteRTCP(b, s.bond.remotes[i][1]); err != nil {
				s.logf("bond: write feedback path %d: %v", i, err)
			}
		}
		s.lastTx = now
		return
	}
	// Receiver: route to the selected live path (NACK-peer selection).
	idx, ok := s.bond.group.SelectNackPath(now)
	if !ok {
		return
	}
	p := s.bond.peers[idx]
	if p.RTCP == nil {
		return // that path's return address not learned yet
	}
	if err := s.bond.conns[idx].WriteRTCP(b, p.RTCP); err != nil {
		s.logf("bond: write feedback on path %d: %v", idx, err)
	}
	s.lastTx = now
}

// sendBondKeepalive emits a periodic keepalive: a sender sends an SR + SDES +
// RTT-echo on every path (so receivers learn its return address and RTT
// tracks); a receiver sends an RR + RTT-echo on the selected live path.
func (s *Session) sendBondKeepalive(now clock.Timestamp) {
	echo := []wire.Feedback{wire.RttEchoRequest{Timestamp: uint64(clock.NTPTimeFromTimestamp(now))}}
	s.sendBondFeedback(echo, now)
}

// tickBond ages the paths and logs any that died this interval. (The flow keeps
// running on the survivors; the merge needs no notification.)
func (s *Session) tickBond(now clock.Timestamp) {
	for _, idx := range s.bond.group.Tick(now) {
		s.logf("bond: path %d declared dead", idx)
	}
}

// closeBond closes every path socket. Called from shutdown for a bonded session.
func (s *Session) closeBond() {
	for _, c := range s.bond.conns {
		c.Close()
	}
}
