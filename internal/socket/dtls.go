package socket

import (
	"net"
	"time"

	"github.com/zsiec/ristgo/internal/dtls"
)

// DTLS transport security for the Main profile (VSF TR-06-2 §6). When enabled,
// the single GRE socket's media I/O is carried inside a DTLS 1.2 session: the
// whole tunnel (media + feedback) is protected, an alternative to the GRE
// PSK-AES-CTR payload encryption. Only the single-socket (Main) Conn supports it.

// EnableDTLSClient configures the Conn to run a DTLS client handshake to remote
// on Handshake. The RIST sender is the DTLS client.
func (c *Conn) EnableDTLSClient(remote *net.UDPAddr, cfg *dtls.Config) {
	c.dtlsCfg = cfg
	c.dtlsClient = true
	c.dtlsRemote = remote
}

// EnableDTLSServer configures the Conn to run a DTLS server handshake, learning
// the peer from the first inbound datagram on Handshake. The RIST receiver is
// the DTLS server.
func (c *Conn) EnableDTLSServer(cfg *dtls.Config) {
	c.dtlsCfg = cfg
	c.dtlsClient = false
}

// DTLSEnabled reports whether a DTLS session is configured (and so Handshake
// must run before media flows).
func (c *Conn) DTLSEnabled() bool { return c.dtlsCfg != nil }

// Handshake performs the configured DTLS handshake over the single socket,
// binding the session to one peer. It is a no-op when DTLS is not enabled. After
// it returns, ReadMedia/WriteMedia carry application records.
func (c *Conn) Handshake() error {
	if c.dtlsCfg == nil {
		return nil
	}
	if c.dtlsClient {
		// The handshake conn keeps the *net.UDPAddr internally; only the
		// dtlsPeer crossing the ReadMedia boundary is widened to netip.AddrPort.
		c.dtlsPeer = c.dtlsRemote.AddrPort()
		c.dtls = dtls.Client(&connectedUDP{pc: c.media, peer: c.dtlsRemote}, c.dtlsCfg)
	} else {
		ad, err := acceptUDP(c.media)
		if err != nil {
			return err
		}
		c.dtlsPeer = ad.peer.AddrPort()
		c.dtls = dtls.Server(ad, c.dtlsCfg)
	}
	return c.dtls.Handshake()
}

// connectedUDP is a dtls.Transport bound to one peer over an unconnected UDP
// socket: writes address the peer, reads ignore datagrams from anyone else.
type connectedUDP struct {
	pc   *net.UDPConn
	peer *net.UDPAddr
}

func (c *connectedUDP) Read(p []byte) (int, error) {
	for {
		n, addr, err := c.pc.ReadFromUDP(p)
		if err != nil {
			return 0, err
		}
		if sameAddr(addr, c.peer) {
			return n, nil
		}
	}
}

func (c *connectedUDP) Write(p []byte) (int, error)       { return c.pc.WriteToUDP(p, c.peer) }
func (c *connectedUDP) SetReadDeadline(t time.Time) error { return c.pc.SetReadDeadline(t) }
func (c *connectedUDP) Close() error                      { return nil } // Conn.Close owns the socket

// udpAdapter is the server-side dtls.Transport: it learns the peer from the
// first datagram and replays it, then filters subsequent reads to that peer.
type udpAdapter struct {
	pc    *net.UDPConn
	peer  *net.UDPAddr
	first []byte
}

// acceptUDP blocks for the first datagram, learning the peer address.
//
// THREAT MODEL: the DTLS server peer is bound to the source IP+port of the first
// datagram seen on the socket (RIST has no DTLS Connection ID, RFC 9146). An
// off-path attacker who races a spoofed datagram to the listening port before
// the legitimate client can therefore capture the binding and force the real
// client's handshake to be dropped (a first-datagram-binding denial of service).
// This is a pre-handshake liveness concern only: it cannot break confidentiality
// or authenticity — once the handshake completes, every record is bound to the
// negotiated keys, and the DTLS layer's HelloVerifyRequest cookie (handshake_io)
// forces a return-routability round-trip before any handshake state is
// committed, so a blind off-path spoof cannot complete a handshake. Post-
// handshake, AEAD plus the anti-replay window fully protect the session.
func acceptUDP(pc *net.UDPConn) (*udpAdapter, error) {
	buf := make([]byte, 1<<16)
	n, addr, err := pc.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	return &udpAdapter{pc: pc, peer: addr, first: append([]byte(nil), buf[:n]...)}, nil
}

func (a *udpAdapter) Read(p []byte) (int, error) {
	if a.first != nil {
		n := copy(p, a.first)
		a.first = nil
		return n, nil
	}
	for {
		n, addr, err := a.pc.ReadFromUDP(p)
		if err != nil {
			return 0, err
		}
		if sameAddr(addr, a.peer) {
			return n, nil
		}
	}
}

func (a *udpAdapter) Write(p []byte) (int, error)       { return a.pc.WriteToUDP(p, a.peer) }
func (a *udpAdapter) SetReadDeadline(t time.Time) error { return a.pc.SetReadDeadline(t) }
func (a *udpAdapter) Close() error                      { return nil }

// sameAddr reports whether two UDP addresses are the same peer.
func sameAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}
