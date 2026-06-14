// Package socket is the UDP transport for RIST. The Simple profile (VSF
// TR-06-1) uses a pair of unconnected UDP sockets on adjacent even/odd ports —
// RTP media on the even port P, compound RTCP on the odd port P+1. The Main
// profile (TR-06-2) tunnels everything over a single GRE port; ListenSingle /
// ListenEphemeralSingle bind that one socket (the Conn's media and rtcp aliases
// then refer to it, and the session reads/writes it via ReadMedia/WriteMedia).
//
// The sockets are deliberately unconnected (net.ListenUDP, not DialUDP) and
// every send takes an explicit destination, so one transport serves both
// roles: a receiver binds the well-known port pair and learns the sender's
// source addresses from inbound datagrams, while a sender binds an ephemeral
// pair and addresses the receiver's well-known ports. Address learning and the
// even/odd split mirror libRIST (bind, address matching).
//
// This package only moves bytes; it never parses RTP/RTCP or touches the flow
// core. Read/Write are safe for concurrent use across the two sockets (each
// *net.UDPConn is independently goroutine-safe), which is how the host runs a
// reader goroutine per socket alongside the event loop.
package socket

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/zsiec/ristgo/internal/dtls"
)

// Conn is a RIST UDP transport. For the Simple profile it holds a media socket
// (even port) and an RTCP socket (odd port). For the Main profile it holds one
// socket carrying everything: media and rtcp both alias it and single is true.
type Conn struct {
	media  *net.UDPConn
	rtcp   *net.UDPConn
	single bool // Main profile: media == rtcp, one socket carries everything

	// DTLS transport security (Main profile, optional): when dtlsCfg is set,
	// Handshake establishes a DTLS 1.2 session over the single socket and
	// ReadMedia/WriteMedia carry the GRE tunnel as DTLS application records. See
	// dtls.go.
	dtlsCfg    *dtls.Config
	dtlsClient bool
	dtlsRemote *net.UDPAddr   // client role: the peer to converse with
	dtls       *dtls.Conn     // established by Handshake
	dtlsPeer   netip.AddrPort // known (client) or learned (server) peer address
}

// Listen binds the media socket to host:port and the RTCP socket to
// host:port+1. port must be even (TR-06-1 §4: the media port is even, RTCP is
// the adjacent odd port); port 0 is rejected because the pair cannot be
// derived from an ephemeral media bind. host may be empty to bind all
// interfaces. It is the receiver-side constructor.
func Listen(host string, port int) (*Conn, error) {
	if port <= 0 || port%2 != 0 {
		return nil, fmt.Errorf("rist: socket: media port %d must be a positive even number", port)
	}
	media, err := bind(host, port)
	if err != nil {
		return nil, fmt.Errorf("rist: socket: bind media port %d: %w", port, err)
	}
	rtcp, err := bind(host, port+1)
	if err != nil {
		media.Close()
		return nil, fmt.Errorf("rist: socket: bind rtcp port %d: %w", port+1, err)
	}
	return &Conn{media: media, rtcp: rtcp}, nil
}

// ListenEphemeral binds both sockets to OS-chosen ports on host (empty host
// binds all interfaces). It is the sender-side constructor: the sender's local
// ports are arbitrary; the receiver learns them from inbound datagrams.
func ListenEphemeral(host string) (*Conn, error) {
	media, err := bind(host, 0)
	if err != nil {
		return nil, fmt.Errorf("rist: socket: bind media: %w", err)
	}
	rtcp, err := bind(host, 0)
	if err != nil {
		media.Close()
		return nil, fmt.Errorf("rist: socket: bind rtcp: %w", err)
	}
	return &Conn{media: media, rtcp: rtcp}, nil
}

// ListenEphemeralEvenOdd binds an OS-chosen even media port and the adjacent odd
// RTCP port on host (empty host binds all interfaces). It is the Simple-profile
// caller-receiver constructor: a receiver that dials a listening sender still
// needs a local even/odd pair, because a Simple listener-sender infers the
// receiver's media address as its RTCP source port − 1 (the even/odd rule). A
// probe bind picks a free port; if it is odd the even neighbour below is tried,
// then port+1. The small TOCTOU window between probe and the real binds is
// tolerated by retrying.
func ListenEphemeralEvenOdd(host string) (*Conn, error) {
	var lastErr error
	for i := 0; i < 100; i++ {
		probe, err := bind(host, 0)
		if err != nil {
			lastErr = err
			continue
		}
		p := probe.LocalAddr().(*net.UDPAddr).Port
		probe.Close()
		if p%2 != 0 {
			p--
		}
		if p <= 0 {
			continue
		}
		media, err := bind(host, p)
		if err != nil {
			lastErr = err
			continue
		}
		rtcp, err := bind(host, p+1)
		if err != nil {
			media.Close()
			lastErr = err
			continue
		}
		return &Conn{media: media, rtcp: rtcp}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no free even/odd port pair after 100 tries")
	}
	return nil, fmt.Errorf("rist: socket: bind ephemeral even/odd pair: %w", lastErr)
}

// ListenEphemeralFamily is ListenEphemeral with an explicit address family
// ("udp4" or "udp6"). A multicast sender must bind its egress socket in the
// group's family: a dual-stack ("udp", [::]) socket cannot have an IPv4
// multicast interface/TTL set on it (the ipv4 socket options reject a
// v6-bound fd with EINVAL). network "udp" (the default) preserves the
// dual-stack unicast behavior.
func ListenEphemeralFamily(network, host string) (*Conn, error) {
	media, err := bindNet(network, host, 0)
	if err != nil {
		return nil, fmt.Errorf("rist: socket: bind media: %w", err)
	}
	rtcp, err := bindNet(network, host, 0)
	if err != nil {
		media.Close()
		return nil, fmt.Errorf("rist: socket: bind rtcp: %w", err)
	}
	return &Conn{media: media, rtcp: rtcp}, nil
}

// ListenEphemeralSingleFamily is ListenEphemeralSingle with an explicit address
// family ("udp4"/"udp6"); see ListenEphemeralFamily for why a multicast sender
// needs it.
func ListenEphemeralSingleFamily(network, host string) (*Conn, error) {
	c, err := bindNet(network, host, 0)
	if err != nil {
		return nil, fmt.Errorf("rist: socket: bind main: %w", err)
	}
	return &Conn{media: c, rtcp: c, single: true}, nil
}

// FromConns wraps two already-bound UDP sockets (media even, rtcp odd). It
// lets a caller inject sockets — for tests or to satisfy a PacketConn-style
// API — and takes ownership: Close closes both.
func FromConns(media, rtcp *net.UDPConn) *Conn {
	return &Conn{media: media, rtcp: rtcp}
}

// ListenSingle binds one UDP socket on host:port for the Main profile, where a
// single GRE-tunnelled port carries both media and feedback (TR-06-2). Unlike
// Listen it accepts any port (the Main port is not constrained to be even);
// host may be empty to bind all interfaces. It is the Main receiver-side
// constructor. Reads and writes use ReadMedia/WriteMedia on the single socket.
func ListenSingle(host string, port int) (*Conn, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("rist: socket: main port %d out of range", port)
	}
	c, err := bind(host, port)
	if err != nil {
		return nil, fmt.Errorf("rist: socket: bind main port %d: %w", port, err)
	}
	return &Conn{media: c, rtcp: c, single: true}, nil
}

// ListenEphemeralSingle binds one OS-chosen UDP socket on host (empty host
// binds all interfaces) for the Main profile. It is the Main sender-side
// constructor; the receiver learns the local port from inbound datagrams.
func ListenEphemeralSingle(host string) (*Conn, error) {
	c, err := bind(host, 0)
	if err != nil {
		return nil, fmt.Errorf("rist: socket: bind main: %w", err)
	}
	return &Conn{media: c, rtcp: c, single: true}, nil
}

// bind opens an unconnected UDP socket on host:port using the dual-stack "udp"
// network (the default unicast behavior).
func bind(host string, port int) (*net.UDPConn, error) {
	return bindNet("udp", host, port)
}

// bindNet opens an unconnected UDP socket on host:port in the given network
// ("udp", "udp4", or "udp6"). An empty network defaults to "udp".
func bindNet(network, host string, port int) (*net.UDPConn, error) {
	if network == "" {
		network = "udp"
	}
	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	if host == "" {
		addr.IP = nil
	}
	return net.ListenUDP(network, addr)
}

// MediaPort returns the local media (even) port the transport is bound to.
func (c *Conn) MediaPort() int { return c.media.LocalAddr().(*net.UDPAddr).Port }

// ReadMedia reads one media (RTP) datagram into buf, returning the byte count
// and the source address (the sender's media address, for a receiver). When DTLS
// is enabled (Main profile), it returns the next decrypted application record and
// the established peer's address.
//
// It uses (*net.UDPConn).ReadFromUDPAddrPort so the per-datagram receive path is
// allocation-free: a netip.AddrPort is a value type, so the source address is not
// heap-allocated the way ReadFromUDP's *net.UDPAddr was.
func (c *Conn) ReadMedia(buf []byte) (int, netip.AddrPort, error) {
	if c.dtls != nil {
		n, err := c.dtls.Read(buf)
		return n, c.dtlsPeer, err
	}
	return c.media.ReadFromUDPAddrPort(buf)
}

// ReadRTCP reads one RTCP datagram into buf, returning the byte count and the
// source address. Like ReadMedia it reads via ReadFromUDPAddrPort (alloc-free).
func (c *Conn) ReadRTCP(buf []byte) (int, netip.AddrPort, error) {
	return c.rtcp.ReadFromUDPAddrPort(buf)
}

// WriteMedia sends a media (RTP) datagram to dst. When DTLS is enabled (Main
// profile) it seals b as a DTLS application record to the established peer and
// dst is ignored (the DTLS session is bound to one peer).
func (c *Conn) WriteMedia(b []byte, dst netip.AddrPort) error {
	if c.dtls != nil {
		_, err := c.dtls.Write(b)
		return err
	}
	_, err := c.media.WriteToUDPAddrPort(b, dst)
	return err
}

// WriteRTCP sends an RTCP datagram to dst.
func (c *Conn) WriteRTCP(b []byte, dst netip.AddrPort) error {
	_, err := c.rtcp.WriteToUDPAddrPort(b, dst)
	return err
}

// Close closes both sockets, unblocking any in-flight reads (which return a
// net.ErrClosed-wrapped error). It is safe to call more than once.
func (c *Conn) Close() error {
	err := c.media.Close()
	if c.single {
		return err // media and rtcp are the same socket; close it once
	}
	if e := c.rtcp.Close(); e != nil && err == nil {
		err = e
	}
	return err
}
