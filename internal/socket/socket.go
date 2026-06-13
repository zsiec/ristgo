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
// even/odd split mirror libRIST (src/rist.c:1081-1108 bind, src/peer.c address
// matching).
//
// This package only moves bytes; it never parses RTP/RTCP or touches the flow
// core. Read/Write are safe for concurrent use across the two sockets (each
// *net.UDPConn is independently goroutine-safe), which is how the host runs a
// reader goroutine per socket alongside the event loop.
package socket

import (
	"fmt"
	"net"
)

// Conn is a RIST UDP transport. For the Simple profile it holds a media socket
// (even port) and an RTCP socket (odd port). For the Main profile it holds one
// socket carrying everything: media and rtcp both alias it and single is true.
type Conn struct {
	media  *net.UDPConn
	rtcp   *net.UDPConn
	single bool // Main profile: media == rtcp, one socket carries everything
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

// bind opens an unconnected UDP socket on host:port.
func bind(host string, port int) (*net.UDPConn, error) {
	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	if host == "" {
		addr.IP = nil
	}
	return net.ListenUDP("udp", addr)
}

// MediaPort returns the local media (even) port the transport is bound to.
func (c *Conn) MediaPort() int { return c.media.LocalAddr().(*net.UDPAddr).Port }

// ReadMedia reads one media (RTP) datagram into buf, returning the byte count
// and the source address (the sender's media address, for a receiver).
func (c *Conn) ReadMedia(buf []byte) (int, *net.UDPAddr, error) {
	return c.media.ReadFromUDP(buf)
}

// ReadRTCP reads one RTCP datagram into buf, returning the byte count and the
// source address.
func (c *Conn) ReadRTCP(buf []byte) (int, *net.UDPAddr, error) {
	return c.rtcp.ReadFromUDP(buf)
}

// WriteMedia sends a media (RTP) datagram to dst.
func (c *Conn) WriteMedia(b []byte, dst *net.UDPAddr) error {
	_, err := c.media.WriteToUDP(b, dst)
	return err
}

// WriteRTCP sends an RTCP datagram to dst.
func (c *Conn) WriteRTCP(b []byte, dst *net.UDPAddr) error {
	_, err := c.rtcp.WriteToUDP(b, dst)
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
