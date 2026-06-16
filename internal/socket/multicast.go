package socket

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// IP multicast for the RIST transport. Group membership, the multicast hop limit
// (TTL), the egress/join interface, and loopback are not exposed by the standard
// library's *net.UDPConn, so this uses golang.org/x/net/ipv4 and .../ipv6, which
// wrap the same socket and reach the platform IP_* / IPV6_* socket options. The
// wrapping does not change byte movement: ReadMedia/WriteMedia still read and
// write the underlying *net.UDPConn; the x/net PacketConn only configures
// membership and the per-datagram TTL/interface once at setup.

// MulticastOptions configures IP-multicast behavior on a Conn. The zero value is
// "no multicast" — Conn is a plain unicast transport unless these are set.
type MulticastOptions struct {
	// Group is the multicast destination/bind group. A receiver joins it; a
	// sender stamps its egress options when transmitting to it. The zero Addr
	// means "not multicast" (unicast, the default).
	Group netip.Addr
	// Source, when set, selects source-specific multicast (SSM, RFC 4607): a
	// receiver joins the group filtered to this source IP. The zero Addr means
	// any-source multicast (ASM).
	Source netip.Addr
	// Iface is the membership (receiver) or egress (sender) interface; nil lets
	// the OS choose the system default.
	Iface *net.Interface
	// TTL is the sender's multicast hop limit; 0 leaves the OS default (1).
	TTL int
	// Loopback controls whether a sender receives its own multicast on the same
	// host.
	Loopback bool
}

// JoinMulticast joins opts.Group on the receiver's sockets so inbound group
// traffic is delivered. It joins on both the media and RTCP sockets (the Simple
// profile even/odd pair); for a single-socket Main/Advanced Conn the two alias
// one socket, so the second join is skipped. ASM uses JoinGroup; SSM (opts.Source
// set) uses JoinSourceSpecificGroup, restricting delivery to that source. It is a
// no-op when opts.Group is not a multicast address.
func (c *Conn) JoinMulticast(opts MulticastOptions) error {
	if !opts.Group.IsMulticast() {
		return nil
	}
	if err := joinOn(c.media.Load(), opts); err != nil {
		return err
	}
	if !c.single && c.rtcp.Load() != nil {
		if err := joinOn(c.rtcp.Load(), opts); err != nil {
			return err
		}
	}
	return nil
}

// joinOn joins the group on one UDP socket using the address-family-appropriate
// x/net PacketConn (ipv4 or ipv6).
func joinOn(pc *net.UDPConn, opts MulticastOptions) error {
	gaddr := &net.UDPAddr{IP: net.IP(opts.Group.AsSlice())}
	if opts.Group.Is4() {
		p := ipv4.NewPacketConn(pc)
		if opts.Source.IsValid() {
			src := &net.UDPAddr{IP: net.IP(opts.Source.AsSlice())}
			if err := p.JoinSourceSpecificGroup(opts.Iface, gaddr, src); err != nil {
				return fmt.Errorf("rist: socket: join SSM group %s from %s: %w", opts.Group, opts.Source, err)
			}
			return nil
		}
		if err := p.JoinGroup(opts.Iface, gaddr); err != nil {
			return fmt.Errorf("rist: socket: join group %s: %w", opts.Group, err)
		}
		return nil
	}
	p := ipv6.NewPacketConn(pc)
	if opts.Source.IsValid() {
		src := &net.UDPAddr{IP: net.IP(opts.Source.AsSlice())}
		if err := p.JoinSourceSpecificGroup(opts.Iface, gaddr, src); err != nil {
			return fmt.Errorf("rist: socket: join IPv6 SSM group %s from %s: %w", opts.Group, opts.Source, err)
		}
		return nil
	}
	if err := p.JoinGroup(opts.Iface, gaddr); err != nil {
		return fmt.Errorf("rist: socket: join IPv6 group %s: %w", opts.Group, err)
	}
	return nil
}

// SetMulticast configures the sender's outbound multicast options on its media
// (and, for the Simple even/odd pair, RTCP) socket: the egress interface, the
// multicast hop limit (TTL), and loopback. It is a no-op when opts.Group is not a
// multicast address. Only the options the caller set are applied (TTL 0 and a nil
// Iface leave the OS default in place).
func (c *Conn) SetMulticast(opts MulticastOptions) error {
	if !opts.Group.IsMulticast() {
		return nil
	}
	if err := setMulticastOn(c.media.Load(), opts); err != nil {
		return err
	}
	if !c.single && c.rtcp.Load() != nil {
		if err := setMulticastOn(c.rtcp.Load(), opts); err != nil {
			return err
		}
	}
	return nil
}

// setMulticastOn applies the sender egress options to one UDP socket via the
// address-family-appropriate x/net PacketConn.
func setMulticastOn(pc *net.UDPConn, opts MulticastOptions) error {
	if opts.Group.Is4() {
		p := ipv4.NewPacketConn(pc)
		if opts.Iface != nil {
			if err := p.SetMulticastInterface(opts.Iface); err != nil {
				return fmt.Errorf("rist: socket: set multicast interface: %w", err)
			}
		}
		if opts.TTL > 0 {
			if err := p.SetMulticastTTL(opts.TTL); err != nil {
				return fmt.Errorf("rist: socket: set multicast TTL: %w", err)
			}
		}
		if err := p.SetMulticastLoopback(opts.Loopback); err != nil {
			return fmt.Errorf("rist: socket: set multicast loopback: %w", err)
		}
		return nil
	}
	p := ipv6.NewPacketConn(pc)
	if opts.Iface != nil {
		if err := p.SetMulticastInterface(opts.Iface); err != nil {
			return fmt.Errorf("rist: socket: set IPv6 multicast interface: %w", err)
		}
	}
	if opts.TTL > 0 {
		if err := p.SetMulticastHopLimit(opts.TTL); err != nil {
			return fmt.Errorf("rist: socket: set IPv6 multicast hop limit: %w", err)
		}
	}
	if err := p.SetMulticastLoopback(opts.Loopback); err != nil {
		return fmt.Errorf("rist: socket: set IPv6 multicast loopback: %w", err)
	}
	return nil
}
