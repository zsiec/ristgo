// Package tun provides a minimal layer-3 TUN network device for carrying raw IP
// packets over a RIST session (libRIST's rist_tun_* API). An application reads IP
// packets from the device and sends them over a [ristgo.Sender] (or its out-of-band
// IP channel), and writes packets received over RIST back to the device — a simple
// IP-over-RIST tunnel.
//
// Open returns a [Device] whose Read and Write carry whole IP packets with no
// link-layer header (the macOS utun 4-byte address-family prefix is added and
// stripped internally, so the API is identical across platforms). Creating a TUN
// device requires elevated privileges (root / CAP_NET_ADMIN); Open returns the OS
// error (typically a permission error) otherwise.
//
// Supported platforms: Linux (/dev/net/tun) and macOS (utun). On every other
// platform Open returns [ErrUnsupported]. Mirrors libRIST, whose TUN support is
// Linux (and a Windows stub); macOS is a ristgo addition.
package tun

import "errors"

// ErrUnsupported is returned by [Open] and the configuration helpers on a platform
// without a TUN implementation.
var ErrUnsupported = errors.New("rist: tun: not supported on this platform")

// Device is an open TUN device. Read and Write exchange whole IP packets. A Device
// is safe for one reader goroutine concurrent with one writer goroutine (like a
// net.Conn); Close may be called from any goroutine to unblock them.
type Device struct {
	fd   int
	name string
}

// Name returns the kernel interface name of the device (e.g. "tun0" or "utun3"),
// for use with [SetIP], [SetMTU], [BringUp], or external tools.
func (d *Device) Name() string { return d.name }
