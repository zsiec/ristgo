//go:build linux

package tun

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Open creates a Linux TUN device by opening /dev/net/tun and issuing TUNSETIFF with
// IFF_TUN|IFF_NO_PI (a layer-3 device whose reads/writes are raw IP packets, no
// 4-byte packet-info prefix). requestedName picks the interface name ("" lets the
// kernel assign tunN); the assigned name is available via [Device.Name]. Mirrors
// libRIST's rist_tun_open. Requires CAP_NET_ADMIN.
func Open(requestedName string) (*Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("rist: tun: open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(requestedName)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("rist: tun: ifreq %q: %w", requestedName, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("rist: tun: TUNSETIFF: %w", err)
	}
	return &Device{fd: fd, name: ifr.Name()}, nil
}

// Read reads one IP packet from the device into p.
func (d *Device) Read(p []byte) (int, error) { return unix.Read(d.fd, p) }

// Write writes one IP packet from p to the device.
func (d *Device) Write(p []byte) (int, error) { return unix.Write(d.fd, p) }

// Close closes the device, unblocking any in-flight Read/Write.
func (d *Device) Close() error { return unix.Close(d.fd) }

// configSocket opens a throwaway AF_INET datagram socket for the SIOC* interface
// ioctls (these operate on a name, not the TUN fd; libRIST does the same).
func configSocket() (int, error) {
	return unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
}

// SetIP assigns IPv4 address ip (a dotted-quad) with prefixLen (0–32) to interface
// dev. Mirrors libRIST's rist_tun_set_ip.
func SetIP(dev, ip string, prefixLen int) error {
	if prefixLen < 0 || prefixLen > 32 {
		return fmt.Errorf("rist: tun: prefix length %d out of range [0,32]", prefixLen)
	}
	addr := net.ParseIP(ip).To4()
	if addr == nil {
		return fmt.Errorf("rist: tun: %q is not an IPv4 address", ip)
	}
	s, err := configSocket()
	if err != nil {
		return fmt.Errorf("rist: tun: config socket: %w", err)
	}
	defer unix.Close(s)

	ifr, err := unix.NewIfreq(dev)
	if err != nil {
		return err
	}
	if err := ifr.SetInet4Addr(addr); err != nil {
		return err
	}
	if err := unix.IoctlIfreq(s, unix.SIOCSIFADDR, ifr); err != nil {
		return fmt.Errorf("rist: tun: SIOCSIFADDR: %w", err)
	}
	mask := net.CIDRMask(prefixLen, 32)
	nfr, err := unix.NewIfreq(dev)
	if err != nil {
		return err
	}
	if err := nfr.SetInet4Addr([]byte(mask)); err != nil {
		return err
	}
	if err := unix.IoctlIfreq(s, unix.SIOCSIFNETMASK, nfr); err != nil {
		return fmt.Errorf("rist: tun: SIOCSIFNETMASK: %w", err)
	}
	return nil
}

// SetMTU sets the link MTU of interface dev. Mirrors libRIST's rist_tun_set_mtu.
func SetMTU(dev string, mtu int) error {
	s, err := configSocket()
	if err != nil {
		return fmt.Errorf("rist: tun: config socket: %w", err)
	}
	defer unix.Close(s)
	ifr, err := unix.NewIfreq(dev)
	if err != nil {
		return err
	}
	ifr.SetUint32(uint32(mtu))
	if err := unix.IoctlIfreq(s, unix.SIOCSIFMTU, ifr); err != nil {
		return fmt.Errorf("rist: tun: SIOCSIFMTU: %w", err)
	}
	return nil
}

// BringUp brings interface dev administratively up (sets IFF_UP). Mirrors libRIST's
// rist_tun_bring_up.
func BringUp(dev string) error {
	s, err := configSocket()
	if err != nil {
		return fmt.Errorf("rist: tun: config socket: %w", err)
	}
	defer unix.Close(s)
	ifr, err := unix.NewIfreq(dev)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(s, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("rist: tun: SIOCGIFFLAGS: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(s, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("rist: tun: SIOCSIFFLAGS: %w", err)
	}
	return nil
}
