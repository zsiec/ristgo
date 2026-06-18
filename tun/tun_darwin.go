//go:build darwin

package tun

import (
	"encoding/binary"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// macOS utun control name and the getsockopt that returns the assigned "utunN" name.
const (
	utunControlName = "com.apple.net.utun_control"
	utunOptIfname   = 2 // UTUN_OPT_IFNAME (sys/kern_control.h)
	sysprotoControl = 2 // SYSPROTO_CONTROL (sys/sys_domain.h); not exported by x/sys/unix
)

// Open creates a macOS utun device. requestedName picks a specific unit ("utun3" →
// unit 4); "" lets the kernel assign the next free unit. utun reads/writes carry a
// 4-byte address-family prefix on the wire, which Read strips and Write adds, so the
// API exchanges raw IP packets like the Linux path. Requires root.
func Open(requestedName string) (*Device, error) {
	unit, err := utunUnit(requestedName)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("rist: tun: socket(AF_SYSTEM): %w", err)
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("rist: tun: utun control info: %w", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: uint32(unit)}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("rist: tun: connect utun: %w", err)
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("rist: tun: utun name: %w", err)
	}
	return &Device{fd: fd, name: name}, nil
}

// utunUnit maps a requested "utunN" name to the connect unit (N+1); "" → 0 (the
// kernel assigns the next free unit).
func utunUnit(name string) (int, error) {
	if name == "" {
		return 0, nil
	}
	n, ok := strings.CutPrefix(name, "utun")
	if !ok {
		return 0, fmt.Errorf("rist: tun: macOS device name %q must be \"utunN\" or empty", name)
	}
	num, err := strconv.Atoi(n)
	if err != nil || num < 0 {
		return 0, fmt.Errorf("rist: tun: invalid utun unit in %q", name)
	}
	return num + 1, nil
}

// Read reads one IP packet, stripping the 4-byte utun address-family prefix.
func (d *Device) Read(p []byte) (int, error) {
	buf := make([]byte, len(p)+4)
	n, err := unix.Read(d.fd, buf)
	if err != nil {
		return 0, err
	}
	if n <= 4 {
		return 0, nil // header only / runt: no IP payload
	}
	return copy(p, buf[4:n]), nil
}

// Write writes one IP packet, prepending the 4-byte utun address-family prefix
// inferred from the IP version (AF_INET / AF_INET6).
func (d *Device) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	af := uint32(unix.AF_INET)
	if p[0]>>4 == 6 {
		af = unix.AF_INET6
	}
	buf := make([]byte, len(p)+4)
	binary.BigEndian.PutUint32(buf[:4], af)
	copy(buf[4:], p)
	n, err := unix.Write(d.fd, buf)
	if n > 4 {
		n -= 4
	} else {
		n = 0
	}
	return n, err
}

// Close closes the device.
func (d *Device) Close() error { return unix.Close(d.fd) }

// SetIP assigns IPv4 address ip/prefixLen to interface dev. macOS configures a utun
// point-to-point interface via ifconfig (the SIOCAIFADDR ioctl alias struct is gnarly
// and platform-fragile); the address is set as its own peer.
func SetIP(dev, ip string, prefixLen int) error {
	if prefixLen < 0 || prefixLen > 32 {
		return fmt.Errorf("rist: tun: prefix length %d out of range [0,32]", prefixLen)
	}
	return ifconfig(dev, "inet", fmt.Sprintf("%s/%d", ip, prefixLen), ip)
}

// SetMTU sets the link MTU of interface dev.
func SetMTU(dev string, mtu int) error {
	return ifconfig(dev, "mtu", strconv.Itoa(mtu))
}

// BringUp brings interface dev administratively up.
func BringUp(dev string) error {
	return ifconfig(dev, "up")
}

// ifconfig runs /sbin/ifconfig <dev> <args...>, surfacing its stderr on failure.
func ifconfig(dev string, args ...string) error {
	cmd := exec.Command("/sbin/ifconfig", append([]string{dev}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("rist: tun: ifconfig %s %s: %w: %s", dev, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
