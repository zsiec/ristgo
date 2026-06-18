//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package socket

import (
	"net"

	"golang.org/x/sys/unix"
)

// setDontFragment sets the IP Don't-Fragment bit on the UDP socket (BSD/macOS
// IP_DONTFRAG / IPV6_DONTFRAG), so an oversized datagram is dropped rather than
// IP-fragmented. It is best-effort: both address families are attempted (the
// wrong-family option simply errors and is ignored), and any failure leaves the
// socket usable. Mirrors libRIST's udpsocket DF setup.
func setDontFragment(conn *net.UDPConn) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
	})
}
