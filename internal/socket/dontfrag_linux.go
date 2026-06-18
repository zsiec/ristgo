//go:build linux

package socket

import (
	"net"

	"golang.org/x/sys/unix"
)

// setDontFragment sets the IP Don't-Fragment bit on the UDP socket via Linux's
// path-MTU-discovery mode (IP_MTU_DISCOVER=IP_PMTUDISC_DO / the IPv6 equivalent), so
// an oversized datagram is dropped rather than IP-fragmented. Best-effort: both
// address families are attempted and any failure leaves the socket usable. Mirrors
// libRIST's udpsocket DF setup.
func setDontFragment(conn *net.UDPConn) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
	})
}
