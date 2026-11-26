package integration

import (
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// Packet sizes around go-clat's tuns. Translating a full-size IPv4 packet adds 20 bytes (the IPv6 header is longer);
// a fragment also gets an 8-byte fragment header, which makes it exactly the IPv6 minimum MTU of 1280.
const (
	ipv4TunMTU       = 1252
	fullSizeIPv6     = ipv4TunMTU + 20
	fullSizeFragment = ipv4TunMTU + 20 + 8
)

// testDontFragmentLimit checks that the kernel refuses a packet with Don't Fragment that does not fit the IPv4 tun,
// so go-clat never gets a packet it would have to split.
func testDontFragmentLimit(t *testing.T) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: remoteIPv4, Port: echoPort})
	must(t, err)
	defer conn.Close()

	raw, err := conn.SyscallConn()
	must(t, err)

	var sockErr error
	must(t, raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
	}))
	must(t, sockErr)

	fits := ipv4TunMTU - 20 - 8 // IPv4 and UDP headers
	if _, err := conn.Write(make([]byte, fits)); err != nil {
		t.Errorf("writing %d bytes with Don't Fragment: %v, want it to fit", fits, err)
	}

	if _, err := conn.Write(make([]byte, fits+1)); !errors.Is(err, unix.EMSGSIZE) {
		t.Errorf("writing %d bytes with Don't Fragment: %v, want EMSGSIZE", fits+1, err)
	}
}

func expectLargest(t *testing.T, what string, got, want int) {
	t.Helper()

	if got != want {
		t.Errorf("largest %s: %d bytes, want %d", what, got, want)
	}
}
