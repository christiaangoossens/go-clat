package integration

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

const (
	// largeDatagram does not fit in one packet on either side, so it is always fragmented.
	largeDatagram = 4000

	// internetFragment is the largest fragment the remote host sends over its 1500-byte link: the IPv6 and fragment
	// headers and 1448 bytes of data, the largest multiple of 8 that fits.
	internetFragment = 40 + 8 + 1448
)

// testLargeUDPToInternet sends a datagram that the CLAT host's kernel fragments to fit the IPv4 tun. go-clat
// translates each IPv4 fragment into an IPv6 fragment.
func testLargeUDPToInternet(t *testing.T, peer netns.NsHandle) {
	var remote *net.UDPConn
	err := inNetns(peer, func() (err error) {
		remote, err = net.ListenUDP("udp6", &net.UDPAddr{IP: remoteAddr.IP, Port: 9})
		return err
	})
	must(t, err)
	defer remote.Close()

	onUplink := capturePackets(t, clatUplink)

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: remoteIPv4, Port: 9})
	must(t, err)
	defer conn.Close()

	datagram := randomBytes(largeDatagram)
	_, err = conn.Write(datagram)
	must(t, err)

	must(t, remote.SetReadDeadline(time.Now().Add(3*time.Second)))
	buffer := make([]byte, 65535)
	n, err := remote.Read(buffer)
	if err != nil {
		t.Fatalf("the remote host got no datagram: %v", err)
	}

	if !bytes.Equal(buffer[:n], datagram) {
		t.Errorf("the remote host got %d bytes that differ from the %d bytes sent", n, len(datagram))
	}

	sent, _ := onUplink.largest()
	expectLargest(t, "IPv6 packet sent to the internet", sent, fullSizeFragment)
}

// testLargeUDPFromInternet gets a large datagram back from the echo server, which fragments it for its 1500-byte link.
// The CLAT host's kernel reassembles it for conntrack and forwards the fragments unchanged into the 1500-byte IPv6 tun.
// go-clat translates them into IPv4 fragments that are larger than the IPv4 tun's MTU, which the kernel accepts,
// because an MTU only limits what is sent. So the first datagram arrives, without a Packet Too Big that the remote host
// might never get.
func testLargeUDPFromInternet(t *testing.T, peer netns.NsHandle) {
	var remoteICMP *icmp.PacketConn
	err := inNetns(peer, func() (err error) {
		remoteICMP, err = icmp.ListenPacket("ip6:ipv6-icmp", remoteAddr.IP.String())
		return err
	})
	must(t, err)
	defer remoteICMP.Close()

	ipv4Tun, ipv6Tun := clatTuns(t)
	onIPv4Tun := capturePackets(t, ipv4Tun)
	onIPv6Tun := capturePackets(t, ipv6Tun)

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: remoteIPv4, Port: echoPort})
	must(t, err)
	defer conn.Close()

	expectEcho(t, conn, randomBytes(largeDatagram))
	expectNoICMP(t, remoteICMP, ipv6.ICMPTypePacketTooBig)

	read, _ := onIPv6Tun.largest()
	_, written := onIPv4Tun.largest()
	expectLargest(t, "IPv6 packet go-clat read", read, internetFragment)
	expectLargest(t, "IPv4 packet go-clat wrote", written, internetFragment-40-8+20)
}
