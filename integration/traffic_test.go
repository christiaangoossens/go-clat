package integration

import (
	"bytes"
	"net"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// TestCLAT starts go-clat in a network without IPv4 and checks that IPv4 traffic to 1.1.1.1 gets through it. The
// subtests run in order and share one go-clat process.
func TestCLAT(t *testing.T) {
	peer := setupNetwork(t)
	startFakeInternet(t, peer)

	t.Run("no IPv4 before go-clat starts", testNoIPv4)

	clat := startCLAT(t, nat64Prefix)

	t.Run("ping right after go-clat starts", testPing)
	t.Run("Router Advertisements are still accepted", testRouterAdvertisementsAccepted)
	t.Run("UDP echo", testUDPEcho)
	t.Run("closed port gets Port Unreachable", testPortUnreachable)
	t.Run("HTTP download of 1 MB", testHTTPDownload)
	t.Run("HTTP upload of 1 MB", testHTTPUpload)
	t.Run("large UDP to the internet", func(t *testing.T) { testLargeUDPToInternet(t, peer) })
	t.Run("large UDP from the internet", func(t *testing.T) { testLargeUDPFromInternet(t, peer) })
	t.Run("Don't Fragment packets must fit the IPv4 tun", testDontFragmentLimit)
	t.Run("TTL 1 gets Time Exceeded from the router address", testIPv4TimeExceeded)
	t.Run("IPv6 Time Exceeded gets back through SNAT", func(t *testing.T) { testIPv6TimeExceeded(t, peer) })
	t.Run("shutdown undoes go-clat's changes", func(t *testing.T) { testShutdown(t, clat) })
	t.Run("network-specific NAT64 prefixes", testNetworkSpecificPrefixes)
}

func testPing(t *testing.T) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	must(t, err)
	defer conn.Close()

	request := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 1, Seq: 1, Data: []byte("go-clat")}}
	sendICMP(t, conn, request, remoteIPv4)

	reply := receiveICMP(t, conn, remoteIPv4, ipv4.ICMPTypeEchoReply)
	if data := reply.Body.(*icmp.Echo).Data; string(data) != "go-clat" {
		t.Errorf("echo reply carries %q, want %q", data, "go-clat")
	}
}

func testUDPEcho(t *testing.T) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: remoteIPv4, Port: echoPort})
	must(t, err)
	defer conn.Close()

	expectEcho(t, conn, []byte("hello through go-clat"))
}

// expectEcho sends the datagram once to the echo server and checks that the same datagram comes back.
func expectEcho(t *testing.T, conn *net.UDPConn, datagram []byte) {
	t.Helper()

	must(t, conn.SetDeadline(time.Now().Add(3*time.Second)))

	_, err := conn.Write(datagram)
	must(t, err)

	buffer := make([]byte, 65535)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("no echo of %d bytes: %v", len(datagram), err)
	}

	if !bytes.Equal(buffer[:n], datagram) {
		t.Errorf("echo of %d bytes differs from the %d bytes sent", n, len(datagram))
	}
}
