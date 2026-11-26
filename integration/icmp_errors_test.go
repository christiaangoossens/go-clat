package integration

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// routerIPv4 is the address go-clat sends its own ICMP errors from on the IPv4 side.
var routerIPv4 = net.IPv4(192, 0, 0, 254)

// closedPort has no server on the remote host.
const closedPort = 9999

// testIPv4TimeExceeded sends UDP with TTL 1, which expires in go-clat. go-clat answers it on the IPv4 tun.
func testIPv4TimeExceeded(t *testing.T) {
	icmpConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	must(t, err)
	defer icmpConn.Close()

	udp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: remoteIPv4, Port: echoPort})
	must(t, err)
	defer udp.Close()

	must(t, ipv4.NewConn(udp).SetTTL(1))
	_, err = udp.Write([]byte("expires in go-clat"))
	must(t, err)

	receiveICMP(t, icmpConn, routerIPv4, ipv4.ICMPTypeTimeExceeded)
}

// testPortUnreachable sends UDP to a closed port. The remote host answers with an ICMPv6 Port Unreachable, which must
// come back through conntrack and go-clat as an ICMPv4 Port Unreachable, so the socket reports a refused connection.
func testPortUnreachable(t *testing.T) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: remoteIPv4, Port: closedPort})
	must(t, err)
	defer conn.Close()

	must(t, conn.SetDeadline(time.Now().Add(3*time.Second)))

	_, err = conn.Write([]byte("anyone there?"))
	must(t, err)

	_, err = conn.Read(make([]byte, 100))
	if !errors.Is(err, unix.ECONNREFUSED) {
		t.Errorf("reading the answer: %v, want ECONNREFUSED", err)
	}
}

// testIPv6TimeExceeded checks go-clat's return path through its SNAT rule. The remote host answers UDP with hop limit
// 2, so the answer expires in go-clat, which sends an ICMPv6 Time Exceeded back to the remote host. Conntrack must
// treat that error as related to the UDP flow, so the remote host sees its answer quoted as it sent it: to the public
// address, not to go-clat's internal tunnel address.
func testIPv6TimeExceeded(t *testing.T, peer netns.NsHandle) {
	var remoteUDP *net.UDPConn
	var remoteICMP *icmp.PacketConn

	err := inNetns(peer, func() error {
		var err error
		if remoteUDP, err = net.ListenUDP("udp6", &net.UDPAddr{IP: remoteAddr.IP, Port: 53}); err != nil {
			return err
		}

		remoteICMP, err = icmp.ListenPacket("ip6:ipv6-icmp", remoteAddr.IP.String())
		return err
	})
	must(t, err)
	defer remoteUDP.Close()
	defer remoteICMP.Close()

	must(t, ipv6.NewConn(remoteUDP).SetHopLimit(2))

	clatUDP, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: remoteIPv4, Port: 53})
	must(t, err)
	defer clatUDP.Close()

	_, err = clatUDP.Write([]byte("query"))
	must(t, err)

	client := answerOnce(t, remoteUDP)
	if public := publicAddrs(t); len(public) != 1 || !public[0].IP.Equal(client.Addr().AsSlice()) {
		t.Fatalf("the remote host got UDP from %s, want go-clat's public address %v: SNAT did not apply", client, public)
	}

	message := receiveICMP(t, remoteICMP, client.Addr().AsSlice(), ipv6.ICMPTypeTimeExceeded)
	from, to := quotedUDP(t, message.Body.(*icmp.TimeExceeded).Data)

	remote, _ := netip.AddrFromSlice(remoteAddr.IP)
	wantFrom := netip.AddrPortFrom(remote, 53)
	if from != wantFrom || to != client {
		t.Errorf("Time Exceeded quotes %s -> %s, want %s -> %s", from, to, wantFrom, client)
	}
}

// answerOnce echoes one datagram and returns where it came from.
func answerOnce(t *testing.T, conn *net.UDPConn) netip.AddrPort {
	t.Helper()

	must(t, conn.SetDeadline(time.Now().Add(3*time.Second)))

	buffer := make([]byte, 2048)
	n, from, err := conn.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatalf("the remote host got no UDP: %v", err)
	}

	_, err = conn.WriteToUDPAddrPort(buffer[:n], from)
	must(t, err)

	return netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
}

// quotedUDP returns the addresses of the IPv6 UDP packet that an ICMPv6 error quotes.
func quotedUDP(t *testing.T, quoted []byte) (from, to netip.AddrPort) {
	t.Helper()

	header, err := ipv6.ParseHeader(quoted)
	if err != nil {
		t.Fatalf("cannot parse the quoted packet: %v", err)
	}

	if header.NextHeader != unix.IPPROTO_UDP || len(quoted) < ipv6.HeaderLen+4 {
		t.Fatalf("the quoted packet is not UDP with its ports: %x", quoted)
	}

	ports := quoted[ipv6.HeaderLen:]
	src, _ := netip.AddrFromSlice(header.Src)
	dst, _ := netip.AddrFromSlice(header.Dst)

	return netip.AddrPortFrom(src, binary.BigEndian.Uint16(ports[0:])),
		netip.AddrPortFrom(dst, binary.BigEndian.Uint16(ports[2:]))
}
