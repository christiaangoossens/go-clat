package main

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/christiaangoossens/go-siit"
)

const remoteIPv4 = "8.8.8.8"
const remoteIPv6 = "64:ff9b::808:808"

type testSetup struct {
	translator *siit.Translator
	publicIPv6 net.IP
	tunnelIPv6 net.IP
}

// newTestSetup builds the translator the way app() does, with the Well-Known Prefix and a documentation prefix as
// the public network.
func newTestSetup(t *testing.T) testSetup {
	t.Helper()

	_, nat64Net, _ := net.ParseCIDR("64:ff9b::/96")
	_, publicNet, _ := net.ParseCIDR("2001:db8:1::/64")

	publicIPv6, err := generateIPv6Address(getIPv4TunAddress(), publicNet)
	if err != nil {
		t.Fatal(err)
	}

	_, tunnelIPv6 := getIPv6TunNet(getIPv4TunAddress())

	translator, err := newTranslator(nat64Net, publicIPv6, tunnelIPv6)
	if err != nil {
		t.Fatalf("newTranslator: %v", err)
	}

	return testSetup{translator: translator, publicIPv6: publicIPv6, tunnelIPv6: tunnelIPv6}
}

// runIPv4Loop runs translateIPv4Loop until the fake tun is empty and returns what was forwarded.
func (s testSetup) runIPv4Loop(t *testing.T, ipv4Tun *fakeTun) []siit.Packet {
	t.Helper()

	var forwarded []siit.Packet
	forward := func(packet siit.Packet) error {
		forwarded = append(forwarded, append(siit.Packet(nil), packet...))
		return nil
	}

	if err := translateIPv4Loop(s.translator, ipv4Tun, forward); !errors.Is(err, io.EOF) {
		t.Fatalf("loop ended with %v, want io.EOF", err)
	}

	return forwarded
}

// runIPv6Loop runs translateIPv6Loop until the fake tun is empty and returns what was written to the IPv4 tun.
func (s testSetup) runIPv6Loop(t *testing.T, ipv6Tun *fakeTun) [][]byte {
	t.Helper()

	ipv4Out := &fakeTun{}
	if err := translateIPv6Loop(s.translator, ipv6Tun, ipv4Out, s.tunnelIPv6); !errors.Is(err, io.EOF) {
		t.Fatalf("loop ended with %v, want io.EOF", err)
	}

	return ipv4Out.written
}

func TestNewTranslatorAcceptsCLATConfig(t *testing.T) {
	newTestSetup(t)
}

func TestRoundTrip(t *testing.T) {
	setup := newTestSetup(t)

	// Outgoing: host -> IPv4 tun -> forwarded over IPv6.
	ipv4Tun := &fakeTun{incoming: [][]byte{ipv4UDPPacket(t, "192.0.0.1", remoteIPv4, 64)}}
	forwarded := setup.runIPv4Loop(t, ipv4Tun)

	if len(forwarded) != 1 || len(ipv4Tun.written) != 0 {
		t.Fatalf("forwarded %d packets and replied %d, want 1 and 0", len(forwarded), len(ipv4Tun.written))
	}

	assertAddresses(t, forwarded[0], mustAddr(t, setup.tunnelIPv6), netip.MustParseAddr(remoteIPv6))

	// Incoming: answer -> IPv6 tun -> IPv4 tun.
	ipv6Tun := &fakeTun{incoming: [][]byte{ipv6UDPPacket(t, remoteIPv6, setup.tunnelIPv6.String(), 64)}}
	translated := setup.runIPv6Loop(t, ipv6Tun)

	if len(translated) != 1 || len(ipv6Tun.written) != 0 {
		t.Fatalf("translated %d packets and replied %d, want 1 and 0", len(translated), len(ipv6Tun.written))
	}

	assertAddresses(t, translated[0], netip.MustParseAddr(remoteIPv4), netip.MustParseAddr("192.0.0.1"))
}

func TestIPv4TimeExceededGoesBackToIPv4Tun(t *testing.T) {
	setup := newTestSetup(t)

	ipv4Tun := &fakeTun{incoming: [][]byte{ipv4UDPPacket(t, "192.0.0.1", remoteIPv4, 1)}}
	if forwarded := setup.runIPv4Loop(t, ipv4Tun); len(forwarded) != 0 {
		t.Error("expired packet was forwarded")
	}

	if len(ipv4Tun.written) != 1 {
		t.Fatalf("got %d replies on the IPv4 tun, want 1", len(ipv4Tun.written))
	}

	assertAddresses(t, ipv4Tun.written[0], toAddr(getIPv4RouterAddress()), netip.MustParseAddr("192.0.0.1"))
}

func TestIPv6TimeExceededGoesBackToIPv6Tun(t *testing.T) {
	setup := newTestSetup(t)

	ipv6Tun := &fakeTun{incoming: [][]byte{ipv6UDPPacket(t, remoteIPv6, setup.tunnelIPv6.String(), 1)}}
	if translated := setup.runIPv6Loop(t, ipv6Tun); len(translated) != 0 {
		t.Error("expired packet was translated")
	}

	if len(ipv6Tun.written) != 1 {
		t.Fatalf("got %d replies on the IPv6 tun, want 1", len(ipv6Tun.written))
	}

	// The reply comes from the router address, which the EAM entry maps to the public IPv6 address.
	assertAddresses(t, ipv6Tun.written[0], mustAddr(t, setup.publicIPv6), netip.MustParseAddr(remoteIPv6))
}

// The packets here are ones go-siit would translate, so only go-clat's own filters can stop them.
func TestLoopsIgnoreForeignPackets(t *testing.T) {
	setup := newTestSetup(t)

	ipv4Tun := &fakeTun{incoming: [][]byte{
		ipv4UDPPacket(t, "1.1.1.1", remoteIPv4, 64),
		ipv6UDPPacket(t, setup.tunnelIPv6.String(), remoteIPv6, 64),
	}}
	if forwarded := setup.runIPv4Loop(t, ipv4Tun); len(forwarded)+len(ipv4Tun.written) != 0 {
		t.Error("a foreign packet on the IPv4 tun produced output")
	}

	ipv6Tun := &fakeTun{incoming: [][]byte{
		ipv6UDPPacket(t, remoteIPv6, "64:ff9b::101:101", 64),
		ipv4UDPPacket(t, remoteIPv4, "192.0.0.1", 64),
	}}
	if translated := setup.runIPv6Loop(t, ipv6Tun); len(translated)+len(ipv6Tun.written) != 0 {
		t.Error("a foreign packet on the IPv6 tun produced output")
	}
}

func assertAddresses(t *testing.T, packet []byte, src, dst netip.Addr) {
	t.Helper()

	p := siit.Packet(packet)
	if p.Src() != src || p.Dst() != dst {
		t.Errorf("got %s -> %s, want %s -> %s", p.Src(), p.Dst(), src, dst)
	}
}
