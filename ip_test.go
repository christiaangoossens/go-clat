package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// A checksum-neutral address gives the same UDP checksum as the IPv4 address it stands for. This checks it with the
// test's own checksum code (internetChecksum), against a peer in the (also neutral) Well-Known Prefix.
func TestGenerateIPv6AddressIsChecksumNeutral(t *testing.T) {
	ipv4 := getIPv4TunAddress()
	_, ipv6Net, _ := net.ParseCIDR("2001:db8:1::/64")

	ipv4Packet := ipv4UDPPacket(t, ipv4.String(), remoteIPv4, 64)
	ipv4Checksum := binary.BigEndian.Uint16(ipv4Packet[20+6:])

	for range 100 {
		ipv6, err := generateIPv6Address(ipv4, ipv6Net)
		if err != nil {
			t.Fatal(err)
		}

		if !ipv6Net.Contains(ipv6) {
			t.Fatalf("%s is outside %s", ipv6, ipv6Net)
		}

		if !bytes.Equal(ipv6[12:], ipv4.To4()) {
			t.Fatalf("%s does not end in %s", ipv6, ipv4)
		}

		ipv6Packet := ipv6UDPPacket(t, ipv6.String(), remoteIPv6, 64)
		if got := binary.BigEndian.Uint16(ipv6Packet[40+6:]); got != ipv4Checksum {
			t.Fatalf("UDP checksum from %s is %#04x, from %s it is %#04x", ipv6, got, ipv4, ipv4Checksum)
		}
	}
}

func TestGenerateIPv6AddressRandomizesHostBits(t *testing.T) {
	_, ipv6Net, _ := net.ParseCIDR("2001:db8:1::/64")

	first, _ := generateIPv6Address(getIPv4TunAddress(), ipv6Net)
	second, _ := generateIPv6Address(getIPv4TunAddress(), ipv6Net)

	if first.Equal(second) {
		t.Errorf("two calls both returned %s", first)
	}
}

func TestGenerateIPv6AddressKeepsUnalignedPrefix(t *testing.T) {
	_, ipv6Net, _ := net.ParseCIDR("2001:db8:1:f0::/60")

	for range 100 {
		ipv6, err := generateIPv6Address(getIPv4TunAddress(), ipv6Net)
		if err != nil {
			t.Fatal(err)
		}

		if !ipv6Net.Contains(ipv6) {
			t.Fatalf("%s is outside %s", ipv6, ipv6Net)
		}
	}
}

func TestGenerateIPv6AddressPrefixLimit(t *testing.T) {
	tests := []struct {
		prefix string
		valid  bool
	}{
		{"2001:db8:1::/80", true},
		{"2001:db8:1::/81", false},
		{"2001:db8:1::1/128", false},
	}

	for _, test := range tests {
		_, ipv6Net, _ := net.ParseCIDR(test.prefix)

		_, err := generateIPv6Address(getIPv4TunAddress(), ipv6Net)
		if (err == nil) != test.valid {
			t.Errorf("%s: got error %v, want valid=%v", test.prefix, err, test.valid)
		}
	}
}

func TestToPrefixUnmapsIPv4(t *testing.T) {
	ipNet := &net.IPNet{IP: net.IPv4(192, 0, 0, 0), Mask: net.CIDRMask(29, 32)} // a 16-byte IP

	prefix := toPrefix(ipNet)
	if !prefix.Addr().Is4() || prefix.Bits() != 29 {
		t.Errorf("got %s, want 192.0.0.0/29 as IPv4", prefix)
	}
}
