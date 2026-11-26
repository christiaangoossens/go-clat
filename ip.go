package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
)

// toAddr converts a net.IP, unmapping IPv4 addresses stored in 16 bytes.
func toAddr(ip net.IP) netip.Addr {
	addr, _ := netip.AddrFromSlice(ip)
	return addr.Unmap()
}

func toPrefix(ipNet *net.IPNet) netip.Prefix {
	bits, _ := ipNet.Mask.Size()
	return netip.PrefixFrom(toAddr(ipNet.IP), bits)
}

// Fixed IPv4 tunnel address
// TODO: Make dynamic and actually check if it's available
func getIPv4TunAddress() net.IP {
	return net.IPv4(192, 0, 0, 1)
}

func getIPv4RouterAddress() net.IP {
	return net.IPv4(192, 0, 0, 254)
}

// Return the two addresses to be used for the tun net
func getIPv6TunNet(ipv4Addr net.IP) (net.IP, net.IP) {
	// Make net from fdb1:5394:aa52:6464:6464::/64
	ip, net, err := net.ParseCIDR("fdb1:5394:aa52:6464:6464::/64")
	if err != nil {
		log.Fatal(err)
	}

	ip2, err := generateIPv6Address(ipv4Addr, net)
	if err != nil {
		log.Fatal(err)
	}

	return ip, ip2
}

// ipv6Candidate is an IPv6 address on an interface that is up, as its prefix.
type ipv6Candidate struct {
	prefix *net.IPNet
	iface  net.Interface
}

// getPublicIPv6 returns the prefix and interface to send translated packets from.
func getPublicIPv6() (*net.IPNet, *net.Interface, error) {
	candidates, err := ipv6Candidates()
	if err != nil {
		return nil, nil, err
	}

	chosen, err := choosePublicIPv6(candidates)
	if err != nil {
		return nil, nil, err
	}

	log.Printf("Discovered IPv6 prefix %s on interface %s", chosen.prefix, chosen.iface.Name)
	return chosen.prefix, &chosen.iface, nil
}

func ipv6Candidates() ([]ipv6Candidate, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var candidates []ipv6Candidate
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() != nil {
				continue
			}

			prefix := &net.IPNet{IP: ipNet.IP.Mask(ipNet.Mask), Mask: ipNet.Mask}
			candidates = append(candidates, ipv6Candidate{prefix: prefix, iface: iface})
		}
	}

	return candidates, nil
}

// choosePublicIPv6 picks the first global unicast prefix. Go counts unique local addresses (fc00::/7) as global
// unicast, but they cannot reach a NAT64 service on the internet, so a ULA is only chosen when there is nothing else
// (for example a NAT64 on the local router).
func choosePublicIPv6(candidates []ipv6Candidate) (ipv6Candidate, error) {
	var ula *ipv6Candidate

	for i, candidate := range candidates {
		ip := candidate.prefix.IP
		if !ip.IsGlobalUnicast() {
			continue
		}

		if !ip.IsPrivate() {
			return candidate, nil
		}

		if ula == nil {
			ula = &candidates[i]
		}
	}

	if ula != nil {
		log.Printf("No global IPv6 address found, using unique local prefix %s", ula.prefix)
		return *ula, nil
	}

	return ipv6Candidate{}, fmt.Errorf("No global IPv6 address found")
}

// onesComplementSum folds the 16-bit words of data into a ones' complement sum, as the internet checksum does.
func onesComplementSum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(sum)
}

func onesComplementAdd(a, b uint16) uint16 {
	sum := uint32(a) + uint32(b)
	return uint16(sum&0xffff + sum>>16)
}

// generateIPv6Address returns a random address in ipv6Net that ends in ipv4Addr and is checksum-neutral to it (as
// described in RFC 6052 Section 4.1), so translating between the two leaves transport checksums unchanged. It is used
// through an EAM entry, not as an RFC 6052 address. Bytes 10-11 balance the sum, so the prefix can be at most /80.
func generateIPv6Address(ipv4Addr net.IP, ipv6Net *net.IPNet) (net.IP, error) {
	ipv4 := ipv4Addr.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("invalid IPv4 address %s", ipv4Addr)
	}

	prefixLen, bits := ipv6Net.Mask.Size()
	if bits != 8*net.IPv6len || prefixLen > 80 {
		return nil, fmt.Errorf("IPv6 prefix %s must be /80 or shorter to generate an address in it "+
			"(a /128 address, as DHCPv6 hands out, is not supported)", ipv6Net)
	}

	ipv6 := make(net.IP, net.IPv6len)
	rand.Read(ipv6[:10]) // never fails since Go 1.24
	for i := range ipv6[:10] {
		ipv6[i] = ipv6Net.IP[i]&ipv6Net.Mask[i] | ipv6[i]&^ipv6Net.Mask[i]
	}

	copy(ipv6[12:], ipv4)

	// Bytes 10-11 are still zero, so this is the sum of everything else.
	balance := onesComplementAdd(onesComplementSum(ipv4), ^onesComplementSum(ipv6))
	binary.BigEndian.PutUint16(ipv6[10:], balance)

	return ipv6, nil
}
