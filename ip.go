package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"
)

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

func getPublicIPv6() (*net.IPNet, *net.Interface, error) {
	// Get the IPv6 prefix from the first global IPv6 address
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, nil, err
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && ipNet.IP.To4() == nil && ipNet.IP.IsGlobalUnicast() {
				// Get the prefix from this address
				_, ipNet, err := net.ParseCIDR(ipNet.String())
				if err != nil {
					return nil, nil, err
				}

				// Log the prefix found
				log.Printf("Discovered IPv6 prefix %s on interface %s", ipNet, iface.Name)

				return ipNet, &iface, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("No global IPv6 address found")
}

// CalculateChecksumDelta calculates the necessary delta value to maintain checksum neutrality.
func calculateChecksumDelta(ipv4 net.IP, ipv6 net.IP) uint16 {
	sum := func(data []byte) uint32 {
		var s uint32
		for i := 0; i < len(data)-1; i += 2 {
			s += uint32(binary.BigEndian.Uint16(data[i:]))
		}
		return s
	}

	// Calculate the initial checksum over the IPv4 address and lower 8 bytes of IPv6
	ipv4PseudoPartial := make([]byte, 12)
	copy(ipv4PseudoPartial[0:4], ipv4)
	ipSum := sum(ipv4PseudoPartial) + sum(ipv6[8:])

	// The checksum delta we need to apply
	delta := -int16((ipSum + (ipSum >> 16)) & 0xFFFF)
	return uint16(delta)
}

// GenerateRandomBytes generates random bytes for the non-checksum-neutral part using a custom random source.
func generateRandomBytes(length int, seed int64) []byte {
	r := rand.New(rand.NewSource(seed)) // Use a new random source with the specified seed
	bytes := make([]byte, length)
	for i := range bytes {
		bytes[i] = byte(r.Intn(256))
	}
	return bytes
}

func generateIPv6Address(ipv4Addr net.IP, ipv6Net *net.IPNet) (net.IP, error) {
	// Parse the IPv4 address
	ipv4 := ipv4Addr.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("invalid IPv4 address, not in 4-byte format")
	}

	prefixLen, _ := ipv6Net.Mask.Size()

	// Construct initial IPv6 with the prefix
	ipv6 := make(net.IP, net.IPv6len)
	copy(ipv6, ipv6Net.IP)

	// Define where the IPv4 embedded address starts
	startIdx := prefixLen / 8

	// Fill the remaining bytes with random values and control checksum neutrality
	if startIdx < 12 {
		// Fill the middle part with random values using a seed based on the current time
		copy(ipv6[startIdx:12], generateRandomBytes(12-startIdx, time.Now().UnixNano()))
	}

	// Embed the checksum-neutral IPv4 value
	binary.BigEndian.PutUint32(ipv6[12:], binary.BigEndian.Uint32(ipv4))

	// Calculate necessary checksum-neutral delta
	delta := calculateChecksumDelta(ipv4, ipv6)
	ipv6[15] -= byte(delta & 0xFF)

	// Return the generated IPv6 address
	return ipv6, nil
}
