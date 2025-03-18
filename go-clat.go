package main

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	log.Printf("Starting GO-CLAT")

	nat64Net, err := getNAT64Prefix()
	if err != nil {
		log.Fatal(err)
	}

	ipv6Addr, ipv6Iface, err := getIPv6Src()
	if err != nil {
		log.Fatal(err)
	}

	iface, err := createIPv4Tun()

	if err != nil {
		log.Fatal(err)
	}

	/**
		 * Big open question:

		 * How do you listen for incoming packets on IPv6?
		 * Possibly: add extra IPv6 address and use pcap to listen for incoming packets on that address
		 * Or: listen with pcap for all incoming IPv6 packets and filter out matching packets originating from IPv4 prefix
		 * Make sure to exclude direct packets in that case

	     * After that: translating IPv4 packets into IPv6 packets and the other way around
		 * Just follow https://datatracker.ietf.org/doc/html/rfc6145

		 * Only focus on implementing ICMP, UDP and TCP, unicast.

		 * Total list of problems
		 * - Receiving IPv4 packet: Solved, just read from the tun interface
		 * - Sending IPv6 packet: Possible (raw socket send)
		 * - Translation: doable, just follow the RFC
		 * - Receiving IPv6 packet: Possible (raw socket per type)
		 * - Sending IPv4 packet: Solved, just write back to the tun interface
	*/

	// Listen for incoming packets with a certain origin (IPv6) and log them
	go func() {
		listenPCAP(ipv6Iface, ipv6Addr, nat64Net)
	}()

	/*go func() {
		listenIPv6TCP()
	}()

	go func() {
		listenIPv6UDP()
	}()*/

	// Define how to deal with incoming packets
	log.Printf("Listening for incoming IPv4 packets on %s", iface.Name())
	packet := make([]byte, 2000)
	for {
		n, err := iface.Read(packet)
		if err != nil {
			log.Fatal(err)
		}

		// Parse the IPv4 packet
		// Use gopacket to parse the IPv4 packet
		packetData := packet[:n]
		packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			// Not IPv4 packet, ignore because we are only translating IPv4 here
			continue
		}

		ip, _ := ipLayer.(*layers.IPv4)

		// https://datatracker.ietf.org/doc/html/rfc6145
		// Safeguards

		// Just ignore this packet, it's not a deliberate packet that we need to translate
		if ip.SrcIP.IsUnspecified() {
			continue
		}

		// If multicast, drop the packet
		if ip.DstIP.IsMulticast() {
			continue
		}

		// If the packet is fragmented ICMP, drop it
		// Source: Fragmented ICMP/ICMPv6 packets will not be translated by the IP/ICMP translator.
		if ip.Protocol == layers.IPProtocolICMPv4 &&
			(ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0) {
			log.Printf("Dropping fragmented ICMP packet")
			continue
		}

		// Drop packet if the packet is not a TCP, UDP or ICMP packet
		if ip.Protocol != layers.IPProtocolTCP &&
			ip.Protocol != layers.IPProtocolUDP &&
			ip.Protocol != layers.IPProtocolICMPv4 {
			log.Printf("Dropping packet with unsupported protocol %d", ip.Protocol)
			continue
		}

		log.Printf("IPv4 Packet: Src: %s, Dst: %s, Flags: %s, ID: %d, TTL: %d, Protocol: %s",
			ip.SrcIP, ip.DstIP, ip.Flags, ip.Id, ip.TTL, ip.Protocol)

		// Get NAT64 translated destination from the ip.DstIP
		// Map ip.DstIP onto the NAT64 prefix
		// Parse the NAT64 prefix into an IPv6 address

		// Map the IPv4 destination onto the NAT64 prefix
		ipv4Bytes := ip.DstIP.To4()
		if ipv4Bytes == nil {
			log.Printf("Invalid IPv4 address: %s", ip.DstIP)
			continue
		}

		nat64DstIP := nat64Net.IP
		copy(nat64DstIP[12:], ipv4Bytes)

		log.Printf("Translated IPv4 destination %s to NAT64 IPv6 destination %s",
			ip.DstIP, nat64DstIP)

	}
}
