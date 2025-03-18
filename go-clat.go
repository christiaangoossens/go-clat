package main

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	log.Printf("Starting GO-CLAT")

	iface, err := createIPv4Tun()

	if err != nil {
		log.Fatal(err)
	}

	/**
		 * Big open questions:

		 * 1. How do you listen for incoming packets on IPv6?
		 * Possibly: add extra IPv6 address and use pcap to listen for incoming packets on that address
		 * Or: listen with pcap for all incoming IPv6 packets and filter out matching packets originating from IPv4 prefix
		 * Make sure to exclude direct packets in that case


	     * After that: translating IPv4 packets into IPv6 packets and the other way around
		 * Just follow https://datatracker.ietf.org/doc/html/rfc6145

		 * Only focus on implementing ICMP, UDP and TCP, unicast.
	*/

	// Listen for incoming packets with a certain origin (IPv6) and log them
	go func() {

	}()

	// Define how to deal with incoming packets
	packet := make([]byte, 2000)
	for {
		n, err := iface.Read(packet)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Packet Received: % x\n", packet[:n])

		// Parse the IPv4 packet
		// Use gopacket to parse the IPv4 packet
		packetData := packet[:n]
		packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			log.Printf("Not an IPv4 packet")
			continue
		}

		ip, _ := ipLayer.(*layers.IPv4)

		// https://datatracker.ietf.org/doc/html/rfc6145
		// Safeguards

		// Drop packet if origin is not actually our IP
		if ip.SrcIP.String() != "192.0.0.1" {
			log.Printf(
				"Dropping packet with incorrect source IP %s, CLAT doesn't support translating this.",
				ip.SrcIP.String(),
			)
			continue
		}

		// If multicast, drop the packet
		if ip.DstIP.IsMulticast() {
			log.Printf("Dropping multicast packet")
			continue
		}

		// If the packet is fragmented ICMP, drop it
		// Source: Fragmented ICMP/ICMPv6 packets will not be translated by the IP/ICMP translator.
		if ip.Protocol == layers.IPProtocolICMPv4 &&
			(ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0) {
			log.Printf("Dropping fragmented ICMP packet")
			continue
		}

		log.Printf("IPv4 Packet: Src: %s, Dst: %s, Flags: %s, ID: %d, TTL: %d, Protocol: %s",
			ip.SrcIP, ip.DstIP, ip.Flags, ip.Id, ip.TTL, ip.Protocol)

	}
}
