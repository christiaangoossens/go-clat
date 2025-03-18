package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func listenIPv6ICMP() {
	log.Printf("Listening for incoming ICMPv6 packets")

	// Open raw socket for IPv6 ICMP packets
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		fmt.Printf("Error opening socket: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)

	// Receive packets
	for {
		buffer := make([]byte, 4096)
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil {
			fmt.Printf("Error receiving data: %v\n", err)
			continue
		}

		packet := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv6, gopacket.Default)
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer == nil {
			fmt.Printf("Received ICMPv6 packet of length %d, but failed to parse IPv6 header\n", n)
			continue
		}

		ipv6 := ipv6Layer.(*layers.IPv6)
		fmt.Printf(
			"Received ICMPv6 packet: src=%s, dest=%s, length=%d, next_header=%d\n",
			ipv6.SrcIP,
			ipv6.DstIP,
			ipv6.Length,
			ipv6.NextHeader,
		)
	}
}

func listenIPv6TCP() {
	log.Printf("Listening for incoming TCP packets")

	// Open raw socket for IPv6 TCP packets
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		fmt.Printf("Error opening socket: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)

	for {
		buffer := make([]byte, 4096)
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil {
			fmt.Printf("Error receiving data: %v\n", err)
			continue
		}

		packet := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv6, gopacket.Default)
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer == nil {
			fmt.Printf("Received TCP packet of length %d, but failed to parse IPv6 header\n", n)
			continue
		}

		ipv6 := ipv6Layer.(*layers.IPv6)
		fmt.Printf(
			"Received TCP packet: src=%s, dest=%s, length=%d, next_header=%d\n",
			ipv6.SrcIP,
			ipv6.DstIP,
			ipv6.Length,
			ipv6.NextHeader,
		)
	}
}

func listenIPv6UDP() {
	log.Printf("Listening for incoming UDP packets")

	// Open raw socket for IPv6 UDP packets
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		fmt.Printf("Error opening socket: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)

	for {
		buffer := make([]byte, 4096)
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil {
			fmt.Printf("Error receiving data: %v\n", err)
			continue
		}

		log.Printf("Raw UDP packet (hex): %s", fmt.Sprintf("%x", buffer[:n]))

		packet := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv6, gopacket.Default)
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer == nil {
			fmt.Printf("Received UDP packet of length %d, but failed to parse IPv6 header\n", n)
			continue
		}

		ipv6 := ipv6Layer.(*layers.IPv6)
		fmt.Printf(
			"Received UDP packet: src=%s, dest=%s, length=%d, next_header=%d\n",
			ipv6.SrcIP,
			ipv6.DstIP,
			ipv6.Length,
			ipv6.NextHeader,
		)
	}
}

func listenPCAP(iface string, address net.IP, nat64Prefix *net.IPNet) {
	// Open the device for capturing
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", iface, err)
	}
	defer handle.Close()

	sourceNet := nat64Prefix.String()
	destNet := address.String() + "/128"

	// Filter to specific source & destinations (I'm only interested if this is the destination)
	filter := fmt.Sprintf("src net %s and dst net %s", sourceNet, destNet)

	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	log.Printf(
		"Listening for IPv6 return packets from the NAT64 prefix %s on interface %s",
		sourceNet,
		iface,
	)

	// Use a packet source to read packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		log.Printf("Packet captured")

		// Extract the IPv6 layer from the packet
		if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ipv6, _ := ipv6Layer.(*layers.IPv6) // Assert type
			log.Printf(
				"IPv6 Src: %s -> Dst: %s, protocol: %s\n",
				ipv6.SrcIP,
				ipv6.DstIP,
				ipv6.NextLayerType(),
			)
		}
	}
}
