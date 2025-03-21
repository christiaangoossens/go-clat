// https://github.com/ddrown/android_external_android-clat/blob/master/translate.c
package main

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func translateIPv4(packet gopacket.Packet, src net.IP, dest net.IP) []byte {
	// Translate an IPv4 packet to an IPv6 packet
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		// Not IPv4 packet, ignore because we are only translating IPv4 here
		return nil
	}

	ip, _ := ipLayer.(*layers.IPv4)
	protocol := ip.Protocol

	if protocol == layers.IPProtocolICMPv4 {
		protocol = layers.IPProtocolICMPv6
	}

	// Create a new IPv6 packet that matches the IPv4 Packet without any payload
	ipv6 := &layers.IPv6{
		Version:      6,
		TrafficClass: ip.TOS,
		FlowLabel:    0,
		NextHeader:   protocol,
		HopLimit:     ip.TTL - 1, // We are a router, TODO: Check if this is 0
		SrcIP:        src,
		DstIP:        dest,
	}

	var payload []byte

	switch protocol {
	case layers.IPProtocolICMPv6:
		payload = translateICMPv4(ipv6, ip.Payload)
	default:
		return nil
	}

	return serializePacket(ipv6, gopacket.Payload(payload))
}

func translateICMPv4(ip *layers.IPv6, payload []byte) []byte {
	// Parse the ICMP packet to get the type
	packet := gopacket.NewPacket(payload, layers.LayerTypeICMPv4, gopacket.Default)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		log.Println("Not an ICMPv4 packet")
		return nil
	}

	icmp, _ := icmpLayer.(*layers.ICMPv4)

	var newType uint8
	switch icmp.TypeCode.Type() {
	case 8:
		newType = 128
	case 0:
		newType = 129
	default:
		log.Printf("Dropping ICMPv4 packet with unsupported type %d", icmp.TypeCode.Type())
		return nil
	}

	// Create new IPv6 ICMP packet
	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(newType, 0), // code is 0 for both 128 and 129,
	}

	// Set the actual id & seq
	// Create ICMPv6 Echo Message
	echoLayer := &layers.ICMPv6Echo{
		Identifier: icmp.Id,
		SeqNumber:  icmp.Seq,
	}

	// Use the pseudoheader to calculate the checksum
	err := icmpv6.SetNetworkLayerForChecksum(ip)
	if err != nil {
		log.Printf("Failed to set network layer for ICMPv6 checksum: %v", err)
		return nil
	}

	return serializePacket(icmpv6, echoLayer)
}

func serializePacket(layers ...gopacket.SerializableLayer) []byte {
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, layers...)

	if err != nil {
		log.Printf("Failed to serialize packet: %v", err)
		return nil
	}

	return buffer.Bytes()
}
