// https://github.com/ddrown/android_external_android-clat/blob/master/translate.c
package main

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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
	// Manually parsing ICMPv4
	icmpv4Type := payload[0] // Type
	// icmpv4Code := payload[1] // Code (not used in translation)
	// Checksum is at bytes [2:4], generally skipped for just translating
	identifier := (uint16(payload[4]) << 8) | uint16(payload[5])
	sequence := (uint16(payload[6]) << 8) | uint16(payload[7])

	// Extract payload data after ICMPv4 header
	icmpv4Payload := payload[8:]

	var newType uint8
	switch icmpv4Type {
	case 8:
		newType = 128
	case 0:
		newType = 129
	default:
		log.Printf("Dropping ICMPv4 packet with unsupported type %d", icmpv4Type)
		return nil
	}

	// Create new IPv6 ICMP packet
	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(newType, 0), // code is 0 for both 128 and 129,
	}

	// Set the actual id & seq
	// Create ICMPv6 Echo Message
	echoLayer := &layers.ICMPv6Echo{
		Identifier: identifier,
		SeqNumber:  sequence,
	}

	// Use the pseudoheader to calculate the checksum
	err := icmpv6.SetNetworkLayerForChecksum(ip)
	if err != nil {
		log.Printf("Failed to set network layer for ICMPv6 checksum: %v", err)
		return nil
	}

	return serializePacket(icmpv6, echoLayer, gopacket.Payload(icmpv4Payload))
}

func translateIPv6(packet gopacket.Packet, dest net.IP, reversed bool) []byte {
	/*if !reversed {
		// Recieved IPv6 packet
		log.Printf("Recieved IPv6 packet to translate %x", packet.Data())
	}*/

	// Translate an IPv6 packet to an IPv4 packet
	ipLayer := packet.Layer(layers.LayerTypeIPv6)
	if ipLayer == nil {
		// Not IPv6 packet, ignore because we are only translating IPv6 here
		return nil
	}

	ip, _ := ipLayer.(*layers.IPv6)
	protocol := ip.NextHeader

	if protocol == layers.IPProtocolICMPv6 {
		protocol = layers.IPProtocolICMPv4
	}

	var src net.IP
	if reversed {
		src = dest
		dest = ip.DstIP[12:]
	} else {
		src = ip.SrcIP[12:]
	}

	// Create a new IPv4 packet that matches the IPv6 Packet without any payload
	ipv4 := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        ip.TrafficClass,
		Length:     0, // Automatically calculated during serialization
		Id:         0, // ID can be set if needed for fragmentation; 0 for simple cases
		Flags:      0,
		FragOffset: 0,
		TTL:        ip.HopLimit - 1,
		Protocol:   protocol,
		SrcIP:      src,
		DstIP:      dest,
	}

	var payload []byte
	isErrorPkt := false

	switch protocol {
	case layers.IPProtocolICMPv4:
		isErrorPkt, payload = translateICMPv6(ip.Payload)
	default:
		return nil
	}

	if isErrorPkt {
		ipv4.SrcIP = net.IPv4(192, 0, 0, 2)
		innerPacket := gopacket.NewPacket(ip.Payload[8:], layers.LayerTypeIPv6, gopacket.Default)
		innerPacketPayload := translateIPv6(innerPacket, dest, true)
		return serializePacket(ipv4, gopacket.Payload(payload), gopacket.Payload(innerPacketPayload))
	}

	return serializePacket(ipv4, gopacket.Payload(payload))
}

func translateICMPv6(payload []byte) (bool, []byte) {
	// Parse the ICMP packet to get the type
	// Read ICMPv6 header fields
	icmpv6Type := payload[0]
	code := payload[1]

	switch icmpv6Type {
	case 128:
		return false, translateICMPv6Echo(8, payload)
	case 129:
		return false, translateICMPv6Echo(0, payload)
	case 1:
		// Destination Unreachable
		return true, generateICMPv6DestUnreachError(code)
	default:
		log.Printf("Dropping ICMPv6 packet with unsupported type %d", icmpv6Type)
		return false, nil
	}
}

func translateICMPv6Echo(newType byte, payload []byte) []byte {
	identifier := (uint16(payload[4]) << 8) | uint16(payload[5])
	sequence := (uint16(payload[6]) << 8) | uint16(payload[7])
	icmpv6Payload := payload[8:]

	// Create new IPv4 ICMP packet
	icmpv4 := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(newType, 0), // code is 0 for both 8 and 0,
		Id:       identifier,
		Seq:      sequence,
	}

	return serializePacket(icmpv4, gopacket.Payload(icmpv6Payload))
}

func generateICMPv6DestUnreachError(code byte) []byte {
	var newCode byte

	switch code {
	case 0:
		//  Code 0 (No route to destination):  Set the Code to 1 (Host unreachable).
		newCode = 1
	case 1:
		// Code 1 (Communication with destination administratively prohibited):  Set the Code to 10 (Communication with destination host administratively prohibited).
		newCode = 10
	case 2:
		//  Code 2 (Beyond scope of source address):  Set the Code to 1 (Host unreachable).
		newCode = 1
	case 3:
		// Code 3 (Address unreachable):  Set the Code to 1 (Host unreachable).
		newCode = 1
	case 4:
		//  Code 4 (Port unreachable):  Set the Code to 3 (Port unreachable).
		newCode = 3
	default:
		// Other Code values:  Silently drop.
		return nil
	}

	// Create new IPv4 ICMP packet
	icmpv4 := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(3, newCode),
	}

	return serializePacket(icmpv4)
}
