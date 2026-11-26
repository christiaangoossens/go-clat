package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
)

const udpProtocol = 17

// fakeTun returns the queued packets from Read, then io.EOF, and records every Write.
type fakeTun struct {
	incoming [][]byte
	written  [][]byte
}

func (f *fakeTun) Read(buffer []byte) (int, error) {
	if len(f.incoming) == 0 {
		return 0, io.EOF
	}

	packet := f.incoming[0]
	f.incoming = f.incoming[1:]

	return copy(buffer, packet), nil
}

func (f *fakeTun) Write(packet []byte) (int, error) {
	f.written = append(f.written, append([]byte(nil), packet...))
	return len(packet), nil
}

func ipv4UDPPacket(t *testing.T, src, dst string, ttl uint8) []byte {
	t.Helper()

	srcAddr, dstAddr := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	udp := udpSegment(srcAddr[:], dstAddr[:])

	header := make([]byte, 20)
	header[0] = 0x45 // version 4, header length 5 words
	binary.BigEndian.PutUint16(header[2:], uint16(len(header)+len(udp)))
	header[8] = ttl
	header[9] = udpProtocol
	copy(header[12:], srcAddr[:])
	copy(header[16:], dstAddr[:])
	binary.BigEndian.PutUint16(header[10:], internetChecksum(header))

	return append(header, udp...)
}

func ipv6UDPPacket(t *testing.T, src, dst string, hopLimit uint8) []byte {
	t.Helper()

	srcAddr, dstAddr := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	udp := udpSegment(srcAddr[:], dstAddr[:])

	header := make([]byte, 40)
	header[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(header[4:], uint16(len(udp)))
	header[6] = udpProtocol
	header[7] = hopLimit
	copy(header[8:], srcAddr[:])
	copy(header[24:], dstAddr[:])

	return append(header, udp...)
}

// udpSegment builds a UDP datagram from port 40000 to 53 with its checksum over the pseudo header. The IPv4 and IPv6
// pseudo headers hold the same words (addresses, protocol, length), so one layout serves both.
func udpSegment(src, dst []byte) []byte {
	payload := []byte("hello")

	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], 40000)
	binary.BigEndian.PutUint16(udp[2:], 53)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)

	pseudo := append(append([]byte(nil), src...), dst...)
	pseudo = append(pseudo, 0, udpProtocol, udp[4], udp[5])

	checksum := internetChecksum(append(pseudo, udp...))
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], checksum)

	return udp
}

// internetChecksum is the RFC 1071 checksum, written apart from onesComplementSum so tests do not check the code
// against itself.
func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		word := uint32(data[i]) << 8
		if i+1 < len(data) {
			word |= uint32(data[i+1])
		}
		sum += word
	}

	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}

	return ^uint16(sum)
}

func mustAddr(t *testing.T, ip net.IP) netip.Addr {
	t.Helper()

	addr := toAddr(ip)
	if !addr.IsValid() {
		t.Fatalf("invalid address %v", ip)
	}

	return addr
}
