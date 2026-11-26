package main

import (
	"errors"
	"io"
	"log"
	"net"

	"github.com/christiaangoossens/go-siit"
)

// Larger than both tun MTUs, so a read never truncates a packet.
const readBufferSize = 2048

// newTranslator creates the CLAT translator. The router address gets an EAM entry to the public IPv6 address, because
// go-siit rejects a non-global router address inside the Well-Known Prefix without one.
func newTranslator(nat64Net *net.IPNet, publicIPv6, tunnelIPv6 net.IP) (*siit.Translator, error) {
	router, err := siit.ParseEAMEntry(getIPv4RouterAddress().String(), publicIPv6.String())
	if err != nil {
		return nil, err
	}

	host, err := siit.ParseEAMEntry(getIPv4TunAddress().String(), tunnelIPv6.String())
	if err != nil {
		return nil, err
	}

	return siit.NewTranslator(siit.Config{
		NAT64Prefix:       toPrefix(nat64Net),
		IPv4RouterAddress: toAddr(getIPv4RouterAddress()),
		EAMTable:          siit.EAMTable{router, host},
	})
}

// translateIPv4Loop translates packets from the host on the IPv4 tun and forwards them over IPv6. It returns when
// reading from the tun fails.
func translateIPv4Loop(translator *siit.Translator, ipv4Tun io.ReadWriter, forward func(siit.Packet) error) error {
	hostAddr := toAddr(getIPv4TunAddress())
	buffer := make([]byte, readBufferSize)

	for {
		n, err := ipv4Tun.Read(buffer)
		if err != nil {
			return err
		}

		packet := siit.Packet(buffer[:n])
		if packet.Version() != 4 || packet.Src() != hostAddr {
			continue
		}

		result, err := translator.TranslateIPv4(packet)
		deliver(result, err, forward, ipv4Tun)
	}
}

// translateIPv6Loop translates return packets on the IPv6 tun and writes them to the IPv4 tun. It returns when
// reading from the IPv6 tun fails.
func translateIPv6Loop(translator *siit.Translator, ipv6Tun io.ReadWriter, ipv4Tun io.Writer, tunnelIPv6 net.IP) error {
	tunnelAddr := toAddr(tunnelIPv6)
	buffer := make([]byte, readBufferSize)

	for {
		n, err := ipv6Tun.Read(buffer)
		if err != nil {
			return err
		}

		packet := siit.Packet(buffer[:n])
		if packet.Version() != 6 || packet.Dst() != tunnelAddr {
			continue
		}

		result, err := translator.TranslateIPv6(packet)
		deliver(result, err, writeTo(ipv4Tun), ipv6Tun)
	}
}

// deliver forwards a translated packet, or writes the translator's ICMP error back to the interface the packet came from.
func deliver(result siit.Packet, err error, forward func(siit.Packet) error, origin io.Writer) {
	var translationErr *siit.TranslationError

	switch {
	case errors.As(err, &translationErr):
		if _, err := origin.Write(translationErr.Reply); err != nil {
			log.Printf("Error writing ICMP reply: %v", err)
		}

	case err != nil:
		log.Printf("Dropping packet: %v", err)

	case len(result) > 0:
		if err := forward(result); err != nil {
			log.Printf("Error sending packet to %s: %v", result.Dst(), err)
		}
	}
}

func writeTo(w io.Writer) func(siit.Packet) error {
	return func(packet siit.Packet) error {
		_, err := w.Write(packet)
		return err
	}
}
