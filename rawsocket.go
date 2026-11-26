package main

import (
	"fmt"
	"syscall"

	"github.com/christiaangoossens/go-siit"
)

// ipv6Sender sends complete IPv6 packets (header included) through one long-lived raw socket.
type ipv6Sender struct {
	fd int
}

// newIPv6Sender opens the raw socket. Close it when done.
func newIPv6Sender() (*ipv6Sender, error) {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("Failed to create raw IPv6 socket: %w", err)
	}

	return &ipv6Sender{fd: fd}, nil
}

// Send writes the packet to the destination in its IPv6 header.
func (s *ipv6Sender) Send(packet siit.Packet) error {
	addr := &syscall.SockaddrInet6{Addr: packet.Dst().As16()}

	return syscall.Sendto(s.fd, packet, 0, addr)
}

func (s *ipv6Sender) Close() error {
	return syscall.Close(s.fd)
}
