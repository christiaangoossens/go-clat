package integration

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/icmp"
)

func sendICMP(t *testing.T, conn *icmp.PacketConn, message icmp.Message, to net.IP) {
	t.Helper()

	packet, err := message.Marshal(nil)
	must(t, err)

	_, err = conn.WriteTo(packet, &net.IPAddr{IP: to})
	must(t, err)
}

// expectNoICMP checks that no ICMP message of the given type has arrived. Call it after the traffic that could cause one
// has completed: it only waits briefly.
func expectNoICMP(t *testing.T, conn *icmp.PacketConn, unwanted icmp.Type) {
	t.Helper()

	must(t, conn.SetReadDeadline(time.Now().Add(200*time.Millisecond)))

	buffer := make([]byte, 2048)
	for {
		n, sender, err := conn.ReadFrom(buffer)
		if err != nil {
			return
		}

		if message, err := icmp.ParseMessage(unwanted.Protocol(), buffer[:n]); err == nil && message.Type == unwanted {
			t.Errorf("got %v from %s", unwanted, sender)
		}
	}
}

// receiveICMP returns the first ICMP message of the wanted type that arrives from the given address within three
// seconds.
func receiveICMP(t *testing.T, conn *icmp.PacketConn, from net.IP, want icmp.Type) *icmp.Message {
	t.Helper()

	must(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))

	buffer := make([]byte, 2048)
	for {
		n, sender, err := conn.ReadFrom(buffer)
		if err != nil {
			t.Fatalf("no %v from %s: %v", want, from, err)
		}

		message, err := icmp.ParseMessage(want.Protocol(), buffer[:n])
		if err == nil && message.Type == want && sender.(*net.IPAddr).IP.Equal(from) {
			return message
		}
	}
}
