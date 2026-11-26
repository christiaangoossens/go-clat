package integration

import (
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// packetCapture records the largest packet that passes an interface in each direction, like a minimal tcpdump.
type packetCapture struct {
	fd      int
	stopped atomic.Bool
	done    chan struct{}

	mu       sync.Mutex
	sent     int // largest packet the kernel sent out of the interface (for a tun: what go-clat reads)
	received int // largest packet the kernel received on the interface (for a tun: what go-clat writes)
}

// capturePackets starts recording packet sizes on the named interface until stop is called.
func capturePackets(t *testing.T, iface string) *packetCapture {
	t.Helper()

	link, err := netlink.LinkByName(iface)
	must(t, err)

	// Protocol 0 captures nothing until bind selects the interface and all protocols.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, 0)
	must(t, err)

	must(t, unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: link.Attrs().Index}))

	// Wake up regularly to notice stop.
	must(t, unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100_000}))

	capture := &packetCapture{fd: fd, done: make(chan struct{})}
	go capture.run()
	t.Cleanup(capture.stop)

	return capture
}

func (c *packetCapture) run() {
	defer close(c.done)

	for !c.stopped.Load() {
		if err := c.receive(0); err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return
		}
	}
}

// receive records the size of one captured packet.
func (c *packetCapture) receive(flags int) error {
	buffer := make([]byte, 1) // MSG_TRUNC returns the full length, the contents are not needed

	n, from, err := unix.Recvfrom(c.fd, buffer, flags|unix.MSG_TRUNC)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if from.(*unix.SockaddrLinklayer).Pkttype == unix.PACKET_OUTGOING {
		c.sent = max(c.sent, n)
	} else {
		c.received = max(c.received, n)
	}

	return nil
}

// stop ends the capture after recording the packets that are still queued. It is safe to call more than once.
func (c *packetCapture) stop() {
	if c.stopped.Swap(true) {
		return
	}

	<-c.done

	for c.receive(unix.MSG_DONTWAIT) == nil {
	}

	unix.Close(c.fd)
}

// largest stops the capture and returns the largest packet sent and received.
func (c *packetCapture) largest() (sent, received int) {
	c.stop()

	c.mu.Lock()
	defer c.mu.Unlock()

	return c.sent, c.received
}

func htons(v uint16) uint16 {
	var bytes [2]byte
	binary.BigEndian.PutUint16(bytes[:], v)

	return binary.NativeEndian.Uint16(bytes[:])
}
