package integration

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/vishvananda/netns"
)

const (
	echoPort = 7
	httpPort = 80
)

// download is what the HTTP server on the remote host serves: 1 MB of random bytes, so it takes many full-size packets.
var download = randomBytes(1 << 20)

// startFakeInternet runs a UDP echo server and an HTTP server on the remote host in the peer namespace. The remote
// host is a real IPv6 host at 64:ff9b::101:101, so through go-clat it is 1.1.1.1 behind a NAT64. It has an address in
// each other NAT64 prefix too.
//
// The HTTP server listens on all addresses. The echo server listens on each address separately, so it answers from the
// address it was asked on: a connected UDP socket ignores answers from any other address.
func startFakeInternet(t *testing.T, peer netns.NsHandle) {
	t.Helper()

	var echoes []net.PacketConn
	var web net.Listener

	err := inNetns(peer, func() error {
		for _, remote := range remoteAddrs() {
			echo, err := net.ListenUDP("udp6", &net.UDPAddr{IP: remote, Port: echoPort})
			if err != nil {
				return err
			}

			t.Cleanup(func() { echo.Close() })
			echoes = append(echoes, echo)
		}

		var err error
		web, err = net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6unspecified, Port: httpPort})
		return err
	})
	if err != nil {
		t.Fatalf("starting the fake internet: %v", err)
	}

	server := &http.Server{Handler: http.HandlerFunc(serveHTTP)}
	t.Cleanup(func() { server.Close() })

	for _, echo := range echoes {
		go serveEcho(echo)
	}

	go server.Serve(web)
}

// serveHTTP answers a GET with download, and a POST with the SHA-256 of what was uploaded.
func serveHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		w.Write(download)
		return
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, request.Body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "%x", hash.Sum(nil))
}

// serveEcho sends every datagram back to where it came from, until the connection is closed.
func serveEcho(conn net.PacketConn) {
	buffer := make([]byte, 65535)

	for {
		n, from, err := conn.ReadFrom(buffer)
		if err != nil {
			return
		}

		conn.WriteTo(buffer[:n], from)
	}
}

func randomBytes(n int) []byte {
	data := make([]byte, n)
	rand.Read(data) // never fails since Go 1.24

	return data
}
