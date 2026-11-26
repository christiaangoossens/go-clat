package integration

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// testHTTPDownload checks that TCP from the internet uses full-size packets that fit both tuns.
func testHTTPDownload(t *testing.T) {
	ipv4Tun, ipv6Tun := clatTuns(t)
	onIPv4Tun := capturePackets(t, ipv4Tun)
	onIPv6Tun := capturePackets(t, ipv6Tun)

	response, err := httpClient(t).Get(remoteURL())
	body := httpBody(t, response, err)

	if !bytes.Equal(body, download) {
		t.Errorf("downloaded %d bytes that differ from the %d bytes the server sent", len(body), len(download))
	}

	read, _ := onIPv6Tun.largest()
	_, written := onIPv4Tun.largest()
	expectLargest(t, "IPv6 packet go-clat read", read, fullSizeIPv6)
	expectLargest(t, "IPv4 packet go-clat wrote", written, ipv4TunMTU)
}

// testHTTPUpload checks that TCP to the internet uses full-size packets that fit the IPv4 tun.
func testHTTPUpload(t *testing.T) {
	ipv4Tun, _ := clatTuns(t)
	onIPv4Tun := capturePackets(t, ipv4Tun)
	onUplink := capturePackets(t, clatUplink)

	upload := randomBytes(1 << 20)
	response, err := httpClient(t).Post(remoteURL(), "application/octet-stream", bytes.NewReader(upload))
	hash := httpBody(t, response, err)

	if want := fmt.Sprintf("%x", sha256.Sum256(upload)); string(hash) != want {
		t.Errorf("the server got an upload with SHA-256 %s, want %s", hash, want)
	}

	read, _ := onIPv4Tun.largest()
	sent, _ := onUplink.largest()
	expectLargest(t, "IPv4 packet go-clat read", read, ipv4TunMTU)
	expectLargest(t, "IPv6 packet sent to the internet", sent, fullSizeIPv6)
}

// httpBody returns the body of a successful response.
func httpBody(t *testing.T, response *http.Response, err error) []byte {
	t.Helper()

	must(t, err)
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	must(t, err)

	if response.StatusCode != http.StatusOK {
		t.Fatalf("HTTP %s: %s", response.Status, body)
	}

	return body
}

func httpClient(t *testing.T) *http.Client {
	transport := &http.Transport{} // no proxy from the environment
	t.Cleanup(transport.CloseIdleConnections)

	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func remoteURL() string {
	return fmt.Sprintf("http://%s:%d/", remoteIPv4, httpPort)
}
