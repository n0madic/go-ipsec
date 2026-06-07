//go:build e2e_server

// Package integration holds the build-tagged live interop tests. They dial a
// real IKEv2 endpoint with operator-injected credentials and are excluded from
// normal builds. Run the EAP-MSCHAPv2 tests with:
//
//	IPSEC_SERVER=vpn.example.com:500 \
//	IPSEC_EAP_USER=user IPSEC_EAP_PASS=secret \
//	go test -tags e2e_server -v ./test/integration -run Live
//
// The PSK test instead needs IPSEC_PSK (and IPSEC_LOCAL_ID for the IDi the
// gateway keys the PSK by; it defaults to client.test):
//
//	IPSEC_SERVER=vpn.example.com:500 IPSEC_PSK=secret \
//	go test -tags e2e_server -v ./test/integration -run LivePSK
//
// Never iterate against a live endpoint for primitive debugging — a server may
// rate-limit repeated failed handshakes. Use the offline KAT and handshake
// gates for that.
package integration

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	ipsec "github.com/n0madic/go-ipsec"
)

func liveConfig(t *testing.T) ipsec.Config {
	t.Helper()
	server := os.Getenv("IPSEC_SERVER")
	user := os.Getenv("IPSEC_EAP_USER")
	pass := os.Getenv("IPSEC_EAP_PASS")
	if server == "" || user == "" || pass == "" {
		t.Skip("set IPSEC_SERVER, IPSEC_EAP_USER, IPSEC_EAP_PASS to run live tests")
	}
	cfg := ipsec.Config{
		Server: server,
		EAP:    ipsec.EAPMSCHAPv2{Username: user, Password: pass},
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if id := os.Getenv("IPSEC_LOCAL_ID"); id != "" {
		cfg.LocalID = ipsec.Email(id)
	}
	if id := os.Getenv("IPSEC_REMOTE_ID"); id != "" {
		cfg.RemoteID = ipsec.FQDN(id)
	}
	if caFile := os.Getenv("IPSEC_CA"); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			t.Fatal("no certs in IPSEC_CA")
		}
		cfg.RootCAs = pool
	}
	return cfg
}

// livePSKConfig builds a PSK (pre-shared key) live config. PSK auth carries no
// EAP username and no certificate, so the IKE identity is the IDi — defaulted to
// the FQDN the strongSwan rw-psk conn keys its PSK by (client.test).
func livePSKConfig(t *testing.T) ipsec.Config {
	t.Helper()
	server := os.Getenv("IPSEC_SERVER")
	psk := os.Getenv("IPSEC_PSK")
	if server == "" || psk == "" {
		t.Skip("set IPSEC_SERVER and IPSEC_PSK to run the live PSK test")
	}
	localID := os.Getenv("IPSEC_LOCAL_ID")
	if localID == "" {
		localID = "client.test"
	}
	cfg := ipsec.Config{
		Server:  server,
		LocalID: ipsec.FQDN(localID),
		PSK:     psk,
		Logger:  slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if id := os.Getenv("IPSEC_REMOTE_ID"); id != "" {
		cfg.RemoteID = ipsec.FQDN(id)
	}
	return cfg
}

// TestLiveHandshake dials a live endpoint and asserts the Child SA is installed
// and a CP address was assigned.
func TestLiveHandshake(t *testing.T) {
	cfg := liveConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := ipsec.Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if !client.LocalIP().IsValid() {
		t.Fatal("no CP address assigned")
	}
	t.Logf("tunnel up: localIP=%s dns=%v", client.LocalIP(), client.DNS())
}

// TestLiveIPv6 exercises inner-IPv6 against the strongSwan server with two hard
// gates: (1) the responder assigns an inner v6 address via CFG
// INTERNAL_IP6_ADDRESS and accepts the client's v6 traffic selectors; (2) a TCP
// round-trip over inner IPv6 to the in-container v6 echo target completes.
//
// The round-trip was once best-effort because inner-v6 delivery was MISattributed
// to a server-side XFRM limitation. The real cause was a client bug — esp.Encrypt
// stamped the ESP trailer Next Header to IPv4 (4) for every packet, so strongSwan
// decrypted the inner v6 datagram but routed it to the IPv4 input path and dropped
// it (Ip6InReceives flat, xfrm_stat error counters 0). esp.Encrypt now derives the
// Next Header from the inner IP version (41 for v6) and the round-trip is verified
// live, so it is a hard gate (no opt-in flag). IPSEC_V6_TARGET overrides the
// default target ([fd00:cafe::1]:7777, matching test/strongswan/entrypoint.sh);
// the whole path is inside the container, so it needs no Docker-host v6 egress.
func TestLiveIPv6(t *testing.T) {
	cfg := liveConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := ipsec.Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Gate 1: the responder assigned an inner v6 address via CFG.
	ip6 := client.LocalIP6()
	if !ip6.IsValid() {
		t.Fatal("no inner IPv6 address assigned (CFG INTERNAL_IP6_ADDRESS)")
	}
	t.Logf("inner IPv6: localIP6=%s dns6=%v", ip6, client.DNS6())

	// Gate 2: a TCP round-trip over inner IPv6 completes.
	target := os.Getenv("IPSEC_V6_TARGET")
	if target == "" {
		target = "[fd00:cafe::1]:7777"
	}
	if err := ipv6RoundTrip(t, client, target); err != nil {
		t.Fatalf("v6 data-path round-trip to %s: %v", target, err)
	}
	t.Logf("inner IPv6 round-trip OK via %s", target)
}

// ipv6RoundTrip dials target through the tunnel, writes a token and verifies it
// is echoed back. The short timeout keeps the best-effort probe from eating the
// full deadline when the server-side data path does not complete.
func ipv6RoundTrip(t *testing.T, client *ipsec.Client, target string) error {
	t.Helper()
	dctx, dcancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer dcancel()
	conn, err := client.DialContext(dctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	const token = "ping6"
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte(token)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, len(token))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if got := string(buf); got != token {
		return fmt.Errorf("echo mismatch: got %q, want %q", got, token)
	}
	return nil
}

// TestLiveDiag connects a raw TCP socket through the tunnel and dumps the
// gVisor stack drop counters to pinpoint where inbound packets are lost.
func TestLiveDiag(t *testing.T) {
	cfg := liveConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client, err := ipsec.Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	n, err := client.Net()
	if err != nil {
		t.Fatal(err)
	}
	s := n.Stack()
	dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	defer dcancel()
	conn, derr := client.DialContext(dctx, "tcp", "1.1.1.1:80")
	t.Logf("TCP dial to 1.1.1.1:80: err=%v", derr)
	if conn != nil {
		conn.Close()
	}
	st := s.Stats()
	t.Logf("IP: recv=%d delivered=%d malformed=%d invalidDst=%d invalidSrc=%d",
		st.IP.PacketsReceived.Value(), st.IP.PacketsDelivered.Value(),
		st.IP.MalformedPacketsReceived.Value(),
		st.IP.InvalidDestinationAddressesReceived.Value(),
		st.IP.InvalidSourceAddressesReceived.Value())
	t.Logf("TCP: valid=%d invalid=%d cksumErr=%d listenDrop=%d resets=%d failedConn=%d",
		st.TCP.ValidSegmentsReceived.Value(), st.TCP.InvalidSegmentsReceived.Value(),
		st.TCP.ChecksumErrors.Value(), st.TCP.ListenOverflowSynDrop.Value(),
		st.TCP.ResetsReceived.Value(), st.TCP.FailedConnectionAttempts.Value())
}

// TestLiveHTTPGet routes an HTTP GET through the tunnel and logs the exit IP, to
// be compared against the server egress.
func TestLiveHTTPGet(t *testing.T) {
	cfg := liveConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := ipsec.Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	t.Logf("exit IP via tunnel: %s", httpGetThroughTunnel(t, client))
}

// TestLivePSKHandshake dials the live endpoint with PSK auth (no EAP, no
// certificate) and asserts the Child SA is installed and a CP address assigned,
// then proves the data plane with an HTTP GET — the e2e gate for the PSK
// IKE_AUTH path against a real strongSwan server.
func TestLivePSKHandshake(t *testing.T) {
	cfg := livePSKConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := ipsec.Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("dial (PSK): %v", err)
	}
	defer client.Close()

	if !client.LocalIP().IsValid() {
		t.Fatal("no CP address assigned")
	}
	t.Logf("PSK tunnel up: localIP=%s dns=%v", client.LocalIP(), client.DNS())
	t.Logf("PSK exit IP via tunnel: %s", httpGetThroughTunnel(t, client))
}

// httpGetThroughTunnel resolves and dials api.ipify.org over the tunnel and
// returns the exit IP it reports, failing the test on any error or a
// non-IP response. Shared by the EAP and PSK live data-plane checks.
func httpGetThroughTunnel(t *testing.T, client *ipsec.Client) string {
	t.Helper()
	resolver := client.Resolver("")
	httpClient := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				// Resolve through the tunnel DNS, then dial the literal IP.
				ips, err := resolver.LookupNetIP(ctx, "ip4", host)
				if err != nil || len(ips) == 0 {
					return nil, err
				}
				return client.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
			},
		},
	}

	resp, err := httpClient.Get("http://api.ipify.org")
	if err != nil {
		t.Fatalf("HTTP GET through tunnel: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	exitIP := strings.TrimSpace(string(body))
	if net.ParseIP(exitIP) == nil {
		t.Fatalf("unexpected ipify response: %q", exitIP)
	}
	return exitIP
}
