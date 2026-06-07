package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestDialReplyCode is finding #22: an upstream dial timeout maps to Host
// unreachable (0x04), distinguishable from a genuine Connection refused (0x05).
func TestDialReplyCode(t *testing.T) {
	if got := dialReplyCode(context.DeadlineExceeded); got != repHostUnreach {
		t.Fatalf("deadline -> %#x, want repHostUnreach %#x", got, repHostUnreach)
	}
	if got := dialReplyCode(errors.New("connection refused")); got != repConnRefused {
		t.Fatalf("generic error -> %#x, want repConnRefused %#x", got, repConnRefused)
	}
}

// TestSocks5DomainResolveFailureReply is findings #23/#24: a CONNECT to an
// unresolvable domain name is answered with Host unreachable (0x04), not Address
// type not supported (0x08), and the bounded resolve does not hang.
func TestSocks5DomainResolveFailureReply(t *testing.T) {
	srv := &socksServer{
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) { return net.Dial(network, addr) },
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("dns down")
			},
		},
		idle: time.Second,
		log:  slog.New(slog.DiscardHandler),
	}
	proxyAddr := startSocks(t, srv)
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{socksVersion, 1, methodNoAuth}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	name := "nonexistent.invalid"
	req := []byte{socksVersion, cmdConnect, 0x00, atypDomain, byte(len(name))}
	req = append(req, name...)
	req = append(req, 0x00, 0x50) // port 80
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != repHostUnreach {
		t.Fatalf("resolve-failure reply = %#x, want repHostUnreach %#x", reply[1], repHostUnreach)
	}
}

// TestSocks5ReadsPortBeforeResolve proves a domain CONNECT consumes the port
// bytes from the client socket before any DNS resolution begins, so a slow
// resolver cannot eat the handshake deadline before the port is off the wire.
// The client withholds the trailing port bytes: the server must block reading
// the port and therefore must NOT have started resolving; once the port is sent,
// resolution proceeds.
func TestSocks5ReadsPortBeforeResolve(t *testing.T) {
	resolveStarted := make(chan struct{}, 1)
	srv := &socksServer{
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) { return net.Dial(network, addr) },
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				select {
				case resolveStarted <- struct{}{}:
				default:
				}
				return nil, errors.New("dns down")
			},
		},
		idle: time.Second,
		log:  slog.New(slog.DiscardHandler),
	}
	proxyAddr := startSocks(t, srv)
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.Write([]byte{socksVersion, 1, methodNoAuth}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}

	// CONNECT to a domain, but withhold the 2 trailing port bytes.
	name := "slow.invalid"
	req := []byte{socksVersion, cmdConnect, 0x00, atypDomain, byte(len(name))}
	req = append(req, name...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}

	// Without the port on the wire the server must block reading it and must not
	// have resolved yet.
	select {
	case <-resolveStarted:
		t.Fatal("resolution started before the port was read")
	case <-time.After(300 * time.Millisecond):
	}

	// Send the port; resolution may now proceed.
	if _, err := c.Write([]byte{0x00, 0x50}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-resolveStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("resolution did not start after the port was sent")
	}
}

// startEcho starts a TCP echo server on loopback and returns its address.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func startSocks(t *testing.T, srv *socksServer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.serveListener(ctx, ln)
	return ln.Addr().String()
}

// socksConnect performs a SOCKS5 no-auth CONNECT to an IPv4 target and returns
// the established proxy connection.
func socksConnect(t *testing.T, proxyAddr, targetIP string, targetPort uint16) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	// Method negotiation: VER, NMETHODS=1, NoAuth.
	if _, err := c.Write([]byte{socksVersion, 1, methodNoAuth}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != socksVersion || resp[1] != methodNoAuth {
		t.Fatalf("bad method reply %v", resp)
	}
	// CONNECT request, ATYP IPv4.
	req := []byte{socksVersion, cmdConnect, 0x00, atypIPv4}
	req = append(req, net.ParseIP(targetIP).To4()...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], targetPort)
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != repSuccess {
		t.Fatalf("CONNECT failed, rep=%d", reply[1])
	}
	return c
}

func TestSocks5ConnectEcho(t *testing.T) {
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	var port uint16
	if _, err := net.ResolveTCPAddr("tcp", echoAddr); err != nil {
		t.Fatal(err)
	}
	p, _ := net.LookupPort("tcp", portStr)
	port = uint16(p)

	srv := &socksServer{
		dial:     func(ctx context.Context, network, addr string) (net.Conn, error) { return net.Dial(network, addr) },
		resolver: net.DefaultResolver,
		idle:     5 * time.Second,
		log:      slog.New(slog.DiscardHandler),
	}
	proxyAddr := startSocks(t, srv)

	conn := socksConnect(t, proxyAddr, host, port)
	defer conn.Close()

	msg := []byte("hello through socks")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
}

func TestSocks5RejectsBadVersion(t *testing.T) {
	srv := &socksServer{
		dial:     func(ctx context.Context, network, addr string) (net.Conn, error) { return nil, io.EOF },
		resolver: net.DefaultResolver,
		log:      slog.New(slog.DiscardHandler),
	}
	proxyAddr := startSocks(t, srv)
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// SOCKS4 version byte → server should drop the connection.
	c.Write([]byte{0x04, 1, 0x00})
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("expected connection to be closed for bad version")
	}
}

func TestIsUnroutableTarget(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"0.0.0.0", true},
		{"::", true},
		{"169.254.1.1", true},
		{"224.0.0.1", true},
		{"ff02::1", true},
		{"8.8.8.8", false},
		{"127.0.0.1", false},   // loopback left to the dialer
		{"10.10.10.1", false},  // private — valid VPN destination
		{"192.168.1.5", false}, // private — valid VPN destination
		{"example.com", false}, // not a literal IP — leave it to the dial
	} {
		if got := isUnroutableTarget(tc.host); got != tc.want {
			t.Errorf("isUnroutableTarget(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestSocks5RejectsUnroutableTarget: a CONNECT to 0.0.0.0 is answered with
// HostUnreachable immediately, without ever invoking the upstream dialer.
func TestSocks5RejectsUnroutableTarget(t *testing.T) {
	var dialed atomic.Bool
	srv := &socksServer{
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed.Store(true)
			return nil, io.EOF
		},
		resolver: net.DefaultResolver,
		log:      slog.New(slog.DiscardHandler),
	}
	proxyAddr := startSocks(t, srv)

	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{socksVersion, 1, methodNoAuth}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	// CONNECT 0.0.0.0:443 (ATYP IPv4, port 0x01BB).
	req := []byte{socksVersion, cmdConnect, 0x00, atypIPv4, 0, 0, 0, 0, 0x01, 0xBB}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("no reply: %v", err)
	}
	if reply[1] != repHostUnreach {
		t.Fatalf("reply code = %d, want repHostUnreach (%d)", reply[1], repHostUnreach)
	}
	if dialed.Load() {
		t.Fatal("upstream dialer was invoked for an unroutable target")
	}
}

func TestCheckLoopbackBind(t *testing.T) {
	for _, tc := range []struct {
		addr    string
		allow   bool
		wantErr bool
	}{
		{"127.0.0.1:1080", false, false},
		{"localhost:1080", false, false},
		{"0.0.0.0:1080", false, true},
		{"192.168.1.5:1080", false, true},
		{"0.0.0.0:1080", true, false},
	} {
		err := checkLoopbackBind(tc.addr, tc.allow)
		if (err != nil) != tc.wantErr {
			t.Errorf("checkLoopbackBind(%q, %v) err=%v, wantErr=%v", tc.addr, tc.allow, err, tc.wantErr)
		}
	}
}

// startStreamer starts a TCP server that, on each connection, discards input
// and writes total bytes in chunk-sized writes spaced by gap, then closes. It
// models a sustained one-directional download (the client never speaks again).
func startStreamer(t *testing.T, total, chunk int, gap time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, chunk)
				for i := range buf {
					buf[i] = byte(i)
				}
				for sent := 0; sent < total; {
					n := min(chunk, total-sent)
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
					sent += n
					time.Sleep(gap)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// TestSpliceOneDirectionalSurvivesIdle is the regression guard for the idle
// timeout being mistakenly applied per-direction: a long download must not be
// truncated just because the client side is silent for longer than the idle
// window. The stream runs ~0.5s while idle is 200ms; the full payload must
// still arrive.
func TestSpliceOneDirectionalSurvivesIdle(t *testing.T) {
	const total = 1 << 20 // 1 MiB
	addr := startStreamer(t, total, 16*1024, 8*time.Millisecond)
	host, portStr, _ := net.SplitHostPort(addr)
	p, _ := net.LookupPort("tcp", portStr)

	srv := &socksServer{
		dial:     func(ctx context.Context, network, addr string) (net.Conn, error) { return net.Dial(network, addr) },
		resolver: net.DefaultResolver,
		idle:     200 * time.Millisecond,
		log:      slog.New(slog.DiscardHandler),
	}
	proxyAddr := startSocks(t, srv)
	conn := socksConnect(t, proxyAddr, host, uint16(p))
	defer conn.Close()

	// Client stays silent and only drains the stream.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if len(got) != total {
		t.Fatalf("one-directional transfer truncated by idle timeout: got %d of %d bytes", len(got), total)
	}
}

// TestSpliceHalfCloseDeliversResponse is finding #7: a client that half-closes
// its write side after sending its request (HTTP/1.0 / SMTP / gRPC pattern) must
// still receive the full upstream response — the splice must CloseWrite the peer
// on read-EOF, not tear down both directions.
func TestSpliceHalfCloseDeliversResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	const reply = "UPSTREAM-RESPONSE-AFTER-HALF-CLOSE"
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c) // drain the request until the client half-closes (EOF)
		c.Write([]byte(reply))
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := net.LookupPort("tcp", portStr)

	srv := &socksServer{
		dial:     func(ctx context.Context, network, addr string) (net.Conn, error) { return net.Dial(network, addr) },
		resolver: net.DefaultResolver,
		idle:     2 * time.Second,
		log:      slog.New(slog.DiscardHandler),
	}
	proxyAddr := startSocks(t, srv)
	conn := socksConnect(t, proxyAddr, host, uint16(p))
	defer conn.Close()

	if _, err := conn.Write([]byte("CLIENT-REQUEST")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(got) != reply {
		t.Fatalf("half-close truncated the response: got %q, want %q", got, reply)
	}
}

// TestSpliceIdleZeroNoHalfCloseLeak guards the finding-#7 regression fix: with the
// idle watchdog disabled (-idle 0), a client half-close must still tear the splice
// down promptly rather than leaving the surviving pump blocked forever on a
// half-open peer that received our FIN but never closes.
func TestSpliceIdleZeroNoHalfCloseLeak(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { c.Close() }) // hold open: never read, write, or close
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := net.LookupPort("tcp", portStr)

	srv := &socksServer{
		dial:     func(ctx context.Context, network, addr string) (net.Conn, error) { return net.Dial(network, addr) },
		resolver: net.DefaultResolver,
		idle:     0, // watchdog disabled
		log:      slog.New(slog.DiscardHandler),
	}
	proxyAddr := startSocks(t, srv)
	conn := socksConnect(t, proxyAddr, host, uint16(p))
	defer conn.Close()

	if _, err := conn.Write([]byte("req")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected teardown after half-close with idle disabled")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("half-close did not tear down promptly with idle==0 (leak): %v", elapsed)
	}
}

// TestSpliceClosesWhenFullyIdle verifies the idle watchdog still fires when
// BOTH directions are silent for the whole window.
func TestSpliceClosesWhenFullyIdle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() }) // hold open, silent
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := net.LookupPort("tcp", portStr)

	srv := &socksServer{
		dial:     func(ctx context.Context, network, addr string) (net.Conn, error) { return net.Dial(network, addr) },
		resolver: net.DefaultResolver,
		idle:     200 * time.Millisecond,
		log:      slog.New(slog.DiscardHandler),
	}
	proxyAddr := startSocks(t, srv)
	conn := socksConnect(t, proxyAddr, host, uint16(p))
	defer conn.Close()

	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected idle connection to be closed")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("idle close took too long: %v", elapsed)
	}
}
