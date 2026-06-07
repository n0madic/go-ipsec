package main

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// handshakeTimeout bounds the SOCKS5 method/auth/request negotiation so a client
// that connects and stalls mid-handshake cannot pin a goroutine indefinitely.
const handshakeTimeout = 30 * time.Second

// SOCKS5 constants (RFC 1928 / RFC 1929).
const (
	socksVersion = 0x05
	authVersion  = 0x01

	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodNoneOK   = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess           = 0x00
	repHostUnreach       = 0x04
	repConnRefused       = 0x05
	repCommandNotSupport = 0x07
	repAddrNotSupport    = 0x08
)

// dialFunc dials a TCP connection to a literal IP:port through the tunnel.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type socksServer struct {
	dial     dialFunc
	resolver *net.Resolver
	auth     string // "user:pass" or "" for no-auth
	idle     time.Duration
	log      *slog.Logger
}

func (s *socksServer) serve(ctx context.Context, listen string) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", listen)
	if err != nil {
		return fmt.Errorf("socks listen: %w", err)
	}
	s.log.Info("SOCKS5 proxy listening", "addr", ln.Addr())
	return s.serveListener(ctx, ln)
}

func (s *socksServer) serveListener(ctx context.Context, ln net.Listener) error {
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("socks accept: %w", err)
		}
		go s.handle(ctx, conn)
	}
}

func (s *socksServer) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	// Bound the negotiation phase so a stalled client can't hang the goroutine
	// in io.ReadFull forever. Cleared before splicing, which has its own idle
	// watchdog over the established connection.
	_ = client.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := s.negotiate(client); err != nil {
		s.log.Debug("socks negotiate failed", "err", err)
		return
	}
	target, err := s.readRequest(ctx, client)
	if err != nil {
		s.log.Debug("socks request failed", "err", err)
		return
	}
	_ = client.SetDeadline(time.Time{}) // hand off to splice's idle watchdog

	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	upstream, err := s.dial(dialCtx, "tcp", target)
	cancel()
	if err != nil {
		s.log.Debug("upstream dial failed", "target", target, "err", err)
		writeReply(client, dialReplyCode(err))
		return
	}
	defer upstream.Close()

	if err := writeReply(client, repSuccess); err != nil {
		return
	}
	s.splice(client, upstream)
}

// negotiate performs the SOCKS5 method handshake.
func (s *socksServer) negotiate(c net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != socksVersion {
		return fmt.Errorf("unsupported SOCKS version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}

	want := byte(methodNoAuth)
	if s.auth != "" {
		want = methodUserPass
	}
	if !slices.Contains(methods, want) {
		c.Write([]byte{socksVersion, methodNoneOK})
		return errors.New("no acceptable auth method")
	}
	if _, err := c.Write([]byte{socksVersion, want}); err != nil {
		return err
	}
	if want == methodUserPass {
		return s.checkUserPass(c)
	}
	return nil
}

func (s *socksServer) checkUserPass(c net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != authVersion {
		return errors.New("bad auth version")
	}
	user := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return err
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(c, plenBuf); err != nil {
		return err
	}
	pass := make([]byte, plenBuf[0])
	if _, err := io.ReadFull(c, pass); err != nil {
		return err
	}
	// Constant-time comparison so attempt latency does not leak the credential
	// prefix length (subtle.ConstantTimeCompare returns 0 on a length mismatch).
	cand := string(user) + ":" + string(pass)
	if subtle.ConstantTimeCompare([]byte(cand), []byte(s.auth)) == 1 {
		_, err := c.Write([]byte{authVersion, 0x00})
		return err
	}
	c.Write([]byte{authVersion, 0x01})
	return errors.New("bad credentials")
}

// readRequest parses the SOCKS5 request and returns the dial target (literal
// IP:port), resolving a domain name through the tunnel resolver.
func (s *socksServer) readRequest(ctx context.Context, c net.Conn) (string, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", err
	}
	if hdr[0] != socksVersion {
		return "", errors.New("bad request version")
	}
	if hdr[1] != cmdConnect {
		writeReply(c, repCommandNotSupport)
		return "", fmt.Errorf("unsupported command %d (only CONNECT)", hdr[1])
	}

	var host, domain string
	switch hdr[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return "", err
		}
		name := make([]byte, lb[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return "", err
		}
		domain = string(name)
	default:
		writeReply(c, repAddrNotSupport)
		return "", fmt.Errorf("unsupported address type %d", hdr[3])
	}

	// Read the port before any DNS work. The port bytes follow the address on the
	// wire, so a domain lookup done first could burn the client handshake deadline
	// before these two bytes are read, failing an otherwise-valid request after
	// resolution. resolveHost has its own timeout below.
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return "", err
	}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(portBuf)))

	if hdr[3] == atypDomain {
		// Bound the in-tunnel lookup: it dials a separate resolver conn, so the
		// client socket deadline does not apply to it; without this a black-holed
		// DNS server pins this goroutine far past the handshake bound.
		rctx, rcancel := context.WithTimeout(ctx, handshakeTimeout)
		resolved, err := s.resolveHost(rctx, domain)
		rcancel()
		if err != nil {
			// The ATYP (domain) IS supported; the name just did not resolve, so reply
			// Host unreachable (0x04), not Address type not supported (0x08).
			writeReply(c, repHostUnreach)
			return "", fmt.Errorf("resolve %q: %w", domain, err)
		}
		host = resolved
	}

	target := net.JoinHostPort(host, port)
	// Short-circuit obviously-unroutable targets (e.g. 0.0.0.0:443 from a
	// DNS-sinkholed domain) so the client gets an immediate "host unreachable"
	// instead of a 30s dial timeout, and we skip a doomed netstack dial.
	if isUnroutableTarget(host) {
		writeReply(c, repHostUnreach)
		return "", fmt.Errorf("unroutable target %s", target)
	}
	return target, nil
}

// isUnroutableTarget reports whether a literal destination IP can never be a
// valid CONNECT target over the tunnel: the unspecified address (0.0.0.0 / ::,
// often what a DNS sinkhole returns for a blocked domain), link-local, or
// multicast. Private ranges (RFC 1918 and friends) are intentionally NOT
// rejected — they are legitimate destinations behind a VPN; loopback is left to
// the dialer too, since the proxy cannot tell a deliberate target apart. A
// non-literal host (shouldn't occur post-resolve) defers the decision to the dial.
func isUnroutableTarget(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast()
}

// resolveHost resolves a hostname to a literal IP via the tunnel resolver,
// preferring IPv4 (the tunnel is IPv4-only for now).
func (s *socksServer) resolveHost(ctx context.Context, name string) (string, error) {
	ips, err := s.resolver.LookupNetIP(ctx, "ip4", name)
	if err != nil || len(ips) == 0 {
		// Retry any family in case of an IPv6-only name.
		ips, err = s.resolver.LookupNetIP(ctx, "ip", name)
		if err != nil {
			return "", err
		}
	}
	if len(ips) == 0 {
		return "", errors.New("no addresses")
	}
	return ips[0].Unmap().String(), nil
}

// splice copies bidirectionally between client and upstream until either side
// closes or the connection goes idle.
//
// Idle is a property of the whole connection, not of one direction: a bulk
// download is a stream of bytes from upstream while the client stays silent,
// and vice versa for an upload. The deadline must therefore be reset by
// activity in EITHER direction. A shared last-activity timestamp updated by
// both pumps, enforced by a single watchdog, closes the connection only when
// both directions have been quiet for the full idle window. (A naive per-pump
// read deadline kills a healthy one-directional transfer the moment the silent
// side hits the timeout.)
func (s *socksServer) splice(client, upstream net.Conn) {
	var once sync.Once
	stop := func() { once.Do(func() { client.Close(); upstream.Close() }) }
	defer stop()

	var lastNanos atomic.Int64
	lastNanos.Store(time.Now().UnixNano())
	done := make(chan struct{})

	if s.idle > 0 {
		go func() {
			tick := max(s.idle/4, time.Second)
			t := time.NewTicker(tick)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					if time.Since(time.Unix(0, lastNanos.Load())) >= s.idle {
						stop()
						return
					}
				}
			}
		}()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	type closeWriter interface{ CloseWrite() error }
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				lastNanos.Store(time.Now().UnixNano())
				if _, werr := dst.Write(buf[:n]); werr != nil {
					stop() // write side is broken — tear both directions down
					return
				}
			}
			if err != nil {
				// Source closed/errored: half-close the destination's write side so
				// the peer sees EOF while the OTHER direction keeps relaying in-flight
				// data (a client that shutdown(SHUT_WR)s after its request still gets
				// the full response). The outer deferred stop() closes both when splice
				// returns. Only half-close when the idle watchdog is armed (s.idle > 0):
				// it reaps a peer that received our FIN but never closes its own half,
				// which would otherwise block the surviving pump forever. With the idle
				// timeout disabled, fall back to the unconditional teardown so a
				// pathological half-open peer cannot leak the goroutines/conns.
				if cw, ok := dst.(closeWriter); ok && s.idle > 0 {
					_ = cw.CloseWrite()
				} else {
					stop()
				}
				return
			}
		}
	}
	go pump(upstream, client)
	go pump(client, upstream)
	wg.Wait()
	close(done)
}

// dialReplyCode maps an upstream dial error to the closest SOCKS5 reply code: a
// timeout (an unreachable host that never RSTs) becomes Host unreachable (0x04),
// which a client can distinguish from a genuine refusal; everything else stays
// Connection refused (0x05).
func dialReplyCode(err error) byte {
	if errors.Is(err, context.DeadlineExceeded) {
		return repHostUnreach
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return repHostUnreach
	}
	return repConnRefused
}

// writeReply sends a SOCKS5 reply with a zero BND.ADDR/BND.PORT.
func writeReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{socksVersion, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
