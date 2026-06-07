// Command ipsec2socks dials an IKEv2-EAP-MSCHAPv2 VPN server and exposes the
// tunnel as a local SOCKS5 proxy. Any process can then route traffic through
// the VPN by pointing its SOCKS5 client at the proxy, e.g.:
//
//	curl --socks5-hostname 127.0.0.1:1080 https://example.com
//
// No kernel TUN device is required: the IP packets the ESP layer decrypts feed
// a userspace gVisor TCP/IP stack, and the SOCKS5 server dials through it.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ipsec "github.com/n0madic/go-ipsec"
)

type cliOpts struct {
	server    string
	caFile    string
	eapUser   string
	eapPass   string
	localID   string
	remoteID  string
	listen    string
	socksAuth string
	dns       string
	idle      time.Duration
	timeout   time.Duration
	rekey     time.Duration
	ikeRekey  time.Duration
	dpd       time.Duration
	verbose   bool
	insecure  bool
}

func parseFlags() *cliOpts {
	o := &cliOpts{}
	flag.StringVar(&o.server, "server", "", "VPN server (host[:port], default port 500)")
	flag.StringVar(&o.caFile, "ca", "", "PEM file with CA certificate(s) trusted for the server chain")
	flag.StringVar(&o.eapUser, "eap-user", os.Getenv("IPSEC_EAP_USER"), "EAP-MSCHAPv2 username (default: $IPSEC_EAP_USER)")
	flag.StringVar(&o.eapPass, "eap-pass", os.Getenv("IPSEC_EAP_PASS"), "EAP-MSCHAPv2 password (default: $IPSEC_EAP_PASS)")
	flag.StringVar(&o.localID, "local-id", "", "local IKE identity (email, FQDN, or IP)")
	flag.StringVar(&o.remoteID, "remote-id", "", "expected server identity, matched against the certificate SAN (email, FQDN, or IP)")
	flag.StringVar(&o.listen, "listen", "127.0.0.1:1080", "SOCKS5 listen address")
	flag.StringVar(&o.socksAuth, "socks-auth", "", "optional SOCKS5 username:password (RFC 1929)")
	flag.StringVar(&o.dns, "dns", "", "override DNS server for in-tunnel resolution (IP or IP:53)")
	flag.DurationVar(&o.idle, "idle", 10*time.Minute, "close idle proxied TCP after this duration (0 disables)")
	flag.DurationVar(&o.timeout, "timeout", 45*time.Second, "IKE handshake timeout")
	flag.DurationVar(&o.rekey, "rekey", 0, "Child SA soft lifetime (0 = library default 1h); low values force client-initiated rekey for testing")
	flag.DurationVar(&o.ikeRekey, "ike-rekey", 0, "IKE SA soft lifetime (0 = library default 4h)")
	flag.DurationVar(&o.dpd, "dpd", 0, "Dead Peer Detection interval (0 = library default 30s)")
	flag.BoolVar(&o.verbose, "v", false, "verbose logging (slog Debug)")
	flag.BoolVar(&o.insecure, "insecure-allow-public-bind", false, "allow binding the SOCKS5 listener to a non-loopback address")
	flag.Parse()
	return o
}

func main() {
	opts := parseFlags()
	level := slog.LevelInfo
	if opts.verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if err := run(opts, logger); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(opts *cliOpts, logger *slog.Logger) error {
	if opts.server == "" {
		return errors.New("-server is required")
	}
	if opts.eapUser == "" || opts.eapPass == "" {
		return errors.New("-eap-user and -eap-pass are required (or set $IPSEC_EAP_USER/$IPSEC_EAP_PASS)")
	}
	if err := checkLoopbackBind(opts.listen, opts.insecure); err != nil {
		return err
	}

	cfg := ipsec.Config{
		Server:           opts.server,
		EAP:              ipsec.EAPMSCHAPv2{Username: opts.eapUser, Password: opts.eapPass},
		Logger:           logger,
		RekeyLifetime:    opts.rekey,
		IKERekeyLifetime: opts.ikeRekey,
		DPDTimeout:       opts.dpd,
	}
	if opts.localID != "" {
		cfg.LocalID = parseIdentity(opts.localID)
	}
	if opts.remoteID != "" {
		cfg.RemoteID = parseIdentity(opts.remoteID)
	}
	if opts.caFile != "" {
		pool, err := loadCAPool(opts.caFile)
		if err != nil {
			return err
		}
		cfg.RootCAs = pool
	}

	// Signal handling: first signal cancels; second (or grace timeout) force-exits.
	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-rootCtx.Done():
			return
		}
		select {
		case <-sigCh:
		case <-time.After(5 * time.Second):
		}
		os.Exit(130)
	}()

	dialCtx, dialCancel := context.WithTimeout(rootCtx, opts.timeout+10*time.Second)
	defer dialCancel()

	logger.Info("dialing IKEv2", "server", opts.server, "user", opts.eapUser)
	client, err := ipsec.Dial(dialCtx, cfg)
	if err != nil {
		return fmt.Errorf("ipsec dial: %w", err)
	}
	defer client.Close()
	logger.Info("tunnel up", "localIP", client.LocalIP(), "localIP6", client.LocalIP6(), "dns", client.DNS())

	resolver, err := buildResolver(client, opts.dns)
	if err != nil {
		return err
	}

	srv := &socksServer{
		dial:     client.DialContext,
		resolver: resolver,
		auth:     opts.socksAuth,
		idle:     opts.idle,
		log:      logger,
	}
	return srv.serve(rootCtx, opts.listen)
}

// parseIdentity infers an IKE identity kind from a string: "@"→email,
// parseable IP→IPv4, otherwise FQDN.
func parseIdentity(s string) ipsec.Identity {
	if strings.Contains(s, "@") {
		return ipsec.Email(s)
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
		return ipsec.IPv4(a)
	}
	return ipsec.FQDN(s)
}

// loadCAPool reads PEM certificates into a pool.
func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %q", path)
	}
	return pool, nil
}

// checkLoopbackBind rejects a non-loopback listen address unless explicitly
// allowed, so the open proxy is not accidentally exposed to the network.
func checkLoopbackBind(listen string, allow bool) error {
	if allow {
		return nil
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("bad -listen %q: %w", listen, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// Hostname — require it to be localhost.
		if host == "localhost" {
			return nil
		}
		return fmt.Errorf("-listen %q is not loopback; pass -insecure-allow-public-bind to override", listen)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("-listen %q is not loopback; pass -insecure-allow-public-bind to override", listen)
	}
	return nil
}
