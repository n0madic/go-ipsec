// Command ipsec2socks dials an IKEv2 VPN server (authenticating with either
// EAP-MSCHAPv2 or a pre-shared key) and exposes the tunnel as a local SOCKS5
// proxy. Any process can then route traffic through the VPN by pointing its
// SOCKS5 client at the proxy, e.g.:
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
	psk       string
	localID   string
	remoteID  string
	listen    string
	socksAuth string
	dns       string
	maxConns  int
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
	flag.StringVar(&o.psk, "psk", os.Getenv("IPSEC_PSK"), "pre-shared key for PSK auth (default: $IPSEC_PSK); mutually exclusive with -eap-user/-eap-pass")
	flag.StringVar(&o.localID, "local-id", "", "local IKE identity (email, FQDN, or IP)")
	flag.StringVar(&o.remoteID, "remote-id", "", "expected server identity, matched against the certificate SAN (email, FQDN, or IP)")
	flag.StringVar(&o.listen, "listen", "127.0.0.1:1080", "SOCKS5 listen address")
	flag.StringVar(&o.socksAuth, "socks-auth", "", "optional SOCKS5 username:password (RFC 1929)")
	flag.StringVar(&o.dns, "dns", "", "override DNS server for in-tunnel resolution (IP or IP:53)")
	flag.IntVar(&o.maxConns, "max-conns", 1024, "maximum concurrent proxied connections (0 = unlimited)")
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
	// Authentication: exactly one of PSK or EAP-MSCHAPv2.
	hasPSK := opts.psk != ""
	hasEAP := opts.eapUser != "" || opts.eapPass != ""
	switch {
	case hasPSK && hasEAP:
		return errors.New("set either -psk or -eap-user/-eap-pass, not both")
	case !hasPSK && !hasEAP:
		return errors.New("authentication required: -psk (or $IPSEC_PSK), or -eap-user/-eap-pass (or $IPSEC_EAP_USER/$IPSEC_EAP_PASS)")
	case hasEAP && (opts.eapUser == "" || opts.eapPass == ""):
		return errors.New("-eap-user and -eap-pass are both required for EAP-MSCHAPv2 auth")
	}
	if opts.timeout <= 0 {
		return errors.New("-timeout must be positive")
	}
	if opts.idle < 0 {
		return errors.New("-idle must be >= 0 (0 disables the idle timeout)")
	}
	if opts.maxConns < 0 {
		return errors.New("-max-conns must be >= 0 (0 = unlimited)")
	}
	if opts.socksAuth != "" && !strings.Contains(opts.socksAuth, ":") {
		return errors.New(`-socks-auth must be "user:password"`)
	}
	if err := checkLoopbackBind(opts.listen, opts.insecure, opts.socksAuth != ""); err != nil {
		return err
	}

	cfg := ipsec.Config{
		Server:           opts.server,
		Logger:           logger,
		RekeyLifetime:    opts.rekey,
		IKERekeyLifetime: opts.ikeRekey,
		DPDTimeout:       opts.dpd,
	}
	if hasPSK {
		cfg.PSK = opts.psk
	} else {
		cfg.EAP = ipsec.EAPMSCHAPv2{Username: opts.eapUser, Password: opts.eapPass}
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
		grace := time.NewTimer(5 * time.Second)
		defer grace.Stop()
		select {
		case <-sigCh:
		case <-grace.C:
		}
		os.Exit(130)
	}()

	dialCtx, dialCancel := context.WithTimeout(rootCtx, opts.timeout+10*time.Second)
	defer dialCancel()

	authMode := "eap-mschapv2"
	if hasPSK {
		authMode = "psk"
	}
	logger.Info("dialing IKEv2", "server", opts.server, "auth", authMode)
	client, err := ipsec.Dial(dialCtx, cfg)
	if err != nil {
		return fmt.Errorf("ipsec dial: %w", err)
	}
	defer func() { _ = client.Close() }()
	logger.Info("tunnel up", "localIP", client.LocalIP(), "localIP6", client.LocalIP6(), "dns", client.DNS())

	resolver, err := buildResolver(client, opts.dns)
	if err != nil {
		return err
	}

	srv := &socksServer{
		dial:     client.DialContext,
		resolver: resolver,
		maxConns: opts.maxConns,
		idle:     opts.idle,
		log:      logger,
	}
	if opts.socksAuth != "" {
		user, pass, _ := strings.Cut(opts.socksAuth, ":")
		srv.authUser, srv.authPass, srv.authOn = []byte(user), []byte(pass), true
	}
	return srv.serve(rootCtx, opts.listen)
}

// parseIdentity infers an IKE identity kind from a string: "@"→email,
// parseable IP→IPv4/IPv6, otherwise FQDN. An IPv6 literal must become an IP
// identity, not an FQDN — a DNS-type IDr would never match the server
// certificate's IP SAN and a legitimate server would be rejected.
func parseIdentity(s string) ipsec.Identity {
	if strings.Contains(s, "@") {
		return ipsec.Email(s)
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Unmap().Is4() {
			return ipsec.IPv4(a)
		}
		return ipsec.IPv6(a)
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
// allowed, and even then requires SOCKS auth — an open, unauthenticated relay
// onto the VPN network is never a sane configuration, and the flag name only
// signals "non-loopback bind", not "and also unauthenticated".
func checkLoopbackBind(listen string, allow, hasAuth bool) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("bad -listen %q: %w", listen, err)
	}
	loopback := host == "localhost" // hostname form: require localhost
	if ip, perr := netip.ParseAddr(host); perr == nil {
		loopback = ip.IsLoopback()
	}
	if loopback {
		return nil
	}
	if !allow {
		return fmt.Errorf("-listen %q is not loopback; pass -insecure-allow-public-bind to override", listen)
	}
	if !hasAuth {
		return fmt.Errorf("-listen %q is not loopback and no -socks-auth is set; refusing to expose an unauthenticated proxy", listen)
	}
	return nil
}
