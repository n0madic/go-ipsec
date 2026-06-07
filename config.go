package ipsec

import (
	"crypto/x509"
	"errors"
	"log/slog"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
)

// Default lifecycle parameters.
const (
	DefaultMTU              uint32        = 1400
	DefaultKeepAlive        time.Duration = 20 * time.Second
	DefaultDPDTimeout       time.Duration = 30 * time.Second
	DefaultRekeyLifetime    time.Duration = time.Hour
	DefaultIKERekeyLifetime time.Duration = 4 * time.Hour
	DefaultReplayWindow     uint32        = 64
	// MinRekeyMaxPackets is the floor for a non-zero RekeyMaxPackets: a tiny value
	// would rekey almost every tick and churn the data plane, so validate() floors
	// it (with a warning) rather than honouring an unusable tuning knob.
	MinRekeyMaxPackets uint32 = 4096
	// retransmit bounds for the IKE request/response machinery.
	DefaultRetransmitBase  time.Duration = 2 * time.Second
	DefaultRetransmitMax   time.Duration = 30 * time.Second
	DefaultRetransmitTries int           = 5

	// Auto-reconnect tuning: the redial loop AutoReconnect drives after the IKE
	// SA is declared dead. Backoff grows from Base to Max between attempts; each
	// attempt is bounded by AttemptTimeout.
	DefaultReconnectBackoffBase    time.Duration = 1 * time.Second
	DefaultReconnectBackoffMax     time.Duration = 30 * time.Second
	DefaultReconnectAttemptTimeout time.Duration = 20 * time.Second
)

// Config describes a single IKEv2-EAP-MSCHAPv2 tunnel. Only stdlib-shaped
// fields are exposed; everything provider-specific lives in the caller.
//
// The cipher suite is fixed and not configurable: AES-CBC-256 encryption,
// PRF-HMAC-SHA2-256, AUTH-HMAC-SHA2-256-128 integrity, and a DH group of
// x25519 (group 31, preferred) or MODP-2048 (group 14, fallback) negotiated at
// IKE_SA_INIT. The Child SA reuses AES-CBC-256 + HMAC-SHA2-256-128.
type Config struct {
	// Server is the responder endpoint, host:port. Port defaults to 500.
	Server string

	// LocalID / RemoteID are the IKE identities. RemoteID, when set, is also
	// matched against the server certificate SANs.
	LocalID  Identity
	RemoteID Identity

	// EAP carries the EAP-MSCHAPv2 credentials.
	EAP EAPMSCHAPv2

	// RootCAs is the trust anchor pool for the server certificate chain. When
	// nil the host's system roots are used.
	RootCAs *x509.CertPool

	// Transport supplies the underlying packet socket. When nil a direct UDP
	// dialer is used.
	Transport PacketDialer

	// MTU is the inner tunnel MTU hint (clamped by the data plane).
	MTU uint32

	// Logger receives structured diagnostics. When nil logs are discarded.
	Logger *slog.Logger

	// Lifecycle timers; zero values fall back to the Default* constants.
	KeepAlive        time.Duration
	DPDTimeout       time.Duration
	RekeyLifetime    time.Duration // Child SA soft lifetime
	IKERekeyLifetime time.Duration // IKE SA soft lifetime
	ReplayWindow     uint32

	// RekeyMaxPackets triggers a Child SA rekey once the outbound ESP sequence
	// number reaches it, bounding how much data a single key protects regardless
	// of elapsed time. Zero selects a built-in default (2^31); it is independent
	// of RekeyLifetime, so a tunnel that is idle on the clock but heavy on the
	// wire still rekeys before sequence-number exhaustion. A non-zero value below
	// MinRekeyMaxPackets is raised to that floor (with a warning) to avoid
	// constant rekey churn.
	RekeyMaxPackets uint32

	// ChildSAPFS offers per-Child Perfect Forward Secrecy (a fresh MODP-2048 /
	// group 14 Diffie-Hellman exchange) on Child SA rekeys this client initiates.
	// A server-initiated PFS rekey is always honored regardless of this setting,
	// and once one is seen the client offers PFS on its own rekeys too. Enable it
	// when the peer REQUIRES Child PFS and may rekey before that is learned (cold
	// start). Only group 14 is supported.
	ChildSAPFS bool

	// RequestIPv6 controls whether the client asks the responder for an inner
	// IPv6 address (CFG INTERNAL_IP6_ADDRESS) and offers IPv6 traffic selectors
	// (::/0), so v6 application traffic is carried over ESP instead of failing
	// "network is unreachable". When enabled (the default: a nil pointer or a
	// pointer to true) the tunnel becomes dual-stack iff the responder assigns a
	// v6 address; a v4-only server simply does not, leaving behaviour unchanged.
	// Set it to a pointer to false for strict v4-only appliances.
	RequestIPv6 *bool

	// AutoReconnect controls in-place tunnel re-establishment after the IKE SA is
	// declared dead — e.g. a NAT mapping that expired during a laptop sleep, after
	// which the peer DPD-times us out. When enabled (the default: a nil pointer or
	// a pointer to true) the Client transparently redials on a fresh socket (which
	// re-punches the NAT mapping) and re-addresses the existing netstack in place,
	// so a long-lived binding such as srv.dial = client.DialContext stays valid.
	// Set it to a pointer to false to restore the legacy behavior of tearing the
	// Client down on peer death.
	AutoReconnect *bool

	// Reconnect backoff/timeout knobs; zero values fall back to the Default*
	// constants. They bound the redial loop AutoReconnect drives and are not
	// propagated to the IKE session.
	ReconnectBackoffBase    time.Duration
	ReconnectBackoffMax     time.Duration
	ReconnectAttemptTimeout time.Duration
}

// autoReconnectEnabled resolves the AutoReconnect tri-state: enabled unless the
// caller explicitly passed a pointer to false.
func (c Config) autoReconnectEnabled() bool {
	return c.AutoReconnect == nil || *c.AutoReconnect
}

// requestIPv6Enabled resolves the RequestIPv6 tri-state: enabled unless the
// caller explicitly passed a pointer to false.
func (c Config) requestIPv6Enabled() bool {
	return c.RequestIPv6 == nil || *c.RequestIPv6
}

// EAPMSCHAPv2 holds the inner EAP credentials.
type EAPMSCHAPv2 struct {
	Username string
	Password string
}

// validate fills defaults and rejects unsupported parameters.
func (c *Config) validate() error {
	if c.Server == "" {
		return errors.New("ipsec: Config.Server is required")
	}
	if c.EAP.Username == "" {
		return errors.New("ipsec: Config.EAP.Username is required")
	}
	if c.EAP.Password == "" {
		return errors.New("ipsec: Config.EAP.Password is required")
	}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	// Duration knobs default on <= 0: a negative value is as meaningless as zero
	// (a negative rekey lifetime would disable time-based rekey, a negative
	// backoff would busy-loop the redial), so treat both uniformly as "unset".
	if c.KeepAlive <= 0 {
		c.KeepAlive = DefaultKeepAlive
	}
	if c.DPDTimeout <= 0 {
		c.DPDTimeout = DefaultDPDTimeout
	}
	if c.RekeyLifetime <= 0 {
		c.RekeyLifetime = DefaultRekeyLifetime
	}
	if c.IKERekeyLifetime <= 0 {
		c.IKERekeyLifetime = DefaultIKERekeyLifetime
	}
	if c.ReplayWindow == 0 {
		c.ReplayWindow = DefaultReplayWindow
	}
	if c.ReconnectBackoffBase <= 0 {
		c.ReconnectBackoffBase = DefaultReconnectBackoffBase
	}
	if c.ReconnectBackoffMax <= 0 {
		c.ReconnectBackoffMax = DefaultReconnectBackoffMax
	}
	if c.ReconnectAttemptTimeout <= 0 {
		c.ReconnectAttemptTimeout = DefaultReconnectAttemptTimeout
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	// Clamp an oversized ReplayWindow (checked after Logger is set so the warning
	// lands). esp.NewReplayWindow also clamps defensively; this warns the operator.
	if c.ReplayWindow > esp.MaxReplayWindow {
		c.Logger.Warn("ipsec: ReplayWindow above maximum, clamping it",
			"configured", c.ReplayWindow, "max", esp.MaxReplayWindow)
		c.ReplayWindow = esp.MaxReplayWindow
	}
	// Floor a non-zero RekeyMaxPackets so a tiny value can't churn the data plane
	// with constant rekeys. Zero keeps the "use the built-in default" contract.
	if c.RekeyMaxPackets != 0 && c.RekeyMaxPackets < MinRekeyMaxPackets {
		c.Logger.Warn("ipsec: RekeyMaxPackets below floor, raising it",
			"configured", c.RekeyMaxPackets, "floor", MinRekeyMaxPackets)
		c.RekeyMaxPackets = MinRekeyMaxPackets
	}
	return nil
}
