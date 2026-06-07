package ipsec

import (
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
)

func TestConfigValidateRequiresCredentials(t *testing.T) {
	base := func() Config {
		return Config{
			Server: "vpn.example.com:500",
			EAP:    EAPMSCHAPv2{Username: "user", Password: "secret"},
		}
	}

	// A fully-populated config validates and fills defaults.
	ok := base()
	if err := ok.validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if ok.MTU != DefaultMTU {
		t.Fatal("validate did not fill defaults")
	}

	// Missing password is rejected (it previously slipped through and failed
	// deep in IKE_AUTH with an opaque error).
	noPass := base()
	noPass.EAP.Password = ""
	if err := noPass.validate(); err == nil {
		t.Fatal("empty EAP.Password accepted")
	}

	noUser := base()
	noUser.EAP.Username = ""
	if err := noUser.validate(); err == nil {
		t.Fatal("empty EAP.Username accepted")
	}

	noServer := base()
	noServer.Server = ""
	if err := noServer.validate(); err == nil {
		t.Fatal("empty Server accepted")
	}
}

// TestConfigValidatePSK covers the PSK/EAP credential dispatch: a PSK-only config
// validates (no EAP, no RootCAs needed), supplying both PSK and EAP is rejected as
// ambiguous, and supplying neither is rejected.
func TestConfigValidatePSK(t *testing.T) {
	pskOnly := Config{Server: "vpn.example.com:500", PSK: "sharedsecret"}
	if err := pskOnly.validate(); err != nil {
		t.Fatalf("PSK-only config rejected: %v", err)
	}
	if pskOnly.MTU != DefaultMTU {
		t.Fatal("validate did not fill defaults for a PSK config")
	}

	both := Config{
		Server: "vpn.example.com:500",
		PSK:    "sharedsecret",
		EAP:    EAPMSCHAPv2{Username: "user", Password: "secret"},
	}
	if err := both.validate(); err == nil {
		t.Fatal("config with both PSK and EAP accepted")
	}

	neither := Config{Server: "vpn.example.com:500"}
	if err := neither.validate(); err == nil {
		t.Fatal("config with neither PSK nor EAP accepted")
	}
}

// TestConfigValidateFloorsRekeyMaxPackets is finding #6: a tiny non-zero
// RekeyMaxPackets is raised to MinRekeyMaxPackets so it cannot churn the data
// plane; zero keeps the "use the built-in default" contract; a value at or above
// the floor is left untouched.
func TestConfigValidateFloorsRekeyMaxPackets(t *testing.T) {
	base := func() Config {
		return Config{
			Server: "vpn.example.com:500",
			EAP:    EAPMSCHAPv2{Username: "user", Password: "secret"},
		}
	}

	tiny := base()
	tiny.RekeyMaxPackets = 1
	if err := tiny.validate(); err != nil {
		t.Fatal(err)
	}
	if tiny.RekeyMaxPackets != MinRekeyMaxPackets {
		t.Fatalf("tiny RekeyMaxPackets = %d, want floored to %d", tiny.RekeyMaxPackets, MinRekeyMaxPackets)
	}

	zero := base()
	zero.RekeyMaxPackets = 0
	if err := zero.validate(); err != nil {
		t.Fatal(err)
	}
	if zero.RekeyMaxPackets != 0 {
		t.Fatalf("zero RekeyMaxPackets = %d, want left at 0 (default contract)", zero.RekeyMaxPackets)
	}

	ok := base()
	ok.RekeyMaxPackets = MinRekeyMaxPackets
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	if ok.RekeyMaxPackets != MinRekeyMaxPackets {
		t.Fatalf("at-floor RekeyMaxPackets = %d, want unchanged %d", ok.RekeyMaxPackets, MinRekeyMaxPackets)
	}
}

// TestConfigValidateFloorsKeepAlive: a non-positive KeepAlive (including a
// negative duration that previously slipped through the ==0 check and silently
// disabled NAT keepalives) is floored to the default; a positive value is kept.
func TestConfigValidateFloorsKeepAlive(t *testing.T) {
	base := func() Config {
		return Config{
			Server: "vpn.example.com:500",
			EAP:    EAPMSCHAPv2{Username: "user", Password: "secret"},
		}
	}

	neg := base()
	neg.KeepAlive = -5 * time.Second
	if err := neg.validate(); err != nil {
		t.Fatal(err)
	}
	if neg.KeepAlive != DefaultKeepAlive {
		t.Fatalf("negative KeepAlive = %v, want default %v", neg.KeepAlive, DefaultKeepAlive)
	}

	custom := base()
	custom.KeepAlive = 7 * time.Second
	if err := custom.validate(); err != nil {
		t.Fatal(err)
	}
	if custom.KeepAlive != 7*time.Second {
		t.Fatalf("positive KeepAlive overwritten: %v", custom.KeepAlive)
	}
}

// TestConfigValidateDefaultsNegativeDurations: every duration knob (not just
// KeepAlive) treats a negative value as "unset" and falls back to its default,
// so a negative rekey lifetime cannot silently disable time-based rekey and a
// negative backoff cannot busy-loop the redial.
func TestConfigValidateDefaultsNegativeDurations(t *testing.T) {
	c := Config{
		Server:                  "vpn.example.com:500",
		EAP:                     EAPMSCHAPv2{Username: "user", Password: "secret"},
		DPDTimeout:              -1 * time.Second,
		RekeyLifetime:           -1 * time.Second,
		IKERekeyLifetime:        -1 * time.Second,
		ReconnectBackoffBase:    -1 * time.Second,
		ReconnectBackoffMax:     -1 * time.Second,
		ReconnectAttemptTimeout: -1 * time.Second,
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]struct{ have, want time.Duration }{
		"DPDTimeout":              {c.DPDTimeout, DefaultDPDTimeout},
		"RekeyLifetime":           {c.RekeyLifetime, DefaultRekeyLifetime},
		"IKERekeyLifetime":        {c.IKERekeyLifetime, DefaultIKERekeyLifetime},
		"ReconnectBackoffBase":    {c.ReconnectBackoffBase, DefaultReconnectBackoffBase},
		"ReconnectBackoffMax":     {c.ReconnectBackoffMax, DefaultReconnectBackoffMax},
		"ReconnectAttemptTimeout": {c.ReconnectAttemptTimeout, DefaultReconnectAttemptTimeout},
	} {
		if got.have != got.want {
			t.Errorf("%s = %v, want default %v", name, got.have, got.want)
		}
	}
}

// TestConfigValidateClampsReplayWindow: an oversized ReplayWindow is clamped to
// the maximum the ESP layer can allocate (preventing the word-count overflow /
// unbounded allocation in NewReplayWindow).
func TestConfigValidateClampsReplayWindow(t *testing.T) {
	c := Config{
		Server:       "vpn.example.com:500",
		EAP:          EAPMSCHAPv2{Username: "user", Password: "secret"},
		ReplayWindow: 1 << 30,
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.ReplayWindow != esp.MaxReplayWindow {
		t.Fatalf("ReplayWindow = %d, want clamped to %d", c.ReplayWindow, esp.MaxReplayWindow)
	}
}
