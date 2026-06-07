package ipsec

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

// TestIdentityRoundTrip checks each Identity kind survives a build → encode →
// decode → reconstruct cycle through the IKE Identification payloads.
func TestIdentityRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		id   Identity
	}{
		{"fqdn", FQDN("gateway.example.com")},
		{"email", Email("user@example.com")},
		{"keyid", KeyID([]byte{0x01, 0x02, 0x03, 0xFF})},
		{"ipv4", IPv4(netip.MustParseAddr("10.1.2.3"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Initiator identity payload.
			c := ikemsg.Payloads{&ikemsg.IDiPayload{IDType: ikemsg.IDType(tc.id.idType()), Data: tc.id.idData()}}
			firstType, raw, err := c.Marshal()
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if firstType != ikemsg.PayloadIDi {
				t.Fatalf("first payload type = %d, want %d", firstType, ikemsg.PayloadIDi)
			}

			dec, err := ikemsg.ParsePayloads(firstType, raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			idp, ok := dec[0].(*ikemsg.IDiPayload)
			if !ok {
				t.Fatalf("decoded payload type %T", dec[0])
			}
			got := identityFromWire(uint8(idp.IDType), idp.Data)
			if got.Kind != tc.id.Kind {
				t.Errorf("kind: got %d want %d", got.Kind, tc.id.Kind)
			}
			if !bytes.Equal(got.Data, tc.id.Data) {
				t.Errorf("data: got %x want %x", got.Data, tc.id.Data)
			}
			if got.String() == "" {
				t.Error("String() empty")
			}
		})
	}
}

// TestIPv4ConstructorGuards is finding #5: ipsec.IPv4 must not panic on a
// non-IPv4 or zero addr; it returns the unset Identity (which validate rejects).
func TestIPv4ConstructorGuards(t *testing.T) {
	if id := IPv4(netip.MustParseAddr("192.0.2.7")); id.Kind != IDKindIPv4 || !bytes.Equal(id.Data, []byte{192, 0, 2, 7}) {
		t.Fatalf("valid IPv4 mishandled: %+v", id)
	}
	// A 4-in-6 address is accepted (unmapped to v4).
	if id := IPv4(netip.MustParseAddr("::ffff:192.0.2.8")); id.Kind != IDKindIPv4 || !bytes.Equal(id.Data, []byte{192, 0, 2, 8}) {
		t.Fatalf("4-in-6 IPv4 mishandled: %+v", id)
	}
	for _, addr := range []netip.Addr{netip.MustParseAddr("2001:db8::1"), {}} {
		if id := IPv4(addr); !id.IsZero() {
			t.Fatalf("IPv4(%v) should be the unset Identity, got %+v", addr, id)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		c := Config{Server: "vpn:500", EAP: EAPMSCHAPv2{Username: "u", Password: "p"}}
		if err := c.validate(); err != nil {
			t.Fatal(err)
		}
		if c.MTU != DefaultMTU || c.ReplayWindow != DefaultReplayWindow {
			t.Fatal("defaults not applied")
		}
	})
	t.Run("missing server", func(t *testing.T) {
		c := Config{EAP: EAPMSCHAPv2{Username: "u"}}
		if err := c.validate(); err == nil {
			t.Fatal("expected error for missing server")
		}
	})
	t.Run("missing user", func(t *testing.T) {
		c := Config{Server: "vpn"}
		if err := c.validate(); err == nil {
			t.Fatal("expected error for missing EAP user")
		}
	})
}
