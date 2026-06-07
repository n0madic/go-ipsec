package session

import (
	"bytes"
	"testing"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

// TestSAProposalRoundTrip asserts the IKE SA proposal encodes and decodes
// byte-exact through the message codec and that the decoded proposal is
// recognised as our v1 suite.
func TestSAProposalRoundTrip(t *testing.T) {
	m := &ikemsg.Message{
		InitiatorSPI: 0x1122334455667788,
		Exchange:     ikemsg.ExchangeIKESAInit,
		Flags:        ikemsg.FlagInitiator,
		Payloads: ikemsg.Payloads{
			&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildIKEProposal(1, ikemsg.DH_X25519, ikemsg.DH_MODP2048)}},
			&ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0xA5}, nonceLen)},
		},
	}

	raw, err := m.Marshal()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	dec, err := ikemsg.Parse(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw2, err := dec.Marshal()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("SA round-trip not byte-exact:\n%x\n%x", raw, raw2)
	}

	var foundSA bool
	for _, p := range dec.Payloads {
		if saP, ok := p.(*ikemsg.SAPayload); ok {
			foundSA = true
			if len(saP.Proposals) != 1 || !matchesIKESuite(saP.Proposals[0]) {
				t.Fatal("decoded proposal does not match v1 suite")
			}
		}
	}
	if !foundSA {
		t.Fatal("no SA payload after round-trip")
	}
}

// TestESPProposalRoundTrip does the same for the ESP Child SA proposal.
func TestESPProposalRoundTrip(t *testing.T) {
	spi := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	m := &ikemsg.Message{
		InitiatorSPI: 1, ResponderSPI: 2,
		Exchange:  ikemsg.ExchangeIKEAuth,
		Flags:     ikemsg.FlagInitiator,
		MessageID: 1,
		Payloads: ikemsg.Payloads{
			&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildESPProposal(1, spi)}},
		},
	}

	raw, err := m.Marshal()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec, err := ikemsg.Parse(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, p := range dec.Payloads {
		if saP, ok := p.(*ikemsg.SAPayload); ok {
			if len(saP.Proposals) != 1 {
				t.Fatalf("got %d proposals", len(saP.Proposals))
			}
			prop := saP.Proposals[0]
			if !bytes.Equal(prop.SPI, spi) {
				t.Fatalf("SPI mismatch: %x", prop.SPI)
			}
			if !matchesESPSuite(prop) {
				t.Fatal("decoded ESP proposal does not match suite")
			}
		}
	}
}

// TestMatchesESPSuiteToleratesAlternatives asserts the matcher accepts a
// peer-initiated offer that lists multiple alternative transforms per type (the
// strongSwan both-ESN default), and that selectESPProposal picks our suite even
// when an unsupported proposal (AES-GCM) is listed first.
func TestMatchesESPSuiteToleratesAlternatives(t *testing.T) {
	multi := buildESPProposalMultiOption(1, []byte{1, 2, 3, 4})
	if !matchesESPSuite(multi) {
		t.Fatal("matcher rejected a valid multi-option offer (both-ESN regression)")
	}

	// An AES-GCM-128 proposal (transform ID 20) we do not support, listed first.
	gcm := ikemsg.Proposal{
		Number: 1, Protocol: ikemsg.ProtocolESP, SPI: []byte{9, 9, 9, 9},
		Transforms: []ikemsg.Transform{
			{Type: ikemsg.TransformEncr, ID: 20, KeyLength: 128},
			{Type: ikemsg.TransformESN, ID: ikemsg.ESN_NONE},
		},
	}
	if matchesESPSuite(gcm) {
		t.Fatal("matcher accepted an unsupported AES-GCM proposal")
	}

	saP := &ikemsg.SAPayload{Proposals: []ikemsg.Proposal{gcm, multi}}
	got, ok := selectESPProposal(saP)
	if !ok || !bytes.Equal(got.SPI, multi.SPI) {
		t.Fatal("selectESPProposal did not skip the unsupported first proposal")
	}
}

func TestWithDefaultPort(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":          "1.2.3.4:500",
		"1.2.3.4:4500":     "1.2.3.4:4500",
		"vpn.example.com":  "vpn.example.com:500",
		"[2001:db8::1]":    "[2001:db8::1]:500",
		"[2001:db8::1]:99": "[2001:db8::1]:99",
	}
	for in, want := range cases {
		if got := withDefaultPort(in); got != want {
			t.Errorf("withDefaultPort(%q) = %q, want %q", in, got, want)
		}
	}
}
