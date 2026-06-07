package session

import (
	"fmt"
	"slices"
	"strings"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

// keyLenAES256 is the AES-256 Key Length attribute value (in bits) carried on the
// encryption transform of this client's single suite.
const keyLenAES256 uint16 = 256

// espKeyLen is the ESP key material per direction for the v1 suite.
const (
	espEncrKeyLen  = 32 // AES-256
	espIntegKeyLen = 32 // HMAC-SHA2-256 (RFC 4868)
)

// preferredDHGroups lists the DH groups internal/ikesa can run, most-preferred
// first: Curve25519 (group 31), with MODP-2048 (group 14) as the fallback for
// servers that only run modp. It drives both the multi-group offers we build and
// the group we pick from a peer's offer.
var preferredDHGroups = []uint16{ikemsg.DH_X25519, ikemsg.DH_MODP2048}

// supportedDHGroup reports whether g is a DH group we can run.
func supportedDHGroup(g uint16) bool {
	return slices.Contains(preferredDHGroups, g)
}

// proposalHasDHGroup reports whether a proposal offers the given DH group. A
// peer-initiated proposal may list several alternative DH transforms; this checks
// for presence among them (like hasTransform), not that it is the sole option.
func proposalHasDHGroup(p ikemsg.Proposal, g uint16) bool {
	return hasTransform(p.ByType(ikemsg.TransformDH), g, nil)
}

// negotiateDHGroup returns this client's most-preferred DH group that the offered
// proposal advertises, and whether any supported group was found.
func negotiateDHGroup(p ikemsg.Proposal) (uint16, bool) {
	for _, g := range preferredDHGroups {
		if proposalHasDHGroup(p, g) {
			return g, true
		}
	}
	return 0, false
}

// selectedDHGroup returns the single DH-group ID carried by a narrowed responder
// proposal (the responder selects exactly one transform per type, RFC 7296 §2.7),
// or 0 when the proposal carries no DH transform.
func selectedDHGroup(p ikemsg.Proposal) uint16 {
	dh := p.ByType(ikemsg.TransformDH)
	if len(dh) == 0 {
		return 0
	}
	return dh[0].ID
}

// buildIKEProposal returns the protocol-IKE SA proposal for IKE_SA_INIT,
// advertising one DH-group transform per group in the order given (so an
// IKE_SA_INIT offer can list both x25519 and MODP-2048). Transforms are emitted in
// the canonical order Encr, PRF, Integ, DH (RFC 7296 §3.3).
func buildIKEProposal(number uint8, groups ...uint16) ikemsg.Proposal {
	p := ikemsg.Proposal{
		Number:   number,
		Protocol: ikemsg.ProtocolIKE,
		Transforms: []ikemsg.Transform{
			{Type: ikemsg.TransformEncr, ID: ikemsg.ENCR_AES_CBC, KeyLength: keyLenAES256},
			{Type: ikemsg.TransformPRF, ID: ikemsg.PRF_HMAC_SHA2_256},
			{Type: ikemsg.TransformInteg, ID: ikemsg.AUTH_HMAC_SHA2_256_128},
		},
	}
	for _, g := range groups {
		p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformDH, ID: g})
	}
	return p
}

// buildIKEProposalSPI returns the protocol-IKE SA proposal carrying an 8-byte
// SPI, used in CREATE_CHILD_SA when rekeying the IKE SA. The DH groups offered are
// the established group (an IKE rekey reuses the negotiated group).
func buildIKEProposalSPI(number uint8, spi []byte, groups ...uint16) ikemsg.Proposal {
	p := buildIKEProposal(number, groups...)
	p.SPI = append([]byte(nil), spi...)
	return p
}

// buildESPProposal returns the protocol-ESP Child SA proposal carrying the
// given 4-byte SPI: AES-CBC-256 + HMAC-SHA2-256-128, no ESN.
func buildESPProposal(number uint8, spi []byte) ikemsg.Proposal {
	return espProposal(number, spi)
}

// buildESPProposalPFS is buildESPProposal plus one DH-group transform per group,
// offered when a Child SA carries a per-Child Diffie-Hellman exchange (PFS) or
// when the IKE_AUTH child must advertise its DH group(s) for a strict-PFS server.
// The matching KE payload, if any, is added by the caller (RFC 7296 §2.17–§3.4).
func buildESPProposalPFS(number uint8, spi []byte, groups ...uint16) ikemsg.Proposal {
	return espProposal(number, spi, groups...)
}

// espProposal builds the ESP proposal, inserting the DH-group transforms (if any)
// in the canonical position — after Integ, before ESN (RFC 7296 §3.3) — so the
// encoding is byte-deterministic regardless of how many groups are offered.
func espProposal(number uint8, spi []byte, groups ...uint16) ikemsg.Proposal {
	p := ikemsg.Proposal{
		Number:   number,
		Protocol: ikemsg.ProtocolESP,
		SPI:      append([]byte(nil), spi...),
		Transforms: []ikemsg.Transform{
			{Type: ikemsg.TransformEncr, ID: ikemsg.ENCR_AES_CBC, KeyLength: keyLenAES256},
			{Type: ikemsg.TransformInteg, ID: ikemsg.AUTH_HMAC_SHA2_256_128},
		},
	}
	for _, g := range groups {
		p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformDH, ID: g})
	}
	p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformESN, ID: ikemsg.ESN_NONE})
	return p
}

// hasTransform reports whether the offered transforms include one with the given
// IANA ID (and, when keyLen != nil, that key-length attribute). A peer that
// INITIATES a CREATE_CHILD_SA offers MULTIPLE alternative transforms per type for
// us to choose from — strongSwan, for example, offers both No-ESN and ESN by
// default. Suite matching therefore checks that our required transform is PRESENT
// among the offered alternatives, not that it is the sole option (which only holds
// for an already-narrowed responder selection). RFC 7296 §3.3.
func hasTransform(ts []ikemsg.Transform, id uint16, keyLen *uint16) bool {
	for _, t := range ts {
		if t.ID != id {
			continue
		}
		if keyLen != nil && t.KeyLength != *keyLen {
			continue
		}
		return true
	}
	return false
}

// matchesIKESuite reports whether an IKE proposal offers the suite internal/ikesa
// can run (AES-CBC-256 + PRF-HMAC-SHA2-256 + AUTH-HMAC-SHA2-256-128 + a DH group
// we support: x25519 or MODP-2048), tolerating extra alternative transforms a
// peer-initiated proposal may list alongside ours.
func matchesIKESuite(p ikemsg.Proposal) bool {
	if p.Protocol != ikemsg.ProtocolIKE {
		return false
	}
	keyLen := keyLenAES256
	_, dhOK := negotiateDHGroup(p)
	return hasTransform(p.ByType(ikemsg.TransformEncr), ikemsg.ENCR_AES_CBC, &keyLen) &&
		hasTransform(p.ByType(ikemsg.TransformPRF), ikemsg.PRF_HMAC_SHA2_256, nil) &&
		hasTransform(p.ByType(ikemsg.TransformInteg), ikemsg.AUTH_HMAC_SHA2_256_128, nil) &&
		dhOK
}

// matchesESPSuite reports whether an ESP proposal offers the AES-CBC-256 +
// HMAC-SHA2-256-128 + No-ESN suite the ESP layer implements, tolerating extra
// alternative transforms a peer-initiated proposal may list alongside ours.
func matchesESPSuite(p ikemsg.Proposal) bool {
	if p.Protocol != ikemsg.ProtocolESP {
		return false
	}
	keyLen := keyLenAES256
	return hasTransform(p.ByType(ikemsg.TransformEncr), ikemsg.ENCR_AES_CBC, &keyLen) &&
		hasTransform(p.ByType(ikemsg.TransformInteg), ikemsg.AUTH_HMAC_SHA2_256_128, nil) &&
		hasTransform(p.ByType(ikemsg.TransformESN), ikemsg.ESN_NONE, nil)
}

// isESPSelection reports whether p is a valid narrowed responder SELECTION of our
// ESP suite. Beyond matchesESPSuite (presence among possibly-many offered
// alternatives) it requires exactly one encryption and one integrity transform,
// as an RFC 7296 §2.7 responder selection must carry — rejecting a responder that
// echoes multiple ambiguous alternatives back in what should be a single choice.
func isESPSelection(p ikemsg.Proposal) bool {
	return matchesESPSuite(p) &&
		len(p.ByType(ikemsg.TransformEncr)) == 1 &&
		len(p.ByType(ikemsg.TransformInteg)) == 1
}

// selectESPProposal returns the first offered ESP proposal that matches our
// suite and carries a 4-byte SPI, or ok=false if none do. A peer-initiated rekey
// may list several proposals (e.g. an AES-GCM proposal ahead of AES-CBC); we pick
// the one we can run instead of inspecting only the first.
func selectESPProposal(sa *ikemsg.SAPayload) (ikemsg.Proposal, bool) {
	for _, p := range sa.Proposals {
		if matchesESPSuite(p) && len(p.SPI) == 4 {
			return p, true
		}
	}
	return ikemsg.Proposal{}, false
}

// selectIKEProposal returns the first offered IKE proposal that matches our
// suite and carries an 8-byte SPI (CREATE_CHILD_SA IKE rekey), or ok=false.
func selectIKEProposal(sa *ikemsg.SAPayload) (ikemsg.Proposal, bool) {
	for _, p := range sa.Proposals {
		if matchesIKESuite(p) && len(p.SPI) == 8 {
			return p, true
		}
	}
	return ikemsg.Proposal{}, false
}

// describeProposals renders the offered proposals' transform IDs so a no-match
// error names exactly what the peer proposed (the information needed to debug an
// interop mismatch).
func describeProposals(sa *ikemsg.SAPayload) string {
	var b strings.Builder
	for i, p := range sa.Proposals {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "#%d proto=%d enc=%v integ=%v prf=%v dh=%v esn=%v spiLen=%d",
			p.Number, p.Protocol,
			transformIDs(p.ByType(ikemsg.TransformEncr)), transformIDs(p.ByType(ikemsg.TransformInteg)),
			transformIDs(p.ByType(ikemsg.TransformPRF)), transformIDs(p.ByType(ikemsg.TransformDH)),
			transformIDs(p.ByType(ikemsg.TransformESN)), len(p.SPI))
	}
	return b.String()
}

func transformIDs(ts []ikemsg.Transform) []uint16 {
	ids := make([]uint16, len(ts))
	for i, t := range ts {
		ids[i] = t.ID
	}
	return ids
}
