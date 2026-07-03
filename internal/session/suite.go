package session

import (
	"fmt"
	"slices"
	"strings"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
)

// keyLenAES256 is the AES-256 Key Length attribute value (in bits) carried on
// the encryption transform of the IKE suite and the AES-based ESP suites.
const keyLenAES256 uint16 = 256

// espSuite describes one negotiable ESP transform suite: the wire transforms
// it is offered and matched by, and the per-direction KEYMAT lengths
// internal/ikesa derives for it.
type espSuite struct {
	id     esp.Suite
	encrID uint16 // ENCR transform ID
	// keyBits is the Key Length attribute value on the ENCR transform; 0 means
	// the attribute is ABSENT (ChaCha20-Poly1305, RFC 7634 §2 — its key size is
	// implicit and a peer must not attach the attribute). Matching is strict in
	// both directions: tolerance here would let the two ends derive different
	// KEYMAT lengths.
	keyBits    uint16
	encrKeyLen int // per-direction encryption KEYMAT (including the salt for AEAD)
	// integID is the INTEG transform ID; 0 means the suite is AEAD and no INTEG
	// transform is emitted (this client never offers an explicit AUTH_NONE).
	integID     uint16
	integKeyLen int // per-direction integrity KEYMAT (0 for AEAD)
}

// name returns the suite's diagnostic name (shared with esp.Suite.String).
func (s espSuite) name() string { return s.id.String() }

// aead reports whether the suite is a combined-mode (AEAD) cipher.
func (s espSuite) aead() bool { return s.integID == 0 }

// espSuites is the full suite table in this client's preference order:
// AES-256-GCM-16 (hardware-accelerated single pass), ChaCha20-Poly1305
// (fast without AES-NI), then the RFC-MUST AES-CBC-256 + HMAC-SHA2-256-128.
var espSuites = []espSuite{
	{id: esp.SuiteAESGCM256, encrID: ikemsg.ENCR_AES_GCM_16, keyBits: keyLenAES256, encrKeyLen: 36},
	{id: esp.SuiteChaCha20Poly1305, encrID: ikemsg.ENCR_CHACHA20_POLY1305, encrKeyLen: 36},
	{id: esp.SuiteAESCBC256SHA256, encrID: ikemsg.ENCR_AES_CBC, keyBits: keyLenAES256, encrKeyLen: 32,
		integID: ikemsg.AUTH_HMAC_SHA2_256_128, integKeyLen: 32},
}

// espSuiteByID returns the table row for an esp.Suite id.
func espSuiteByID(id esp.Suite) (espSuite, bool) {
	for _, s := range espSuites {
		if s.id == id {
			return s, true
		}
	}
	return espSuite{}, false
}

// enabledESPSuites maps Config.ESPSuites into suite-table rows, preserving the
// caller's preference order; nil/empty enables the full table in its built-in
// order. Unknown ids are skipped (the public config layer validates them).
func (s *Session) enabledESPSuites() []espSuite {
	if len(s.cfg.ESPSuites) == 0 {
		return espSuites
	}
	out := make([]espSuite, 0, len(s.cfg.ESPSuites))
	for _, id := range s.cfg.ESPSuites {
		if es, ok := espSuiteByID(id); ok {
			out = append(out, es)
		}
	}
	return out
}

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

// ikeSuite describes one negotiable IKE SA (SK{} envelope) transform suite:
// the wire transforms it is offered and matched by, and the SK_e*/SK_a*
// lengths internal/ikesa derives for it (the suite fixes the SKEYSEED split —
// RFC 5282 §7). The PRF is PRF_HMAC_SHA2_256 in every row: it also drives the
// AUTH signed octets, so only the encryption transform is negotiable.
type ikeSuite struct {
	id     ikesa.Suite
	encrID uint16 // ENCR transform ID
	// keyBits is the Key Length attribute value on the ENCR transform; 0 means
	// the attribute is ABSENT (ChaCha20-Poly1305, RFC 7634 §2). Matching is
	// strict in both directions, like the ESP table.
	keyBits    uint16
	encrKeyLen int // SK_e* length (including the 4-byte salt for AEAD)
	// integID is the INTEG transform ID; 0 means the suite is AEAD and no INTEG
	// transform is emitted (this client never offers an explicit AUTH_NONE).
	integID     uint16
	integKeyLen int // SK_a* length (0 for AEAD)
}

// name returns the suite's diagnostic name (shared with ikesa.Suite.String).
func (s ikeSuite) name() string { return s.id.String() }

// aead reports whether the suite is a combined-mode (AEAD) cipher.
func (s ikeSuite) aead() bool { return s.integID == 0 }

// ikeSuites is the negotiable IKE suite table in this client's preference
// order, mirroring the ESP table: AES-256-GCM-16 (RFC 5282, single pass,
// hardware-accelerated), ChaCha20-Poly1305 (RFC 7634), then the RFC-MUST
// AES-CBC-256 + HMAC-SHA2-256-128.
var ikeSuites = []ikeSuite{
	{id: ikesa.SuiteAESGCM256, encrID: ikemsg.ENCR_AES_GCM_16, keyBits: keyLenAES256, encrKeyLen: 36},
	{id: ikesa.SuiteChaCha20Poly1305, encrID: ikemsg.ENCR_CHACHA20_POLY1305, encrKeyLen: 36},
	{id: ikesa.SuiteAESCBC256SHA256, encrID: ikemsg.ENCR_AES_CBC, keyBits: keyLenAES256, encrKeyLen: 32,
		integID: ikemsg.AUTH_HMAC_SHA2_256_128, integKeyLen: 32},
}

// ikeSuiteByID returns the table row for an ikesa.Suite id.
func ikeSuiteByID(id ikesa.Suite) (ikeSuite, bool) {
	for _, s := range ikeSuites {
		if s.id == id {
			return s, true
		}
	}
	return ikeSuite{}, false
}

// enabledIKESuites maps Config.IKESuites into suite-table rows, preserving the
// caller's preference order; nil/empty enables the full table in its built-in
// order. Unknown ids are skipped (the public config layer validates them).
func (s *Session) enabledIKESuites() []ikeSuite {
	if len(s.cfg.IKESuites) == 0 {
		return ikeSuites
	}
	out := make([]ikeSuite, 0, len(s.cfg.IKESuites))
	for _, id := range s.cfg.IKESuites {
		if is, ok := ikeSuiteByID(id); ok {
			out = append(out, is)
		}
	}
	return out
}

// buildIKEProposalForSuite returns the protocol-IKE proposal for one suite,
// with transforms in the canonical order Encr, PRF, [Integ], DH (RFC 7296
// §3.3; an IKE proposal carries no ESN). spi is empty for IKE_SA_INIT and the
// 8-byte IKE SPI for CREATE_CHILD_SA rekeys. An AEAD suite emits no INTEG
// transform (RFC 7296 §3.3.3) and a keyBits==0 suite no Key Length attribute.
func buildIKEProposalForSuite(number uint8, s ikeSuite, spi []byte, groups ...uint16) ikemsg.Proposal {
	p := ikemsg.Proposal{
		Number:   number,
		Protocol: ikemsg.ProtocolIKE,
		Transforms: []ikemsg.Transform{
			{Type: ikemsg.TransformEncr, ID: s.encrID, KeyLength: s.keyBits, HasKeyLength: s.keyBits != 0},
			{Type: ikemsg.TransformPRF, ID: ikemsg.PRF_HMAC_SHA2_256},
		},
	}
	if len(spi) > 0 {
		p.SPI = append([]byte(nil), spi...)
	}
	if !s.aead() {
		p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformInteg, ID: s.integID})
	}
	for _, g := range groups {
		p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformDH, ID: g})
	}
	return p
}

// buildIKEProposals returns one IKE proposal per enabled suite for IKE_SA_INIT,
// numbered 1..n in the given preference order — the same one-proposal-per-suite
// discipline as buildESPProposals (our preference governs the responder's pick,
// selections map back to suites trivially, AEAD and non-AEAD transforms never
// mix in one proposal). Any DH groups are advertised identically on every
// proposal.
func buildIKEProposals(suites []ikeSuite, groups ...uint16) []ikemsg.Proposal {
	props := make([]ikemsg.Proposal, 0, len(suites))
	for i, s := range suites {
		props = append(props, buildIKEProposalForSuite(uint8(i+1), s, nil, groups...))
	}
	return props
}

// buildIKEProposalsSPI is the CREATE_CHILD_SA (IKE SA rekey) variant of
// buildIKEProposals, carrying the new 8-byte IKE SPI on every proposal.
func buildIKEProposalsSPI(spi []byte, suites []ikeSuite, groups ...uint16) []ikemsg.Proposal {
	props := make([]ikemsg.Proposal, 0, len(suites))
	for i, s := range suites {
		props = append(props, buildIKEProposalForSuite(uint8(i+1), s, spi, groups...))
	}
	return props
}

// buildESPProposalForSuite returns the protocol-ESP Child SA proposal for one
// suite, carrying the given 4-byte SPI. Transforms are emitted in the canonical
// order Encr, [Integ], [DH...], ESN (RFC 7296 §3.3) so the encoding is
// byte-deterministic; an AEAD suite carries no INTEG transform (RFC 7296
// §3.3.3), and a suite with keyBits==0 carries no Key Length attribute.
func buildESPProposalForSuite(number uint8, s espSuite, spi []byte, groups ...uint16) ikemsg.Proposal {
	p := ikemsg.Proposal{
		Number:   number,
		Protocol: ikemsg.ProtocolESP,
		SPI:      append([]byte(nil), spi...),
		Transforms: []ikemsg.Transform{
			{Type: ikemsg.TransformEncr, ID: s.encrID, KeyLength: s.keyBits, HasKeyLength: s.keyBits != 0},
		},
	}
	if !s.aead() {
		p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformInteg, ID: s.integID})
	}
	for _, g := range groups {
		p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformDH, ID: g})
	}
	p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformESN, ID: ikemsg.ESN_NONE})
	return p
}

// buildESPProposals returns one proposal per enabled suite, numbered 1..n in
// the given preference order. One proposal per suite (rather than one proposal
// with alternative ENCR transforms) keeps the GCM-vs-ChaCha choice under OUR
// preference (a responder picks the first proposal it can run), maps a
// selection back to its suite trivially, and never mixes AEAD and non-AEAD
// transforms in one proposal (RFC 7296 §3.3.3). Any DH groups are advertised
// identically on every proposal.
func buildESPProposals(spi []byte, suites []espSuite, groups ...uint16) []ikemsg.Proposal {
	props := make([]ikemsg.Proposal, 0, len(suites))
	for i, s := range suites {
		props = append(props, buildESPProposalForSuite(uint8(i+1), s, spi, groups...))
	}
	return props
}

// hasTransform reports whether the offered transforms include one with the given
// IANA ID (and, when keyLen != nil, that key-length attribute — where a *keyLen
// of 0 requires the attribute to be ABSENT). A peer that INITIATES a
// CREATE_CHILD_SA offers MULTIPLE alternative transforms per type for us to
// choose from — strongSwan, for example, offers both No-ESN and ESN by default.
// Suite matching therefore checks that our required transform is PRESENT among
// the offered alternatives, not that it is the sole option (which only holds
// for an already-narrowed responder selection). RFC 7296 §3.3.
func hasTransform(ts []ikemsg.Transform, id uint16, keyLen *uint16) bool {
	for _, t := range ts {
		if t.ID != id {
			continue
		}
		if keyLen != nil {
			switch {
			case *keyLen == 0 && t.HasKeyLength:
				continue // key length must be ABSENT
			case *keyLen != 0 && (!t.HasKeyLength || t.KeyLength != *keyLen):
				continue
			}
		}
		return true
	}
	return false
}

// ikeSuiteMatchesProposal reports whether an IKE proposal offers the given
// suite, tolerating extra alternative transforms a peer-initiated proposal may
// list alongside ours (presence semantics, like suiteMatchesProposal). The
// ENCR key length is matched strictly in both directions, the PRF must be
// present, and for an AEAD suite the proposal must carry either no INTEG
// transform or an explicit AUTH_NONE among the alternatives (RFC 7296 §3.3.3).
// The DH group is checked separately by the callers — the constraint differs
// per exchange (IKE_SA_INIT narrows via selectedDHGroup, a rekey via the KE
// group).
func ikeSuiteMatchesProposal(s ikeSuite, p ikemsg.Proposal) bool {
	if p.Protocol != ikemsg.ProtocolIKE {
		return false
	}
	keyBits := s.keyBits
	if !hasTransform(p.ByType(ikemsg.TransformEncr), s.encrID, &keyBits) {
		return false
	}
	if !hasTransform(p.ByType(ikemsg.TransformPRF), ikemsg.PRF_HMAC_SHA2_256, nil) {
		return false
	}
	integs := p.ByType(ikemsg.TransformInteg)
	if s.aead() {
		return len(integs) == 0 || hasTransform(integs, ikemsg.AUTH_NONE, nil)
	}
	return hasTransform(integs, s.integID, nil)
}

// isIKESelectionFor reports whether p is a valid narrowed responder SELECTION
// of the given IKE suite: exactly one ENCR transform, exactly one PRF, and an
// unambiguous integrity type (none or a single AUTH_NONE for AEAD, exactly one
// HMAC otherwise). The selected suite fixes the SKEYSEED split — SK_a* absent
// and SK_e* salted for AEAD — so an ambiguous "selection" would leave the key
// schedule undefined (mirrors isESPSelectionFor).
func isIKESelectionFor(s ikeSuite, p ikemsg.Proposal) bool {
	if !ikeSuiteMatchesProposal(s, p) ||
		len(p.ByType(ikemsg.TransformEncr)) != 1 || len(p.ByType(ikemsg.TransformPRF)) != 1 {
		return false
	}
	integs := p.ByType(ikemsg.TransformInteg)
	if s.aead() {
		return len(integs) == 0 || (len(integs) == 1 && integs[0].ID == ikemsg.AUTH_NONE)
	}
	return len(integs) == 1
}

// selectedIKESuite maps a narrowed responder IKE proposal to the single
// enabled suite it selects, or ok=false when the proposal is ambiguous or
// selects a suite we did not offer. At most one suite can pass
// isIKESelectionFor (the single ENCR transform pins the suite), so the enabled
// order does not matter here — it is the responder's choice being decoded.
func selectedIKESuite(p ikemsg.Proposal, enabled []ikeSuite) (ikeSuite, bool) {
	for _, s := range enabled {
		if isIKESelectionFor(s, p) {
			return s, true
		}
	}
	return ikeSuite{}, false
}

// suiteMatchesProposal reports whether an ESP proposal offers the given suite,
// tolerating extra alternative transforms a peer-initiated proposal may list
// alongside ours (presence semantics). The ENCR key length is matched strictly
// in both directions: keyBits==0 (ChaCha20-Poly1305) matches only a transform
// WITHOUT the Key Length attribute, and keyBits==256 only a transform carrying
// exactly 256 — tolerance would silently desync the KEYMAT lengths. For an AEAD
// suite the proposal must carry either no INTEG transform or an explicit
// AUTH_NONE among the alternatives; a proposal whose only integrity options are
// real algorithms cannot be narrowed to this suite (RFC 7296 §3.3.3 forbids
// combining an AEAD cipher with a separate integrity transform).
func suiteMatchesProposal(s espSuite, p ikemsg.Proposal) bool {
	if p.Protocol != ikemsg.ProtocolESP {
		return false
	}
	keyBits := s.keyBits
	if !hasTransform(p.ByType(ikemsg.TransformEncr), s.encrID, &keyBits) {
		return false
	}
	integs := p.ByType(ikemsg.TransformInteg)
	if s.aead() {
		if len(integs) > 0 && !hasTransform(integs, ikemsg.AUTH_NONE, nil) {
			return false
		}
	} else if !hasTransform(integs, s.integID, nil) {
		return false
	}
	return hasTransform(p.ByType(ikemsg.TransformESN), ikemsg.ESN_NONE, nil)
}

// isESPSelectionFor reports whether p is a valid narrowed responder SELECTION of
// the given suite. Beyond suiteMatchesProposal (presence among possibly-many
// offered alternatives) it requires exactly one encryption transform and an
// unambiguous integrity type — exactly one HMAC for a non-AEAD suite, none or a
// single AUTH_NONE for an AEAD suite — as an RFC 7296 §2.7 responder selection
// must carry. A responder that echoes multiple alternatives back in what should
// be a single choice is rejected: with several suites offered, an ambiguous
// "selection" leaves the KEYMAT lengths undefined.
func isESPSelectionFor(s espSuite, p ikemsg.Proposal) bool {
	if !suiteMatchesProposal(s, p) || len(p.ByType(ikemsg.TransformEncr)) != 1 {
		return false
	}
	integs := p.ByType(ikemsg.TransformInteg)
	if s.aead() {
		return len(integs) == 0 || (len(integs) == 1 && integs[0].ID == ikemsg.AUTH_NONE)
	}
	return len(integs) == 1
}

// selectedESPSuite maps a narrowed responder proposal to the single enabled
// suite it selects, or ok=false when the proposal is ambiguous or selects a
// suite we did not offer. At most one suite can pass isESPSelectionFor (the
// single ENCR transform pins the suite), so the enabled order does not matter
// here — it is the responder's choice being decoded, not a preference.
func selectedESPSuite(p ikemsg.Proposal, enabled []espSuite) (espSuite, bool) {
	for _, s := range enabled {
		if isESPSelectionFor(s, p) {
			return s, true
		}
	}
	return espSuite{}, false
}

// selectESPProposal picks from a peer-initiated offer: it returns the first
// enabled suite (in OUR preference order) that some offered ESP proposal
// advertises with a 4-byte SPI, together with that proposal. requireGroup, when
// non-zero, additionally requires the proposal to advertise that DH group — a
// peer's KE group may be advertised by only some of its proposals, and the DH
// exchange must run against a proposal that actually offered the group
// (RFC 7296 §3.3).
func selectESPProposal(sa *ikemsg.SAPayload, enabled []espSuite, requireGroup uint16) (ikemsg.Proposal, espSuite, bool) {
	for _, s := range enabled {
		for _, p := range sa.Proposals {
			if !suiteMatchesProposal(s, p) || len(p.SPI) != 4 {
				continue
			}
			if requireGroup != 0 && !proposalHasDHGroup(p, requireGroup) {
				continue
			}
			return p, s, true
		}
	}
	return ikemsg.Proposal{}, espSuite{}, false
}

// selectIKEProposal picks from a peer-initiated IKE-rekey offer: it returns
// the first enabled suite (in OUR preference order) that some offered IKE
// proposal advertises with an 8-byte SPI, together with that proposal.
// requireGroup, when non-zero, additionally requires the proposal to advertise
// that DH group — the peer's KE group may be advertised by only some of its
// proposals, and the DH exchange must run against a proposal that actually
// offered the group (RFC 7296 §3.3; mirrors selectESPProposal).
func selectIKEProposal(sa *ikemsg.SAPayload, enabled []ikeSuite, requireGroup uint16) (ikemsg.Proposal, ikeSuite, bool) {
	for _, s := range enabled {
		for _, p := range sa.Proposals {
			if !ikeSuiteMatchesProposal(s, p) || len(p.SPI) != 8 {
				continue
			}
			if requireGroup != 0 && !proposalHasDHGroup(p, requireGroup) {
				continue
			}
			return p, s, true
		}
	}
	return ikemsg.Proposal{}, ikeSuite{}, false
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
