package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
)

// ikeRekeyGrace is how long a superseded IKE SA stays usable for decoding the
// old-SA DELETE and its ack after an IKE-SA rekey cutover.
const ikeRekeyGrace = 30 * time.Second

// DataPlane is the callback surface the driver uses to install rekeyed Child
// SAs in the ESP layer and to observe data-plane liveness. Implemented by
// ipsec.Client.
type DataPlane interface {
	InstallChildSA(u ChildSAUpdate)
	// LastDataInbound reports when the most recent inbound ESP packet arrived
	// (zero time if none), so DPD treats a data-busy tunnel as alive.
	LastDataInbound() time.Time
	// ChildSAVolume reports the current outbound ESP sequence number of the live
	// Child SA, so the driver can rekey on data volume before the 32-bit counter
	// nears exhaustion.
	ChildSAVolume() uint32
}

// ChildSAUpdate carries a rekeyed Child SA, with keys already oriented for this
// client (Out* = our outbound, In* = our inbound). Suite selects the ESP
// transform the keys were derived for (a rekey may change the suite).
type ChildSAUpdate struct {
	NewInSPI  uint32
	NewOutSPI uint32
	OldInSPI  uint32 // 0 → no predecessor (first install)
	Suite     esp.Suite
	OutEncr   []byte
	OutInteg  []byte
	InEncr    []byte
	InInteg   []byte
}

// SetDataPlane wires the ESP data-plane controller used for rekey cutovers.
func (s *Session) SetDataPlane(dp DataPlane) { s.dataPlane = dp }

// ikeCtx bundles an IKE SA with its SPIs so messages can be encoded/decoded
// under a specific (current or superseded) SA.
type ikeCtx struct {
	sa   *ikesa.IKESA
	spii uint64
	spir uint64
}

// exchangeKind tags the single outstanding initiator-initiated exchange.
type exchangeKind int

const (
	exDPD exchangeKind = iota
	exChildRekey
	exIKERekey
	exDelete
)

// pendingExchange is the at-most-one outstanding initiator request (IKEv2
// window size 1). It carries the bytes for retransmit and the rekey context to
// complete on the matching response.
type pendingExchange struct {
	kind           exchangeKind
	msgID          uint32
	raw            []byte
	attempts       int
	nextRetransmit time.Time
	child          *childRekeyCtx
	ike            *ikeRekeyCtx
	// fast tightens the retransmit schedule (fastDPDBase/fastDPDTries) for a DPD
	// probe initiated right after a detected suspend/wake, so a tunnel whose NAT
	// mapping expired during sleep is declared dead in seconds, not ~90s.
	fast bool
}

type childRekeyCtx struct {
	newInSPI uint32
	oldInSPI uint32
	ni       []byte
	// reestablish marks a fresh CREATE_CHILD_SA replacing a Child SA the peer
	// already DELETEd (RFC 7296 §1.3.1), as opposed to a normal rekey of a live
	// SA. It omits the N(REKEY_SA) reference (the old SPI is gone, so a strict
	// responder would answer CHILD_SA_NOT_FOUND) and skips the trailing DELETE
	// (the peer already removed the old SA).
	reestablish bool
	// dh is the ephemeral DH for a PFS rekey we initiated (nil for non-PFS). The
	// response carries the peer's KE; completeChildRekey folds the shared secret
	// into KEYMAT (RFC 7296 §2.17).
	dh *ikesa.DH
}

type ikeRekeyCtx struct {
	newSPIi uint64
	ni      []byte
	dh      *ikesa.DH
}

// --- Child SA rekey ---

// initiateChildRekey starts a CREATE_CHILD_SA exchange for the Child SA. When
// reestablish is false it rekeys the live SA (carrying N(REKEY_SA) for the old
// SPI). When true it creates a fresh Child SA to replace one the peer already
// DELETEd (no N(REKEY_SA): the old SPI is gone, so a strict responder would
// answer CHILD_SA_NOT_FOUND — RFC 7296 §1.3.1's "create a new Child SA").
func (s *Session) initiateChildRekey(ctx context.Context, reestablish bool) error {
	if s.child == nil {
		return errors.New("session: no Child SA to rekey")
	}
	newSPI, err := randBytes(4)
	if err != nil {
		return err
	}
	ni, err := randBytes(nonceLen)
	if err != nil {
		return err
	}
	// Offer per-Child PFS when enabled/learned: a fresh DH whose public goes in a
	// KE payload, with the matching group advertised in the ESP proposal.
	var dh *ikesa.DH
	if s.childPFS {
		if dh, err = ikesa.NewDH(s.childRekeyGroup()); err != nil {
			return err
		}
	}

	var inner ikemsg.Payloads
	if !reestablish {
		var oldSPI [4]byte
		binary.BigEndian.PutUint32(oldSPI[:], s.child.InitiatorSPI)
		inner = append(inner, &ikemsg.NotifyPayload{Protocol: ikemsg.ProtocolESP, Type: ikemsg.NotifyRekeySA, SPI: oldSPI[:]})
	}
	// Offer the full enabled suite table again (a rekey may migrate the Child SA
	// to a more preferred suite the server has since enabled).
	if dh != nil {
		inner = append(inner, &ikemsg.SAPayload{Proposals: buildESPProposals(newSPI, s.enabledESPSuites(), dh.Group)})
	} else {
		inner = append(inner, &ikemsg.SAPayload{Proposals: buildESPProposals(newSPI, s.enabledESPSuites())})
	}
	inner = append(inner, &ikemsg.NoncePayload{Data: ni})
	if dh != nil {
		inner = append(inner, &ikemsg.KEPayload{Group: dh.Group, Data: dh.Public})
	}
	appendTrafficSelectors(&inner, s.cfg.RequestIPv6)

	msgID := s.messageID
	raw, err := s.encodeSK(ikemsg.ExchangeCreateChildSA, ikeRoleBit(s.ikeSA.Role), msgID, inner)
	if err != nil {
		return err
	}
	s.messageID++
	s.pending = &pendingExchange{
		kind: exChildRekey, msgID: msgID, raw: raw, attempts: 1,
		nextRetransmit: time.Now().Add(s.retransmitBase()),
		child: &childRekeyCtx{
			newInSPI:    binary.BigEndian.Uint32(newSPI),
			oldInSPI:    s.child.InitiatorSPI,
			ni:          ni,
			reestablish: reestablish,
			dh:          dh,
		},
	}
	s.log.Debug("initiating Child SA rekey", "newInSPI", binary.BigEndian.Uint32(newSPI), "reestablish", reestablish, "pfs", dh != nil)
	return s.sendDatagram(ctx, raw)
}

// childRekeyGroup picks the DH group for a PFS Child SA rekey we initiate: the
// group learned from a server-initiated PFS rekey if any, otherwise the group
// negotiated for the IKE SA, falling back to our most-preferred group for the
// Config.ChildSAPFS cold-start before IKE_SA_INIT has run.
func (s *Session) childRekeyGroup() uint16 {
	if s.childPFSGroup != 0 {
		return s.childPFSGroup
	}
	if s.ikeDHGroup != 0 {
		return s.ikeDHGroup
	}
	return preferredDHGroups[0]
}

// completeChildRekey finishes a Child SA rekey we initiated: derive keys and
// install the new SA. For a normal rekey it then DELETEs the old SA; for a
// re-establishment (the peer already DELETEd the old SA) it skips the DELETE.
// Either way InstallChildSA carries the old inbound SPI so the data plane
// grace-removes it after childSAGrace rather than dropping it eagerly.
func (s *Session) completeChildRekey(ctx context.Context, inner ikemsg.Payloads, p *pendingExchange) error {
	prop, suite, nr, ke, err := s.childRekeyResponse(inner)
	if err != nil {
		return err
	}
	respSPI := binary.BigEndian.Uint32(prop.SPI)
	// We initiated this exchange → Ni is ours, Nr the responder's; our outbound is
	// the initiator→responder direction.
	var keys ikesa.ChildKeys
	switch {
	case p.child.dh != nil && ke != nil:
		// PFS: fold the new DH shared secret (from the responder's KE) into KEYMAT
		// (RFC 7296 §2.17). The responder must answer in the group we offered;
		// DH.Shared rejects a wrong-length public.
		if ke.Group != p.child.dh.Group {
			return fmt.Errorf("session: Child SA rekey response KE group %d != offered group %d", ke.Group, p.child.dh.Group)
		}
		shared, derr := p.child.dh.Shared(ke.Data)
		if derr != nil {
			return fmt.Errorf("session: Child SA rekey DH: %w", derr)
		}
		keys = s.ikeSA.DeriveChildKeysPFS(shared, p.child.ni, nr, suite.encrKeyLen, suite.integKeyLen)
	case ke != nil:
		// We did not offer PFS but the responder returned a KE — it cannot add a DH
		// exchange we never requested (RFC 7296 §2.17) and we hold no private to
		// match it. Reject rather than install mismatched keys.
		return errors.New("session: Child SA rekey response carried an unsolicited KE payload")
	default:
		// Non-PFS: either we never offered PFS, or we offered it and the responder
		// narrowed the DH group away (no KE in the response) — RFC 7296 permits a
		// non-PFS Child SA here, so fall back instead of failing the rekey. But if we
		// offered PFS and the responder's selected proposal still carries a DH-group
		// transform yet omitted the KE, that is contradictory: it cannot key a PFS SA
		// without exchanging a KE, so installing non-PFS keys here would silently
		// desync KEYMAT and black-hole the Child SA. Reject instead.
		if p.child.dh != nil && selectedDHGroup(prop) != 0 {
			return errors.New("session: Child SA rekey response selected a DH group but omitted the KE payload")
		}
		keys = s.ikeSA.DeriveChildKeys(p.child.ni, nr, suite.encrKeyLen, suite.integKeyLen)
	}
	s.dataPlane.InstallChildSA(ChildSAUpdate{
		NewInSPI: p.child.newInSPI, NewOutSPI: respSPI, OldInSPI: p.child.oldInSPI,
		Suite:   suite.id,
		OutEncr: keys.EncrIR, OutInteg: keys.IntegIR,
		InEncr: keys.EncrRI, InInteg: keys.IntegRI,
	})
	s.child = &ChildSA{InitiatorSPI: p.child.newInSPI, ResponderSPI: respSPI, Suite: suite.id, Keys: keys}
	s.childInstalledAt = time.Now()
	// A peer DELETE of the SA this rekey just replaced may have queued a
	// re-establishment while the exchange was in flight (window size 1). The
	// fresh SA installed above makes that queued attempt stale — running it
	// would discard the new SA for a redundant third generation — so drop it.
	// Failure paths return before this point and keep the flag set: if the
	// peer instead rejected the rekey (it already DELETEd the old SA), the
	// queued re-establishment is the recovery.
	s.childReestablish = false
	s.nextChildReestablish = time.Time{}
	if p.child.reestablish {
		return nil // the peer already DELETEd the old SA; nothing to DELETE
	}
	// Skip the DELETE when a random new inbound SPI collided with the old one:
	// deleting oldInSPI would tell the peer to drop the SA we just installed (the
	// data plane already skips grace-removal for this case in InstallChildSA).
	if p.child.oldInSPI == p.child.newInSPI {
		return nil
	}
	return s.sendChildDelete(ctx, p.child.oldInSPI)
}

// handleChildRekeyRequest answers a server-initiated Child SA rekey. viaOld
// reports whether the request arrived under the superseded IKE SA (rekey grace
// window), selecting the matching responder-dedup slot.
func (s *Session) handleChildRekeyRequest(ctx context.Context, hdr *ikemsg.Message, inner ikemsg.Payloads, dec *ikeCtx, viaOld bool) error {
	if s.child == nil {
		// Answer (and cache for retransmits) instead of silently dropping, so the peer
		// stops retransmitting rather than looping to its own exchange timeout.
		s.sendNotifyResponse(ctx, dec, hdr.MessageID, viaOld, ikemsg.ProtocolESP, ikemsg.NotifyChildSANotFound, nil, "child rekey: no Child SA")
		return errors.New("session: rekey request but no Child SA")
	}
	saP, ni, ke, reqTSi, reqTSr, err := childRekeyRequestPayloads(inner)
	if err != nil {
		s.sendNotifyResponse(ctx, dec, hdr.MessageID, viaOld, ikemsg.ProtocolESP, ikemsg.NotifyNoProposalChosen, nil, "child rekey: no proposal chosen")
		return err
	}
	// A KE payload means the peer wants per-Child PFS. Honor it when the group is
	// one we run (x25519 or MODP-2048) and it is advertised by a proposal that
	// matches an enabled suite; otherwise tell the peer which group we accept
	// (RFC 7296 §1.3) — this is a clean answer, not a failure, so the peer can
	// retry with a supported group.
	var requireGroup uint16
	if ke != nil {
		if !supportedDHGroup(ke.Group) {
			s.sendInvalidKEPayload(ctx, dec, hdr.MessageID, viaOld)
			s.log.Debug("declined Child PFS rekey: unsupported KE group", "group", ke.Group)
			return nil
		}
		requireGroup = ke.Group
	}
	// Pick our most-preferred enabled suite among the offered proposals. With a
	// KE present the matched proposal must also advertise the KE group: the DH
	// exchange may only run against a proposal that offered it, and the group may
	// be spread across only some of the peer's proposals.
	prop, suite, ok := selectESPProposal(saP, s.enabledESPSuites(), requireGroup)
	if !ok {
		if requireGroup != 0 {
			if _, _, okSansGroup := selectESPProposal(saP, s.enabledESPSuites(), 0); okSansGroup {
				// A suite matches, but no matching proposal advertises the KE group —
				// answer with the group we accept so the peer can retry.
				s.sendInvalidKEPayload(ctx, dec, hdr.MessageID, viaOld)
				s.log.Debug("declined Child PFS rekey: KE group not offered by a matching proposal", "group", requireGroup)
				return nil
			}
		}
		s.sendNotifyResponse(ctx, dec, hdr.MessageID, viaOld, ikemsg.ProtocolESP, ikemsg.NotifyNoProposalChosen, nil, "child rekey: no proposal chosen")
		return fmt.Errorf("session: no offered ESP proposal matches our suites (%s)", describeProposals(saP))
	}
	serverNewSPI := binary.BigEndian.Uint32(prop.SPI)

	var dh *ikesa.DH
	var pfsShared []byte
	if ke != nil {
		if dh, err = ikesa.NewDH(ke.Group); err != nil {
			return err
		}
		if pfsShared, err = dh.Shared(ke.Data); err != nil {
			return fmt.Errorf("session: Child SA rekey DH: %w", err)
		}
	}

	newSPI, err := randBytes(4)
	if err != nil {
		return err
	}
	nr, err := randBytes(nonceLen)
	if err != nil {
		return err
	}

	var resp ikemsg.Payloads
	// Echo the selected proposal number, narrowed to the SELECTED suite (RFC
	// 7296 §2.7: the responder narrows the offer to one transform per type) —
	// not a rebuild of some fixed suite, which would desync KEYMAT whenever the
	// peer's preferred offer differs. A PFS rekey keeps the DH-group transform
	// and answers with our own KE payload.
	if dh != nil {
		resp = append(resp, &ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildESPProposalForSuite(prop.Number, suite, newSPI, dh.Group)}})
	} else {
		resp = append(resp, &ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildESPProposalForSuite(prop.Number, suite, newSPI)}})
	}
	resp = append(resp, &ikemsg.NoncePayload{Data: nr})
	if dh != nil {
		resp = append(resp, &ikemsg.KEPayload{Group: dh.Group, Data: dh.Public})
	}
	// Echo the initiator's offered selectors (a valid subset of themselves, RFC
	// 7296 §2.9 responder narrowing) so a strict/split-tunnel server accepts the
	// reply. Fall back to our full-tunnel selectors only if the request omitted TS.
	if len(reqTSi) > 0 && len(reqTSr) > 0 {
		resp = append(resp,
			&ikemsg.TSiPayload{Selectors: reqTSi},
			&ikemsg.TSrPayload{Selectors: reqTSr},
		)
	} else {
		appendTrafficSelectors(&resp, s.cfg.RequestIPv6)
	}
	raw, err := encodeSKWith(dec.sa, dec.spii, dec.spir,
		ikemsg.ExchangeCreateChildSA, ikeRoleBit(dec.sa.Role)|ikemsg.FlagResponse, hdr.MessageID, resp)
	if err != nil {
		return err
	}

	// Derive keys and install the new inbound SA BEFORE caching/sending the
	// response. The server initiated → Ni is the server's nonce; our outbound is
	// the responder→initiator direction. The CREATE_CHILD_SA runs under the SA
	// that carried it (dec.sa, which may be the superseded SA during the rekey
	// grace window), so KEYMAT uses that SA's SK_d (RFC 7296 §2.17). PFS folds in
	// the new DH shared secret and latches childPFS so our own subsequent
	// rekeys/re-establishments offer it. Installing before the send means a send
	// failure cannot leave the peer able to complete the rekey (it retransmits, we
	// resend the cached response) while our inbound SA is missing; the driver is
	// single-goroutine, so no retransmit is reprocessed before we cache below.
	var keys ikesa.ChildKeys
	if pfsShared != nil {
		keys = dec.sa.DeriveChildKeysPFS(pfsShared, ni, nr, suite.encrKeyLen, suite.integKeyLen)
		// Latch PFS and the group the server required, so our own subsequent
		// rekeys/re-establishments offer the same group.
		s.childPFS = true
		s.childPFSGroup = dh.Group
	} else {
		keys = dec.sa.DeriveChildKeys(ni, nr, suite.encrKeyLen, suite.integKeyLen)
	}
	oldInSPI := s.child.InitiatorSPI
	s.dataPlane.InstallChildSA(ChildSAUpdate{
		NewInSPI: binary.BigEndian.Uint32(newSPI), NewOutSPI: serverNewSPI, OldInSPI: oldInSPI,
		Suite:   suite.id,
		OutEncr: keys.EncrRI, OutInteg: keys.IntegRI,
		InEncr: keys.EncrIR, InInteg: keys.IntegIR,
	})
	s.child = &ChildSA{InitiatorSPI: binary.BigEndian.Uint32(newSPI), ResponderSPI: serverNewSPI, Suite: suite.id, Keys: keys}
	s.childInstalledAt = time.Now()
	// A server-driven install resets the soft lifetime; push our own next-Child-
	// rekey deadline out from the new install time (otherwise it stays armed on the
	// old time and we rekey again immediately).
	s.nextChildRekey = jitteredDeadline(s.childInstalledAt, s.cfg.RekeyLifetime)

	// Cache before send so a retransmit resends this exact response instead of
	// reprocessing (which would install a second SA).
	s.recordPeerResponse(viaOld, hdr.MessageID, raw)
	if err := s.sendDatagram(ctx, raw); err != nil {
		return err
	}
	s.log.Debug("answered server Child SA rekey",
		"newInSPI", binary.BigEndian.Uint32(newSPI), "suite", suite.name(), "pfs", pfsShared != nil)
	return nil
}

// sendInvalidKEPayload answers a server CREATE_CHILD_SA (Child or IKE rekey)
// whose KE used a DH group we cannot run with N(INVALID_KE_PAYLOAD) carrying our
// most-preferred supported group, so the peer can retry with it (RFC 7296 §1.3 /
// §2.7). The response is cached for retransmit dedup like any other server-request
// answer.
func (s *Session) sendInvalidKEPayload(ctx context.Context, dec *ikeCtx, msgID uint32, viaOld bool) {
	var group [2]byte
	binary.BigEndian.PutUint16(group[:], preferredDHGroups[0])
	s.sendNotifyResponse(ctx, dec, msgID, viaOld, ikemsg.ProtocolNone, ikemsg.NotifyInvalidKEPayload, group[:], "INVALID_KE_PAYLOAD")
}

// sendChildDelete sends INFORMATIONAL{ Delete(ESP, inSPI) } for the old Child SA.
func (s *Session) sendChildDelete(ctx context.Context, inSPI uint32) error {
	var spi [4]byte
	binary.BigEndian.PutUint32(spi[:], inSPI)
	inner := ikemsg.Payloads{&ikemsg.DeletePayload{Protocol: ikemsg.ProtocolESP, SPIs: [][]byte{spi[:]}}}
	msgID := s.messageID
	raw, err := s.encodeSK(ikemsg.ExchangeInformational, ikeRoleBit(s.ikeSA.Role), msgID, inner)
	if err != nil {
		return err
	}
	s.messageID++
	s.pending = &pendingExchange{
		kind: exDelete, msgID: msgID, raw: raw, attempts: 1,
		nextRetransmit: time.Now().Add(s.retransmitBase()),
	}
	return s.sendDatagram(ctx, raw)
}

// childRekeyResponse decodes the responder's answer to a Child SA rekey we
// initiated. The SA payload must be a strict SELECTION of one enabled suite
// (exactly one ENCR transform, unambiguous integrity — the same semantics as
// the IKE_AUTH selection): with several suites offered, a response echoing
// multiple alternatives would leave the KEYMAT lengths undefined.
func (s *Session) childRekeyResponse(inner ikemsg.Payloads) (prop ikemsg.Proposal, suite espSuite, nr []byte, ke *ikemsg.KEPayload, err error) {
	var saP *ikemsg.SAPayload
	for _, p := range inner {
		switch v := p.(type) {
		case *ikemsg.SAPayload:
			saP = v
		case *ikemsg.NoncePayload:
			nr = append([]byte(nil), v.Data...)
		case *ikemsg.KEPayload:
			ke = v
		case *ikemsg.NotifyPayload:
			if e := notifyError(v); e != nil {
				return ikemsg.Proposal{}, espSuite{}, nil, nil, e
			}
		}
	}
	if saP == nil {
		return ikemsg.Proposal{}, espSuite{}, nil, nil, errors.New("session: Child SA rekey response missing SA payload")
	}
	if len(saP.Proposals) == 0 {
		return ikemsg.Proposal{}, espSuite{}, nil, nil, errors.New("session: Child SA rekey response carries no proposal")
	}
	prop = saP.Proposals[0]
	suite, ok := selectedESPSuite(prop, s.enabledESPSuites())
	if !ok || len(prop.SPI) != 4 {
		return ikemsg.Proposal{}, espSuite{}, nil, nil, fmt.Errorf("session: Child SA rekey response selected an unsupported or ambiguous proposal (%s)", describeProposals(saP))
	}
	if len(nr) == 0 {
		return ikemsg.Proposal{}, espSuite{}, nil, nil, errors.New("session: Child SA rekey response missing Nr")
	}
	return prop, suite, nr, ke, nil
}

// childRekeyRequestPayloads extracts the payloads of a server-initiated Child
// SA rekey request. Proposal/suite selection is left to the caller, which
// re-selects with the KE group as a constraint when the peer requested PFS.
func childRekeyRequestPayloads(inner ikemsg.Payloads) (saP *ikemsg.SAPayload, ni []byte, ke *ikemsg.KEPayload, tsi, tsr []ikemsg.TrafficSelector, err error) {
	for _, p := range inner {
		switch v := p.(type) {
		case *ikemsg.SAPayload:
			saP = v
		case *ikemsg.NoncePayload:
			ni = append([]byte(nil), v.Data...)
		case *ikemsg.KEPayload:
			// A KE payload means the peer wants PFS (a per-Child DH exchange). It is
			// returned to the caller, which performs the DH and folds the shared
			// secret into KEYMAT; group validation happens there so an unsupported
			// group can be answered with INVALID_KE_PAYLOAD.
			ke = v
		case *ikemsg.TSiPayload:
			// The initiator's offered selectors; the responder must narrow its reply
			// to a subset (RFC 7296 §2.9), so echo these back rather than re-asserting
			// our own full range, which a strict/split-tunnel peer would reject.
			tsi = v.Selectors
		case *ikemsg.TSrPayload:
			tsr = v.Selectors
		}
	}
	if saP == nil {
		return nil, nil, nil, nil, nil, errors.New("session: Child SA rekey request missing SA payload")
	}
	if len(ni) == 0 {
		return nil, nil, nil, nil, nil, errors.New("session: Child SA rekey request missing Ni")
	}
	return saP, ni, ke, tsi, tsr, nil
}

// --- IKE SA rekey ---

// initiateIKERekey starts a CREATE_CHILD_SA exchange that rekeys the IKE SA.
func (s *Session) initiateIKERekey(ctx context.Context) error {
	newSPIi, err := randUint64()
	if err != nil {
		return err
	}
	// An IKE-SA rekey reuses the group negotiated at IKE_SA_INIT; no INVALID_KE
	// retry is needed because the group is already agreed.
	dh, err := ikesa.NewDH(s.ikeDHGroup)
	if err != nil {
		return err
	}
	ni, err := randBytes(nonceLen)
	if err != nil {
		return err
	}

	var spi [8]byte
	binary.BigEndian.PutUint64(spi[:], newSPIi)
	inner := ikemsg.Payloads{
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildIKEProposalSPI(1, spi[:], dh.Group)}},
		&ikemsg.NoncePayload{Data: ni},
		&ikemsg.KEPayload{Group: dh.Group, Data: dh.Public},
	}

	msgID := s.messageID
	raw, err := s.encodeSK(ikemsg.ExchangeCreateChildSA, ikeRoleBit(s.ikeSA.Role), msgID, inner)
	if err != nil {
		return err
	}
	s.messageID++
	s.pending = &pendingExchange{
		kind: exIKERekey, msgID: msgID, raw: raw, attempts: 1,
		nextRetransmit: time.Now().Add(s.retransmitBase()),
		ike:            &ikeRekeyCtx{newSPIi: newSPIi, ni: ni, dh: dh},
	}
	s.log.Debug("initiating IKE SA rekey")
	return s.sendDatagram(ctx, raw)
}

// completeIKERekey finishes an IKE SA rekey we initiated: derive the new SA,
// DELETE the old SA under the old SA, then cut over.
func (s *Session) completeIKERekey(ctx context.Context, inner ikemsg.Payloads, p *pendingExchange) error {
	prop, nr, ker, err := ikeRekeyPayloads(inner)
	if err != nil {
		return err
	}
	newSPIr := binary.BigEndian.Uint64(prop.SPI)
	// The responder must answer in the group we offered (the established IKE group).
	if ker.Group != p.ike.dh.Group {
		return fmt.Errorf("session: IKE rekey response KE group %d != offered group %d", ker.Group, p.ike.dh.Group)
	}
	shared, err := p.ike.dh.Shared(ker.Data)
	if err != nil {
		return fmt.Errorf("session: IKE rekey DH: %w", err)
	}
	newIKE, err := ikesa.DeriveRekeyIKE(s.ikeSA.SKd, ikesa.Initiator, p.ike.newSPIi, newSPIr, p.ike.ni, nr, shared)
	if err != nil {
		return err
	}
	// DELETE the old IKE SA under the OLD SA (still current), then swap.
	if err := s.sendIKEDeleteUnderCurrent(ctx); err != nil {
		s.log.Debug("IKE rekey: old-SA DELETE failed", "err", err)
	}
	s.swapIKE(newIKE, p.ike.newSPIi, newSPIr)
	s.log.Info("IKE SA rekeyed (initiator)")
	return nil
}

// handleIKERekeyRequest answers a server-initiated IKE SA rekey. viaOld reports
// whether the request arrived under the superseded IKE SA (rekey grace window),
// selecting the matching responder-dedup slot.
func (s *Session) handleIKERekeyRequest(ctx context.Context, hdr *ikemsg.Message, inner ikemsg.Payloads, dec *ikeCtx, viaOld bool) error {
	prop, ni, kei, err := ikeRekeyPayloads(inner)
	if err != nil {
		// Cache an error response so retransmits are answered, not reprocessed.
		s.sendNotifyResponse(ctx, dec, hdr.MessageID, viaOld, ikemsg.ProtocolNone, ikemsg.NotifyNoProposalChosen, nil, "IKE rekey: no proposal chosen")
		return err
	}
	// Honor the peer's KE group when we run it and the proposal advertises it;
	// otherwise tell it which group we accept (RFC 7296 §1.3) so it can retry.
	group := kei.Group
	if !supportedDHGroup(group) || !proposalHasDHGroup(prop, group) {
		s.sendInvalidKEPayload(ctx, dec, hdr.MessageID, viaOld)
		s.log.Debug("declined server IKE rekey: unsupported KE group", "group", group)
		return nil
	}
	serverNewSPIi := binary.BigEndian.Uint64(prop.SPI)
	newSPIr, err := randUint64()
	if err != nil {
		return err
	}
	dh, err := ikesa.NewDH(group)
	if err != nil {
		return err
	}
	nr, err := randBytes(nonceLen)
	if err != nil {
		return err
	}
	shared, err := dh.Shared(kei.Data)
	if err != nil {
		return fmt.Errorf("session: IKE rekey DH: %w", err)
	}
	// Key the new IKE SA from the SK_d of the SA that carried this request (dec.sa,
	// which may be the superseded SA during the rekey grace window) per RFC 7296
	// §2.18 — not s.ikeSA.SKd, which after a just-completed cutover is a different
	// SA's SK_d and would diverge from the peer when the request arrives viaOld.
	// Mirrors the Child-rekey path (which derives from dec.sa) and the response
	// framing below, which already encodes under dec.sa.
	newIKE, err := ikesa.DeriveRekeyIKE(dec.sa.SKd, ikesa.Responder, serverNewSPIi, newSPIr, ni, nr, shared)
	if err != nil {
		return err
	}

	var spi [8]byte
	binary.BigEndian.PutUint64(spi[:], newSPIr)
	resp := ikemsg.Payloads{
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildIKEProposalSPI(prop.Number, spi[:], dh.Group)}},
		&ikemsg.NoncePayload{Data: nr},
		&ikemsg.KEPayload{Group: dh.Group, Data: dh.Public},
	}
	raw, err := encodeSKWith(dec.sa, dec.spii, dec.spir,
		ikemsg.ExchangeCreateChildSA, ikeRoleBit(dec.sa.Role)|ikemsg.FlagResponse, hdr.MessageID, resp)
	if err != nil {
		return err
	}
	// Cache before swapIKE (which migrates s.peer → s.oldPeer) so a retransmit
	// of this request, arriving under the old SA during grace, resends this
	// response instead of deriving a third IKE SA and corrupting the cutover.
	s.recordPeerResponse(viaOld, hdr.MessageID, raw)
	if err := s.sendDatagram(ctx, raw); err != nil {
		return err
	}
	// Cut over to the new SA; the server will DELETE the old SA under the old
	// SA, which we ack via the grace-decode path.
	s.swapIKE(newIKE, serverNewSPIi, newSPIr)
	s.log.Info("IKE SA rekeyed (responder)")
	return nil
}

// sendIKEDeleteUnderCurrent sends INFORMATIONAL{ Delete(IKE, SPISize=0) } under
// the current SA (which, at call time, is the one being superseded) and records
// it for retransmit under the old SA until acked.
func (s *Session) sendIKEDeleteUnderCurrent(ctx context.Context) error {
	inner := ikemsg.Payloads{&ikemsg.DeletePayload{Protocol: ikemsg.ProtocolIKE}}
	msgID := s.messageID
	raw, err := s.encodeSK(ikemsg.ExchangeInformational, ikeRoleBit(s.ikeSA.Role), msgID, inner)
	if err != nil {
		return err
	}
	s.messageID++
	// The bytes are frozen under the old SA, so resending them verbatim during
	// the grace window is correct regardless of the post-swap current SA.
	s.oldIKEDelete = &pendingExchange{
		kind: exDelete, msgID: msgID, raw: raw, attempts: 1,
		nextRetransmit: time.Now().Add(s.retransmitBase()),
	}
	return s.sendDatagram(ctx, raw)
}

// swapIKE installs newIKE as current, retiring the old SA into the grace-decode
// slot and resetting the message-ID counter.
func (s *Session) swapIKE(newIKE *ikesa.IKESA, spii, spir uint64) {
	s.oldIKE = &ikeCtx{sa: s.ikeSA, spii: s.initiatorSPI, spir: s.responderSPI}
	s.oldIKEUntil = time.Now().Add(ikeRekeyGrace)
	// Migrate responder-dedup state so a retransmit of the rekey request that
	// triggered this swap (decoded under the old SA) resends the cached response.
	s.oldPeer = s.peer
	s.peer = peerDedup{}
	s.ikeSA = newIKE
	s.initiatorSPI = spii
	s.responderSPI = spir
	s.messageID = 0
	s.ikeInstalledAt = time.Now()
	// The cutover resets the IKE SA soft lifetime; push the next-IKE-rekey
	// deadline out from the new install time. This is the single arming point for
	// the IKE-rekey deadline — both the initiator path (completeMatchingRekey) and
	// the server-initiated path reach swapIKE, so neither re-arms it separately.
	s.nextIKERekey = jitteredDeadline(s.ikeInstalledAt, s.ikeRekeyLifetime())
	s.pending = nil // any old-SA pending is moot under the new SA
}

// ikeRekeyPayloads extracts the narrowed IKE proposal, the nonce, and the KE
// payload (returned whole so callers can read its DH group) from a CREATE_CHILD_SA
// IKE-rekey request or response.
func ikeRekeyPayloads(inner ikemsg.Payloads) (prop ikemsg.Proposal, nonce []byte, ke *ikemsg.KEPayload, err error) {
	var sa *ikemsg.SAPayload
	for _, p := range inner {
		switch v := p.(type) {
		case *ikemsg.SAPayload:
			sa = v
		case *ikemsg.NoncePayload:
			nonce = append([]byte(nil), v.Data...)
		case *ikemsg.KEPayload:
			ke = v
		case *ikemsg.NotifyPayload:
			if e := notifyError(v); e != nil {
				return ikemsg.Proposal{}, nil, nil, e
			}
		}
	}
	if sa == nil {
		return ikemsg.Proposal{}, nil, nil, errors.New("session: IKE rekey missing SA payload")
	}
	prop, ok := selectIKEProposal(sa)
	if !ok {
		return ikemsg.Proposal{}, nil, nil, fmt.Errorf("session: no offered IKE proposal matches our suite (%s)", describeProposals(sa))
	}
	if len(nonce) == 0 || ke == nil || len(ke.Data) == 0 {
		return ikemsg.Proposal{}, nil, nil, errors.New("session: IKE rekey missing Nonce/KE")
	}
	return prop, nonce, ke, nil
}

// isIKERekey reports whether a CREATE_CHILD_SA payload set rekeys the IKE SA (an
// IKE-protocol proposal with a KE payload and no traffic selectors), as opposed
// to a Child SA (ESP proposal, with TS).
func isIKERekey(inner ikemsg.Payloads) bool {
	for _, p := range inner {
		if sa, ok := p.(*ikemsg.SAPayload); ok {
			if len(sa.Proposals) > 0 && sa.Proposals[0].Protocol == ikemsg.ProtocolIKE {
				return true
			}
		}
	}
	return false
}
