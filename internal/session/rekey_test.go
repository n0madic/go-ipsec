package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
)

type fakeDataPlane struct {
	updates    []ChildSAUpdate
	lastInData time.Time
	volume     uint32
}

func (f *fakeDataPlane) InstallChildSA(u ChildSAUpdate) { f.updates = append(f.updates, u) }
func (f *fakeDataPlane) LastDataInbound() time.Time     { return f.lastInData }
func (f *fakeDataPlane) ChildSAVolume() uint32          { return f.volume }

func recvCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 2*time.Second)
}

// serverChildRekey builds a server-initiated (non-PFS) Child SA rekey request:
// REKEY_SA(oldSPI) + an ESP proposal carrying newSPI + Ni + full-tunnel TS.
func serverChildRekey(t *testing.T, respS *Session, msgID uint32, oldSPI, newSPI, ni []byte) []byte {
	t.Helper()
	inner := ikemsg.Payloads{
		&ikemsg.NotifyPayload{Protocol: ikemsg.ProtocolESP, Type: ikemsg.NotifyRekeySA, SPI: oldSPI},
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildESPProposal(1, newSPI)}},
		&ikemsg.NoncePayload{Data: ni},
	}
	appendTrafficSelectors(&inner, false)
	raw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeCreateChildSA, 0, msgID, inner)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// serverIKERekey builds a server-initiated IKE SA rekey request carrying an
// 8-byte SPI proposal in the given DH group + Ni + that group's KE.
func serverIKERekey(t *testing.T, respS *Session, msgID uint32, spi uint64, group uint16, dhPub, ni []byte) []byte {
	t.Helper()
	var spiBuf [8]byte
	binary.BigEndian.PutUint64(spiBuf[:], spi)
	inner := ikemsg.Payloads{
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildIKEProposalSPI(1, spiBuf[:], group)}},
		&ikemsg.NoncePayload{Data: ni},
		&ikemsg.KEPayload{Group: group, Data: dhPub},
	}
	raw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeCreateChildSA, 0, msgID, inner)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestChildRekeyInitiatorRoundTrip drives a full Child SA rekey that we initiate
// against a cooperating responder and checks both ends derive consistent keys.
func TestChildRekeyInitiatorRoundTrip(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initConn := initS.conn
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	respS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP, respDP := &fakeDataPlane{}, &fakeDataPlane{}
	initS.SetDataPlane(initDP)
	respS.SetDataPlane(respDP)

	ctx, cancel := recvCtx(t)
	defer cancel()

	// Initiator → request.
	if err := initS.initiateChildRekey(ctx, false); err != nil {
		t.Fatal(err)
	}
	if initS.pending == nil || initS.pending.kind != exChildRekey {
		t.Fatal("pending child rekey not recorded")
	}

	// Responder reads, derives, responds.
	reqRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hdr, inner, dec, err := respS.decodeIKE(reqRaw)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Exchange != ikemsg.ExchangeCreateChildSA || isIKERekey(inner) {
		t.Fatal("not a Child SA rekey request")
	}
	if err := respS.handleChildRekeyRequest(ctx, hdr, inner, dec, false); err != nil {
		t.Fatal(err)
	}

	// Initiator reads response, completes.
	respRaw, err := initConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if exit := initS.handleInbound(ctx, respRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if initS.pending == nil || initS.pending.kind != exDelete {
		t.Fatal("expected a pending Delete after rekey completion")
	}

	// Both installed exactly one SA, with mirror-consistent keys.
	if len(initDP.updates) != 1 || len(respDP.updates) != 1 {
		t.Fatalf("installs: init=%d resp=%d", len(initDP.updates), len(respDP.updates))
	}
	iu, ru := initDP.updates[0], respDP.updates[0]
	if !bytes.Equal(iu.OutEncr, ru.InEncr) || !bytes.Equal(iu.InEncr, ru.OutEncr) ||
		!bytes.Equal(iu.OutInteg, ru.InInteg) || !bytes.Equal(iu.InInteg, ru.OutInteg) {
		t.Fatal("rekeyed Child SA keys are not mirror-consistent")
	}
	if iu.OldInSPI != 0x1111 {
		t.Fatalf("OldInSPI = %08x, want 1111", iu.OldInSPI)
	}
	if initS.child.InitiatorSPI != iu.NewInSPI || initS.child.ResponderSPI != iu.NewOutSPI {
		t.Fatal("session child SA not updated to new SPIs")
	}

	// The old Child SA is DELETEd.
	delRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, delInner, _, err := respS.decodeIKE(delRaw)
	if err != nil {
		t.Fatal(err)
	}
	var sawESPDelete bool
	for _, p := range delInner {
		if d, ok := p.(*ikemsg.DeletePayload); ok && d.Protocol == ikemsg.ProtocolESP {
			sawESPDelete = true
		}
	}
	if !sawESPDelete {
		t.Fatal("no ESP Delete for the old Child SA")
	}
}

// TestChildRekeyResponder hand-crafts a server-initiated Child SA rekey and
// checks we respond and install with the correct (responder-side) key
// orientation.
func TestChildRekeyResponder(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)

	// Build a server REKEY request (server is the exchange initiator, msgID 5).
	serverNi := bytes.Repeat([]byte{0xC1}, nonceLen)
	serverNewSPI := []byte{0xAB, 0xCD, 0xEF, 0x01}
	reqRaw := serverChildRekey(t, respS, 5, []byte{0, 0, 0x22, 0x22}, serverNewSPI, serverNi)

	ctx, cancel := recvCtx(t)
	defer cancel()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}

	// We must have installed and replied.
	if len(initDP.updates) != 1 {
		t.Fatalf("expected 1 install, got %d", len(initDP.updates))
	}
	u := initDP.updates[0]
	if u.NewOutSPI != 0xABCDEF01 || u.OldInSPI != 0x1111 {
		t.Fatalf("install SPIs wrong: out=%08x old=%08x", u.NewOutSPI, u.OldInSPI)
	}

	// Read our response (sent to the peer conn) and extract our Nr / new SPI to
	// recompute the expected keys (server-initiated → our outbound = R→I).
	respRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, respInner, _, err := respS.decodeIKE(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	var ourNr []byte
	var ourNewSPI uint32
	for _, p := range respInner {
		switch v := p.(type) {
		case *ikemsg.NoncePayload:
			ourNr = v.Data
		case *ikemsg.SAPayload:
			ourNewSPI = beUint32(v.Proposals[0].SPI)
		}
	}
	if ourNewSPI != u.NewInSPI {
		t.Fatal("response SPI does not match installed inbound SPI")
	}
	want := initS.ikeSA.DeriveChildKeys(serverNi, ourNr, espEncrKeyLen, espIntegKeyLen)
	if !bytes.Equal(u.OutEncr, want.EncrRI) || !bytes.Equal(u.InEncr, want.EncrIR) {
		t.Fatal("responder-side key orientation incorrect")
	}
}

// TestChildRekeyResponderEchoesNarrowedTS is finding #8: the response to a
// server-initiated Child rekey must echo the initiator's offered traffic selectors
// (RFC 7296 §2.9 responder narrowing) rather than re-asserting full-tunnel
// 0.0.0.0/0, which a split-tunnel server would reject with TS_UNACCEPTABLE.
func TestChildRekeyResponderEchoesNarrowedTS(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initS.SetDataPlane(&fakeDataPlane{})

	narrowed := []ikemsg.TrafficSelector{{
		TSType: ikemsg.TSIPv4AddrRange, EndPort: 65535,
		StartAddr: []byte{10, 0, 0, 0}, EndAddr: []byte{10, 255, 255, 255},
	}}
	inner := ikemsg.Payloads{
		&ikemsg.NotifyPayload{Protocol: ikemsg.ProtocolESP, Type: ikemsg.NotifyRekeySA, SPI: []byte{0, 0, 0x22, 0x22}},
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildESPProposal(1, []byte{0xAB, 0xCD, 0xEF, 0x08})}},
		&ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0xC2}, nonceLen)},
		&ikemsg.TSiPayload{Selectors: narrowed},
		&ikemsg.TSrPayload{Selectors: narrowed},
	}
	reqRaw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeCreateChildSA, 0, 9, inner)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := recvCtx(t)
	defer cancel()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	respRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, respInner, _, err := respS.decodeIKE(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	var gotTSi, gotTSr []ikemsg.TrafficSelector
	for _, p := range respInner {
		switch v := p.(type) {
		case *ikemsg.TSiPayload:
			gotTSi = v.Selectors
		case *ikemsg.TSrPayload:
			gotTSr = v.Selectors
		}
	}
	checkEcho := func(name string, got []ikemsg.TrafficSelector) {
		if len(got) != 1 {
			t.Fatalf("%s: expected the 1 echoed selector, got %d", name, len(got))
		}
		if !bytes.Equal(got[0].StartAddr, []byte{10, 0, 0, 0}) || !bytes.Equal(got[0].EndAddr, []byte{10, 255, 255, 255}) {
			t.Fatalf("%s: response did not echo the narrowed selector: %+v", name, got[0])
		}
	}
	checkEcho("TSi", gotTSi)
	checkEcho("TSr", gotTSr)
}

// TestIKERekeyInitiatorRoundTrip drives a full IKE SA rekey we initiate and
// checks both ends cut over to an identical new IKE SA.
func TestIKERekeyInitiatorRoundTrip(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initConn := initS.conn
	oldInitSA := initS.ikeSA

	ctx, cancel := recvCtx(t)
	defer cancel()

	if err := initS.initiateIKERekey(ctx); err != nil {
		t.Fatal(err)
	}
	reqRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hdr, inner, dec, err := respS.decodeIKE(reqRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !isIKERekey(inner) {
		t.Fatal("expected an IKE rekey request")
	}
	if err := respS.handleIKERekeyRequest(ctx, hdr, inner, dec, false); err != nil {
		t.Fatal(err)
	}
	// Responder cut over.
	if respS.oldIKE == nil || respS.messageID != 0 {
		t.Fatal("responder did not cut over to the new IKE SA")
	}

	respRaw, err := initConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if exit := initS.handleInbound(ctx, respRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	// The initiator cut over on the rekey response: SA pointer swapped to the new
	// SA and the old SA retained for grace-period decode. (messageID stays 0 here
	// until the old-SA DELETE is later sent, so it is not asserted.)
	if initS.ikeSA == oldInitSA {
		t.Fatal("initiator did not swap the IKE SA")
	}
	if initS.oldIKE == nil {
		t.Fatal("initiator did not retain the old IKE SA for grace decode")
	}

	// The two new IKE SAs must agree: a message encoded by the initiator's new
	// SA decodes under the responder's new SA.
	probe, err := initS.encodeSKEmpty(ikemsg.ExchangeInformational, ikemsg.FlagInitiator, initS.messageID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := respS.decodeIKE(probe); err != nil {
		t.Fatalf("new IKE SAs disagree: %v", err)
	}
}

// TestIKERekeyRequestRetransmitIdempotent feeds a server-initiated IKE rekey
// request twice (the response to the first was "lost") and checks the retransmit
// does NOT re-derive/re-swap the IKE SA — it resends the cached response.
func TestIKERekeyRequestRetransmitIdempotent(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)

	dh, err := ikesa.NewDH(ikemsg.DH_MODP2048)
	if err != nil {
		t.Fatal(err)
	}
	serverNi := bytes.Repeat([]byte{0xD1}, nonceLen)
	// Server is the original responder → I bit clear; msgID 0.
	reqRaw := serverIKERekey(t, respS, 0, 0x9999, ikemsg.DH_MODP2048, dh.Public, serverNi)

	ctx, cancel := recvCtx(t)
	defer cancel()

	// First delivery: cut over to a new IKE SA, send a response.
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if initS.oldIKE == nil {
		t.Fatal("did not cut over to a new IKE SA")
	}
	newSA := initS.ikeSA
	resp1, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Retransmit the SAME request (decoded under the old SA via grace).
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown on retransmit")
	}
	if initS.ikeSA != newSA {
		t.Fatal("retransmit re-swapped the IKE SA — state corrupted")
	}
	resp2, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp1, resp2) {
		t.Fatal("retransmit produced a different response (request was reprocessed)")
	}
}

// TestSimultaneousRekeyRejected checks that a server CREATE_CHILD_SA request
// arriving while our own rekey is pending is declined with TEMPORARY_FAILURE
// instead of installing a second, redundant Child SA.
func TestSimultaneousRekeyRejected(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)

	ctx, cancel := recvCtx(t)
	defer cancel()

	// Our own Child rekey is in flight.
	if err := initS.initiateChildRekey(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := respConn.Recv(ctx); err != nil { // drain our request
		t.Fatal(err)
	}

	// Server initiates its own Child rekey concurrently (I bit clear, msgID 7).
	serverNi := bytes.Repeat([]byte{0xC2}, nonceLen)
	reqRaw := serverChildRekey(t, respS, 7, []byte{0, 0, 0x22, 0x22}, []byte{0xAB, 0xCD, 0xEF, 0x02}, serverNi)

	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	// We must NOT have installed a Child SA for the colliding request.
	if len(initDP.updates) != 0 {
		t.Fatalf("expected no install on collision, got %d", len(initDP.updates))
	}
	// The reply must be a TEMPORARY_FAILURE notify.
	raw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, respInner, _, err := respS.decodeIKE(raw)
	if err != nil {
		t.Fatal(err)
	}
	var sawTempFail bool
	for _, p := range respInner {
		if n, ok := p.(*ikemsg.NotifyPayload); ok && n.Type == ikemsg.NotifyTemporaryFailure {
			sawTempFail = true
		}
	}
	if !sawTempFail {
		t.Fatal("collision reply was not TEMPORARY_FAILURE")
	}
}

// TestResponderRoleDPDClearsInitiatorBit is finding #4: after a server-initiated
// IKE rekey our new IKE SA has Role==Responder, so everything we originate under
// it must CLEAR the I bit (RFC 7296 §3.1).
func TestResponderRoleDPDClearsInitiatorBit(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)

	dh, err := ikesa.NewDH(ikemsg.DH_MODP2048)
	if err != nil {
		t.Fatal(err)
	}
	serverNi := bytes.Repeat([]byte{0xE1}, nonceLen)
	// Server is the original responder → I bit clear; msgID 0.
	reqRaw := serverIKERekey(t, respS, 0, 0x7777, ikemsg.DH_MODP2048, dh.Public, serverNi)

	ctx, cancel := recvCtx(t)
	defer cancel()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if _, err := respConn.Recv(ctx); err != nil { // drain the rekey response
		t.Fatal(err)
	}
	if initS.ikeSA.Role != ikesa.Responder {
		t.Fatalf("expected Responder role after server IKE rekey, got %v", initS.ikeSA.Role)
	}

	// Originate a DPD probe under the new (Responder-role) SA; its I bit must be clear.
	if err := initS.initiateDPD(ctx, false); err != nil {
		t.Fatal(err)
	}
	raw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ikemsg.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Flags.IsInitiator() {
		t.Fatal("DPD originated under a Responder-role SA must clear the I bit")
	}
	if m.Flags.IsResponse() {
		t.Fatal("DPD probe must be a request (R bit clear)")
	}
}

// TestServerChildRekeyRecomputesDeadline is finding #5 (Child half): a
// server-initiated Child rekey must re-arm our own next-Child-rekey deadline from
// the new install time, else housekeeping would rekey again immediately.
func TestServerChildRekeyRecomputesDeadline(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.cfg.RekeyLifetime = time.Hour
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initS.nextChildRekey = time.Time{} // start unset
	initS.SetDataPlane(&fakeDataPlane{})

	serverNi := bytes.Repeat([]byte{0xC5}, nonceLen)
	reqRaw := serverChildRekey(t, respS, 5, []byte{0, 0, 0x22, 0x22}, []byte{0xAB, 0xCD, 0xEF, 0x05}, serverNi)

	ctx, cancel := recvCtx(t)
	defer cancel()
	before := time.Now()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if _, err := respConn.Recv(ctx); err != nil { // drain the response
		t.Fatal(err)
	}
	if initS.nextChildRekey.IsZero() {
		t.Fatal("nextChildRekey not re-armed after a server Child rekey")
	}
	// jitter floor is 0.85×lifetime, so it must be at least ~40m out.
	if initS.nextChildRekey.Before(before.Add(40 * time.Minute)) {
		t.Fatalf("nextChildRekey re-armed too early: +%v", initS.nextChildRekey.Sub(before))
	}
}

// TestServerIKERekeyRecomputesDeadline is finding #5 (IKE half): swapIKE must
// re-arm next-IKE-rekey on cutover, including the server-initiated path.
func TestServerIKERekeyRecomputesDeadline(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.cfg.IKERekeyLifetime = 4 * time.Hour
	initS.nextIKERekey = time.Time{}

	dh, err := ikesa.NewDH(ikemsg.DH_MODP2048)
	if err != nil {
		t.Fatal(err)
	}
	serverNi := bytes.Repeat([]byte{0xE5}, nonceLen)
	reqRaw := serverIKERekey(t, respS, 0, 0x8888, ikemsg.DH_MODP2048, dh.Public, serverNi)

	ctx, cancel := recvCtx(t)
	defer cancel()
	before := time.Now()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if _, err := respConn.Recv(ctx); err != nil { // drain the response
		t.Fatal(err)
	}
	if initS.nextIKERekey.IsZero() {
		t.Fatal("nextIKERekey not re-armed after a server IKE rekey")
	}
	if initS.nextIKERekey.Before(before.Add(2 * time.Hour)) {
		t.Fatalf("nextIKERekey re-armed too early: +%v", initS.nextIKERekey.Sub(before))
	}
}

// TestTemporaryFailureCachedOnRetransmit is finding #7: a colliding server rekey
// declined with TEMPORARY_FAILURE must be cached, so a retransmit resends the
// cached notify instead of being reprocessed as a fresh rekey.
func TestTemporaryFailureCachedOnRetransmit(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)

	ctx, cancel := recvCtx(t)
	defer cancel()

	// Our own Child rekey is in flight (collision precondition).
	if err := initS.initiateChildRekey(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := respConn.Recv(ctx); err != nil { // drain our request
		t.Fatal(err)
	}

	// Server initiates a colliding Child rekey (I bit clear, msgID 7).
	serverNi := bytes.Repeat([]byte{0xC7}, nonceLen)
	reqRaw := serverChildRekey(t, respS, 7, []byte{0, 0, 0x22, 0x22}, []byte{0xAB, 0xCD, 0xEF, 0x07}, serverNi)

	// First delivery: declined with TEMPORARY_FAILURE, cached in peer dedup.
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	resp1, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !initS.peer.set || initS.peer.msgID != 7 {
		t.Fatal("TEMPORARY_FAILURE response was not cached in peer dedup")
	}

	// Retransmit the same request: must resend the cached bytes, not reprocess.
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown on retransmit")
	}
	resp2, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp1, resp2) {
		t.Fatal("retransmit produced a different response (collision reprocessed)")
	}
	if len(initDP.updates) != 0 {
		t.Fatalf("collision must not install a Child SA, got %d", len(initDP.updates))
	}
}

// TestViaOldServerChildRekey is findings #8 and #9: a server Child rekey that
// arrives under the superseded IKE SA during the rekey grace window must (a)
// derive the Child keys under that carrying SA (dec.sa), not the new current SA,
// and (b) cache its response into the oldPeer dedup slot so a retransmit under
// the old SA is deduped.
func TestViaOldServerChildRekey(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)
	oldSharedSA := initS.ikeSA // respS stays on this SA throughout

	ctx, cancel := recvCtx(t)
	defer cancel()

	// 1) Server-initiated IKE rekey so initS cuts over and keeps oldSharedSA in grace.
	dh, err := ikesa.NewDH(ikemsg.DH_MODP2048)
	if err != nil {
		t.Fatal(err)
	}
	ikeRaw := serverIKERekey(t, respS, 0, 0x9090, ikemsg.DH_MODP2048, dh.Public, bytes.Repeat([]byte{0xF1}, nonceLen))
	if exit := initS.handleInbound(ctx, ikeRaw, func() {}); exit {
		t.Fatal("unexpected teardown on IKE rekey")
	}
	if _, err := respConn.Recv(ctx); err != nil { // drain the IKE rekey response
		t.Fatal(err)
	}
	if initS.oldIKE == nil || initS.oldIKE.sa != oldSharedSA {
		t.Fatal("old IKE SA not retained for grace decode")
	}

	// 2) Server Child rekey encoded under the OLD shared SA (= initS.oldIKE.sa),
	//    so initS decodes it via the grace path → viaOld=true.
	serverNi := bytes.Repeat([]byte{0xC9}, nonceLen)
	reqRaw := serverChildRekey(t, respS, 5, []byte{0, 0, 0x22, 0x22}, []byte{0xAB, 0xCD, 0xEF, 0x09}, serverNi)

	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown on via-old Child rekey")
	}
	if len(initDP.updates) != 1 {
		t.Fatalf("expected 1 install, got %d", len(initDP.updates))
	}
	// #8: cached into oldPeer (grace SA), not the current-SA peer slot.
	if !initS.oldPeer.set || initS.oldPeer.msgID != 5 {
		t.Fatal("via-old response not cached into the oldPeer dedup slot")
	}

	// Read our response (under the old SA) and recover our Nr / new SPI.
	respRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, respInner, _, err := respS.decodeIKE(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	var ourNr []byte
	for _, p := range respInner {
		if v, ok := p.(*ikemsg.NoncePayload); ok {
			ourNr = v.Data
		}
	}
	// #9: keys derive under the carrying (old) SA, NOT the new current SA.
	u := initDP.updates[0]
	wantOld := oldSharedSA.DeriveChildKeys(serverNi, ourNr, espEncrKeyLen, espIntegKeyLen)
	if !bytes.Equal(u.OutEncr, wantOld.EncrRI) || !bytes.Equal(u.InEncr, wantOld.EncrIR) {
		t.Fatal("via-old Child keys not derived under dec.sa (the old IKE SA)")
	}
	wrongNew := initS.ikeSA.DeriveChildKeys(serverNi, ourNr, espEncrKeyLen, espIntegKeyLen)
	if bytes.Equal(u.OutEncr, wrongNew.EncrRI) {
		t.Fatal("via-old Child keys wrongly derived under the new current SA")
	}

	// #8: a retransmit under the old SA is deduped (resends cached, no 2nd install).
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown on via-old retransmit")
	}
	if len(initDP.updates) != 1 {
		t.Fatalf("via-old retransmit reprocessed (installs=%d)", len(initDP.updates))
	}
}

// TestChildRekeyErrorDoesNotRearmDeadline pins finding #7: a Child rekey completion
// that errors must NOT re-arm nextChildRekey off the stale childInstalledAt (no
// install happened), so the existing retry-backoff deadline stands.
func TestChildRekeyErrorDoesNotRearmDeadline(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initS.cfg.RekeyLifetime = time.Hour
	initS.childInstalledAt = time.Now()
	initS.SetDataPlane(&fakeDataPlane{})

	ctx, cancel := recvCtx(t)
	defer cancel()

	if err := initS.initiateChildRekey(ctx, false); err != nil { // non-PFS (no KE offered)
		t.Fatal(err)
	}
	msgID := initS.pending.msgID
	if _, err := respConn.Recv(ctx); err != nil { // drain our request
		t.Fatal(err)
	}
	if !initS.nextChildRekey.IsZero() {
		t.Fatal("precondition: nextChildRekey should be unset")
	}

	// Responder answers with an UNSOLICITED KE → completeChildRekey errors.
	dh, err := ikesa.NewDH(ikemsg.DH_MODP2048)
	if err != nil {
		t.Fatal(err)
	}
	resp := ikemsg.Payloads{
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildESPProposal(1, []byte{0xAB, 0xCD, 0xEF, 0x60})}},
		&ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0xE3}, nonceLen)},
		&ikemsg.KEPayload{Group: ikemsg.DH_MODP2048, Data: dh.Public},
	}
	appendTrafficSelectors(&resp, false)
	respRaw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeCreateChildSA, ikemsg.FlagResponse, msgID, resp)
	if err != nil {
		t.Fatal(err)
	}
	if exit := initS.handleInbound(ctx, respRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if !initS.nextChildRekey.IsZero() {
		t.Fatal("nextChildRekey was re-armed despite a failed completion")
	}
}

// TestChildRekeyKEGroupVsProposalMismatch pins the proposalHasDHGroup(prop, group)
// half of the decline condition: a KE that advertises group 14 but whose ESP
// proposal carries a different DH group (here 19, ECP-256) must be declined with
// INVALID_KE_PAYLOAD — we must not run DH against a proposal that did not offer
// the group we support.
func TestChildRekeyKEGroupVsProposalMismatch(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)

	serverDH, err := ikesa.NewDH(ikemsg.DH_MODP2048)
	if err != nil {
		t.Fatal(err)
	}
	// Proposal advertises ONLY group 19, but the KE claims group 14.
	mp := buildESPProposal(1, []byte{0xAB, 0xCD, 0xEF, 0x50})
	mp.Transforms = append(mp.Transforms, ikemsg.Transform{Type: ikemsg.TransformDH, ID: 19})
	inner := ikemsg.Payloads{
		&ikemsg.NotifyPayload{Protocol: ikemsg.ProtocolESP, Type: ikemsg.NotifyRekeySA, SPI: []byte{0, 0, 0x22, 0x22}},
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{mp}},
		&ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0xD5}, nonceLen)},
		&ikemsg.KEPayload{Group: ikemsg.DH_MODP2048, Data: serverDH.Public},
	}
	appendTrafficSelectors(&inner, false)
	reqRaw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeCreateChildSA, 0, 5, inner)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := recvCtx(t)
	defer cancel()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if len(initDP.updates) != 0 {
		t.Fatalf("group mismatch must not install an SA, got %d", len(initDP.updates))
	}
	if initS.childPFS {
		t.Fatal("childPFS must not latch on a declined group mismatch")
	}
	raw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, respInner, _, err := respS.decodeIKE(raw)
	if err != nil {
		t.Fatal(err)
	}
	var sawInvalidKE bool
	for _, p := range respInner {
		if n, ok := p.(*ikemsg.NotifyPayload); ok && n.Type == ikemsg.NotifyInvalidKEPayload {
			sawInvalidKE = true
		}
	}
	if !sawInvalidKE {
		t.Fatal("KE-group/proposal mismatch not answered with INVALID_KE_PAYLOAD")
	}
}

// TestReestablishGraceRemovesOldInbound drives a peer-DELETE re-establishment to
// completion and pins the grace-removal contract: the install carries OldInSPI =
// the old inbound SPI (so the data plane grace-removes it, not eagerly), and no
// ESP DELETE is sent (the peer already removed the old SA).
func TestReestablishGraceRemovesOldInbound(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)

	ctx, cancel := recvCtx(t)
	defer cancel()

	// Server DELETEs the live Child SA → we initiate a fresh re-establishment.
	del := ikemsg.Payloads{&ikemsg.DeletePayload{Protocol: ikemsg.ProtocolESP, SPIs: [][]byte{{0, 0, 0x22, 0x22}}}}
	delRaw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeInformational, 0, 9, del)
	if err != nil {
		t.Fatal(err)
	}
	if exit := initS.handleInbound(ctx, delRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if initS.pending == nil || initS.pending.kind != exChildRekey || !initS.pending.child.reestablish {
		t.Fatal("re-establishment not initiated")
	}
	newInSPI := initS.pending.child.newInSPI
	msgID := initS.pending.msgID

	// Drain the two outbound datagrams (re-establishment CREATE_CHILD_SA + ack).
	for range 2 {
		if _, err := respConn.Recv(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// Responder answers the re-establishment (non-PFS).
	resp := ikemsg.Payloads{
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildESPProposal(1, []byte{0, 0, 0x33, 0x33})}},
		&ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0xE2}, nonceLen)},
	}
	appendTrafficSelectors(&resp, false)
	respRaw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeCreateChildSA, ikemsg.FlagResponse, msgID, resp)
	if err != nil {
		t.Fatal(err)
	}
	if exit := initS.handleInbound(ctx, respRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}

	if len(initDP.updates) != 1 {
		t.Fatalf("re-establishment did not complete: updates=%d", len(initDP.updates))
	}
	u := initDP.updates[0]
	if u.OldInSPI != 0x1111 {
		t.Fatalf("OldInSPI = %08x, want 1111 (grace removal of old inbound)", u.OldInSPI)
	}
	if u.NewInSPI != newInSPI || u.NewOutSPI != 0x3333 {
		t.Fatalf("install SPIs wrong: in=%08x out=%08x", u.NewInSPI, u.NewOutSPI)
	}
	// A re-establishment must NOT send an ESP DELETE (the peer already deleted it).
	if initS.pending != nil {
		t.Fatalf("re-establishment must not leave a pending exchange (kind=%v)", initS.pending.kind)
	}
}

// buildESPProposalMultiOption mimics a strongSwan-initiated Child-rekey offer:
// our suite PLUS extra alternatives the responder is meant to choose from — a
// second AES-128 encryption option and BOTH ESN modes (No-ESN and ESN). The
// pre-fix strict matcher rejected this offer with "invalid Child SA rekey
// request", killing the data plane (#interop). Transforms stay in canonical order.
func buildESPProposalMultiOption(number uint8, spi []byte) ikemsg.Proposal {
	return ikemsg.Proposal{
		Number: number, Protocol: ikemsg.ProtocolESP, SPI: append([]byte(nil), spi...),
		Transforms: []ikemsg.Transform{
			{Type: ikemsg.TransformEncr, ID: ikemsg.ENCR_AES_CBC, KeyLength: keyLenAES256},
			{Type: ikemsg.TransformEncr, ID: ikemsg.ENCR_AES_CBC, KeyLength: 128},
			{Type: ikemsg.TransformInteg, ID: ikemsg.AUTH_HMAC_SHA2_256_128},
			{Type: ikemsg.TransformESN, ID: ikemsg.ESN_NONE},
			{Type: ikemsg.TransformESN, ID: 1 /* ESN enabled */},
		},
	}
}

// TestServerChildRekeyMultiOptionProposal reproduces the production interop bug:
// a server-initiated Child rekey whose ESP proposal offers multiple alternative
// transforms per type must be accepted (we select our suite) and answered with a
// single narrowed proposal — not rejected as "invalid Child SA rekey request".
func TestServerChildRekeyMultiOptionProposal(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)

	serverNi := bytes.Repeat([]byte{0xCA}, nonceLen)
	inner := ikemsg.Payloads{
		&ikemsg.NotifyPayload{Protocol: ikemsg.ProtocolESP, Type: ikemsg.NotifyRekeySA, SPI: []byte{0, 0, 0x22, 0x22}},
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildESPProposalMultiOption(1, []byte{0xAB, 0xCD, 0xEF, 0x11})}},
		&ikemsg.NoncePayload{Data: serverNi},
	}
	appendTrafficSelectors(&inner, false)
	reqRaw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeCreateChildSA, 0, 5, inner)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := recvCtx(t)
	defer cancel()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if len(initDP.updates) != 1 {
		t.Fatalf("multi-option server Child rekey not accepted: installs=%d", len(initDP.updates))
	}

	respRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, respInner, _, err := respS.decodeIKE(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	var saR *ikemsg.SAPayload
	for _, p := range respInner {
		if v, ok := p.(*ikemsg.SAPayload); ok {
			saR = v
		}
	}
	if saR == nil || len(saR.Proposals) != 1 {
		t.Fatal("response missing a single narrowed SA proposal")
	}
	prop := saR.Proposals[0]
	if len(prop.ByType(ikemsg.TransformEncr)) != 1 || len(prop.ByType(ikemsg.TransformESN)) != 1 ||
		prop.ByType(ikemsg.TransformESN)[0].ID != ikemsg.ESN_NONE {
		t.Fatalf("response not narrowed to our single No-ESN suite: enc=%d esn=%d",
			len(prop.ByType(ikemsg.TransformEncr)), len(prop.ByType(ikemsg.TransformESN)))
	}
}

// buildServerChildPFSRekey crafts a server-initiated Child SA rekey that offers
// PFS: REKEY_SA(0x2222) + an ESP proposal carrying DH group propGroup + Ni + a KE
// payload (group keGroup, public dhPub) + TS. Splitting propGroup from keGroup
// lets a test exercise the KE-group-vs-proposal mismatch path.
func buildServerChildPFSRekey(t *testing.T, respS *Session, msgID uint32, ni, newSPI []byte, propGroup, keGroup uint16, dhPub []byte) []byte {
	t.Helper()
	inner := ikemsg.Payloads{
		&ikemsg.NotifyPayload{Protocol: ikemsg.ProtocolESP, Type: ikemsg.NotifyRekeySA, SPI: []byte{0, 0, 0x22, 0x22}},
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildESPProposalPFS(1, newSPI, propGroup)}},
		&ikemsg.NoncePayload{Data: ni},
		&ikemsg.KEPayload{Group: keGroup, Data: dhPub},
	}
	appendTrafficSelectors(&inner, false)
	raw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeCreateChildSA, 0, msgID, inner)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestChildRekeyResponderPFS: a server-initiated Child rekey carrying a KE
// payload (PFS) is accepted — we answer with our own KE, install with keys
// derived under the PFS KEYMAT (DH shared secret folded in), and latch childPFS.
func TestChildRekeyResponderPFS(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)

	serverDH, err := ikesa.NewDH(ikemsg.DH_MODP2048)
	if err != nil {
		t.Fatal(err)
	}
	serverNi := bytes.Repeat([]byte{0xD0}, nonceLen)
	reqRaw := buildServerChildPFSRekey(t, respS, 5, serverNi, []byte{0xAB, 0xCD, 0xEF, 0x21}, ikemsg.DH_MODP2048, ikemsg.DH_MODP2048, serverDH.Public)

	ctx, cancel := recvCtx(t)
	defer cancel()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if len(initDP.updates) != 1 {
		t.Fatalf("PFS rekey not accepted: installs=%d", len(initDP.updates))
	}
	if !initS.childPFS {
		t.Fatal("childPFS not latched after answering a server PFS rekey")
	}
	u := initDP.updates[0]
	if u.NewOutSPI != 0xABCDEF21 || u.OldInSPI != 0x1111 {
		t.Fatalf("install SPIs wrong: out=%08x old=%08x", u.NewOutSPI, u.OldInSPI)
	}

	respRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, respInner, _, err := respS.decodeIKE(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	var ourNr, ourKEr []byte
	var sawDHGroup bool
	for _, p := range respInner {
		switch v := p.(type) {
		case *ikemsg.NoncePayload:
			ourNr = v.Data
		case *ikemsg.KEPayload:
			ourKEr = v.Data
		case *ikemsg.SAPayload:
			if len(v.Proposals) > 0 && proposalHasDHGroup(v.Proposals[0], ikemsg.DH_MODP2048) {
				sawDHGroup = true
			}
		}
	}
	if len(ourKEr) == 0 {
		t.Fatal("PFS response missing KE payload")
	}
	if !sawDHGroup {
		t.Fatal("PFS response proposal missing DH group 14")
	}

	// Keys must derive under the PFS KEYMAT with the DH shared secret (symmetric:
	// serverShared == ourShared), and must differ from a non-PFS derive.
	serverShared, err := serverDH.Shared(ourKEr)
	if err != nil {
		t.Fatal(err)
	}
	want := initS.ikeSA.DeriveChildKeysPFS(serverShared, serverNi, ourNr, espEncrKeyLen, espIntegKeyLen)
	if !bytes.Equal(u.OutEncr, want.EncrRI) || !bytes.Equal(u.InEncr, want.EncrIR) {
		t.Fatal("PFS responder key orientation incorrect")
	}
	nonpfs := initS.ikeSA.DeriveChildKeys(serverNi, ourNr, espEncrKeyLen, espIntegKeyLen)
	if bytes.Equal(u.OutEncr, nonpfs.EncrRI) {
		t.Fatal("keys derived without PFS (DH shared secret not folded into KEYMAT)")
	}
}

// TestChildPFSLearnedFromServer: after honoring one server PFS rekey, the client
// latches childPFS and offers PFS (a KE payload) on its own subsequent rekeys, so
// a PFS-requiring peer accepts them too.
func TestChildPFSLearnedFromServer(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initS.SetDataPlane(&fakeDataPlane{})

	serverDH, err := ikesa.NewDH(ikemsg.DH_MODP2048)
	if err != nil {
		t.Fatal(err)
	}
	reqRaw := buildServerChildPFSRekey(t, respS, 5, bytes.Repeat([]byte{0xD2}, nonceLen), []byte{0xAB, 0xCD, 0xEF, 0x22}, ikemsg.DH_MODP2048, ikemsg.DH_MODP2048, serverDH.Public)

	ctx, cancel := recvCtx(t)
	defer cancel()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if _, err := respConn.Recv(ctx); err != nil { // drain our response
		t.Fatal(err)
	}
	if !initS.childPFS {
		t.Fatal("childPFS not learned from the server PFS rekey")
	}

	// A subsequent client-initiated rekey must now carry a KE payload.
	if err := initS.initiateChildRekey(ctx, false); err != nil {
		t.Fatal(err)
	}
	reqRaw2, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, inner2, _, err := respS.decodeIKE(reqRaw2)
	if err != nil {
		t.Fatal(err)
	}
	var sawKE bool
	for _, p := range inner2 {
		if _, ok := p.(*ikemsg.KEPayload); ok {
			sawKE = true
		}
	}
	if !sawKE {
		t.Fatal("learned PFS not offered on a client-initiated rekey")
	}
}

// TestChildRekeyInitiatorPFSRoundTrip drives a client-initiated PFS Child rekey
// end to end against a cooperating responder: our request carries a KE, the
// responder answers with its own KE and learns PFS, and both ends install
// mirror-consistent keys (which only hold if both folded the same DH secret).
func TestChildRekeyInitiatorPFSRoundTrip(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initConn := initS.conn
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	respS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initS.childPFS = true // offer PFS on our initiated rekey
	initDP, respDP := &fakeDataPlane{}, &fakeDataPlane{}
	initS.SetDataPlane(initDP)
	respS.SetDataPlane(respDP)

	ctx, cancel := recvCtx(t)
	defer cancel()

	if err := initS.initiateChildRekey(ctx, false); err != nil {
		t.Fatal(err)
	}
	reqRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hdr, inner, dec, err := respS.decodeIKE(reqRaw)
	if err != nil {
		t.Fatal(err)
	}
	var reqHasKE bool
	for _, p := range inner {
		if _, ok := p.(*ikemsg.KEPayload); ok {
			reqHasKE = true
		}
	}
	if !reqHasKE {
		t.Fatal("initiator PFS rekey did not carry a KE payload")
	}

	if err := respS.handleChildRekeyRequest(ctx, hdr, inner, dec, false); err != nil {
		t.Fatal(err)
	}
	if !respS.childPFS {
		t.Fatal("responder did not learn PFS from our KE")
	}

	respRaw, err := initConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if exit := initS.handleInbound(ctx, respRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}

	if len(initDP.updates) != 1 || len(respDP.updates) != 1 {
		t.Fatalf("installs: init=%d resp=%d", len(initDP.updates), len(respDP.updates))
	}
	iu, ru := initDP.updates[0], respDP.updates[0]
	if !bytes.Equal(iu.OutEncr, ru.InEncr) || !bytes.Equal(iu.InEncr, ru.OutEncr) ||
		!bytes.Equal(iu.OutInteg, ru.InInteg) || !bytes.Equal(iu.InInteg, ru.OutInteg) {
		t.Fatal("PFS-rekeyed Child SA keys are not mirror-consistent")
	}
}

// TestChildRekeyInitiatorPFSRejectsDHWithoutKE is finding #17: when we offered PFS
// and the responder's selected proposal STILL carries a DH-group transform but
// omits the KE payload, that is contradictory — installing non-PFS keys would
// silently desync KEYMAT. completeChildRekey must reject it (no install), unlike
// the legitimate DH-narrowed-away fallback below.
func TestChildRekeyInitiatorPFSRejectsDHWithoutKE(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initS.childPFS = true
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)

	ctx, cancel := recvCtx(t)
	defer cancel()
	if err := initS.initiateChildRekey(ctx, false); err != nil {
		t.Fatal(err)
	}
	msgID := initS.pending.msgID
	if _, err := respConn.Recv(ctx); err != nil { // drain our PFS request
		t.Fatal(err)
	}

	// Contradictory response: a DH-group transform selected, but NO KE payload.
	resp := ikemsg.Payloads{
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildESPProposalPFS(1, []byte{0xAB, 0xCD, 0xEF, 0x31}, ikemsg.DH_MODP2048)}},
		&ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0xE1}, nonceLen)},
	}
	appendTrafficSelectors(&resp, false)
	respRaw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeCreateChildSA, ikemsg.FlagResponse, msgID, resp)
	if err != nil {
		t.Fatal(err)
	}
	if exit := initS.handleInbound(ctx, respRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if len(initDP.updates) != 0 {
		t.Fatalf("contradictory DH-without-KE response was installed: updates=%d", len(initDP.updates))
	}
}

// TestChildRekeyInitiatorPFSFallbackToNonPFS: when we offer PFS but the responder
// narrows the DH group away (a valid non-PFS response with no KE), completeChildRekey
// must fall back to a non-PFS install rather than erroring and abandoning the rekey
// (RFC 7296 §2.17 permits a non-PFS Child SA here).
func TestChildRekeyInitiatorPFSFallbackToNonPFS(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initS.childPFS = true // offer PFS
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)

	ctx, cancel := recvCtx(t)
	defer cancel()

	if err := initS.initiateChildRekey(ctx, false); err != nil {
		t.Fatal(err)
	}
	initNi := append([]byte(nil), initS.pending.child.ni...)
	msgID := initS.pending.msgID

	// Drain our request and confirm it offered PFS (a KE payload).
	reqRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, reqInner, _, err := respS.decodeIKE(reqRaw)
	if err != nil {
		t.Fatal(err)
	}
	var reqHasKE bool
	for _, p := range reqInner {
		if _, ok := p.(*ikemsg.KEPayload); ok {
			reqHasKE = true
		}
	}
	if !reqHasKE {
		t.Fatal("precondition: initiator did not offer PFS")
	}

	// Responder narrows PFS away: a valid non-PFS response (no DH group, no KE).
	respNr := bytes.Repeat([]byte{0xE0}, nonceLen)
	resp := ikemsg.Payloads{
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildESPProposal(1, []byte{0xAB, 0xCD, 0xEF, 0x30})}},
		&ikemsg.NoncePayload{Data: respNr},
	}
	appendTrafficSelectors(&resp, false)
	respRaw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeCreateChildSA, ikemsg.FlagResponse, msgID, resp)
	if err != nil {
		t.Fatal(err)
	}

	if exit := initS.handleInbound(ctx, respRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if len(initDP.updates) != 1 {
		t.Fatalf("non-PFS fallback did not install: updates=%d", len(initDP.updates))
	}
	u := initDP.updates[0]
	if u.NewOutSPI != 0xABCDEF30 {
		t.Fatalf("wrong out SPI: %08x", u.NewOutSPI)
	}
	// The keys must be the non-PFS KEYMAT (no DH secret folded in).
	want := initS.ikeSA.DeriveChildKeys(initNi, respNr, espEncrKeyLen, espIntegKeyLen)
	if !bytes.Equal(u.OutEncr, want.EncrIR) || !bytes.Equal(u.InEncr, want.EncrRI) {
		t.Fatal("fallback keys are not the non-PFS KEYMAT")
	}
}

// TestChildRekeyInvalidKEGroup: a server PFS rekey whose KE advertises a DH group
// we cannot run is declined with N(INVALID_KE_PAYLOAD) carrying our preferred
// group (31, so the peer can retry), without installing an SA or latching childPFS.
func TestChildRekeyInvalidKEGroup(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)

	serverDH, err := ikesa.NewDH(ikemsg.DH_MODP2048)
	if err != nil {
		t.Fatal(err)
	}
	// KE advertises group 19 (ECP-256), which we do not run; the proposal still
	// advertises group 14.
	const unsupportedGroup uint16 = 19
	reqRaw := buildServerChildPFSRekey(t, respS, 5, bytes.Repeat([]byte{0xD3}, nonceLen), []byte{0xAB, 0xCD, 0xEF, 0x23}, ikemsg.DH_MODP2048, unsupportedGroup, serverDH.Public)

	ctx, cancel := recvCtx(t)
	defer cancel()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if len(initDP.updates) != 0 {
		t.Fatalf("unsupported KE group must not install an SA, got %d", len(initDP.updates))
	}
	if initS.childPFS {
		t.Fatal("childPFS must not latch on a declined KE group")
	}
	raw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, inner, _, err := respS.decodeIKE(raw)
	if err != nil {
		t.Fatal(err)
	}
	var grp []byte
	var sawInvalidKE bool
	for _, p := range inner {
		if n, ok := p.(*ikemsg.NotifyPayload); ok && n.Type == ikemsg.NotifyInvalidKEPayload {
			sawInvalidKE = true
			grp = n.Data
		}
	}
	if !sawInvalidKE {
		t.Fatal("declined KE group not answered with INVALID_KE_PAYLOAD")
	}
	if len(grp) != 2 || binary.BigEndian.Uint16(grp) != ikemsg.DH_X25519 {
		t.Fatalf("INVALID_KE_PAYLOAD did not carry group 31: %v", grp)
	}
}

// TestChildRekeyResponderX25519: a server-initiated Child rekey carrying an
// x25519 (group 31) KE is accepted — we install, answer with our own group-31 KE,
// and latch childPFS plus childPFSGroup==31 so our own rekeys mirror the group.
func TestChildRekeyResponderX25519(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)

	serverDH, err := ikesa.NewDH(ikemsg.DH_X25519)
	if err != nil {
		t.Fatal(err)
	}
	serverNi := bytes.Repeat([]byte{0xD7}, nonceLen)
	reqRaw := buildServerChildPFSRekey(t, respS, 5, serverNi, []byte{0xAB, 0xCD, 0xEF, 0x31}, ikemsg.DH_X25519, ikemsg.DH_X25519, serverDH.Public)

	ctx, cancel := recvCtx(t)
	defer cancel()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if len(initDP.updates) != 1 {
		t.Fatalf("x25519 PFS rekey not accepted: installs=%d", len(initDP.updates))
	}
	if !initS.childPFS {
		t.Fatal("childPFS not latched after answering a server x25519 PFS rekey")
	}
	if initS.childPFSGroup != ikemsg.DH_X25519 {
		t.Fatalf("childPFSGroup = %d, want 31 (learned from the server)", initS.childPFSGroup)
	}
	u := initDP.updates[0]
	if u.NewOutSPI != 0xABCDEF31 || u.OldInSPI != 0x1111 {
		t.Fatalf("install SPIs wrong: out=%08x old=%08x", u.NewOutSPI, u.OldInSPI)
	}

	// Recover our Nr / KEr (group 31) and confirm the PFS keys folded the shared
	// secret (mirror-consistent only if both ends ran the same x25519 exchange).
	respRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, respInner, _, err := respS.decodeIKE(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	var ourNr, ourKEr []byte
	var sawGroup31 bool
	for _, p := range respInner {
		switch v := p.(type) {
		case *ikemsg.NoncePayload:
			ourNr = v.Data
		case *ikemsg.KEPayload:
			ourKEr = v.Data
			if v.Group != ikemsg.DH_X25519 {
				t.Fatalf("response KE group = %d, want 31", v.Group)
			}
		case *ikemsg.SAPayload:
			if len(v.Proposals) > 0 && proposalHasDHGroup(v.Proposals[0], ikemsg.DH_X25519) {
				sawGroup31 = true
			}
		}
	}
	if len(ourKEr) != 32 {
		t.Fatalf("x25519 response KE length = %d, want 32", len(ourKEr))
	}
	if !sawGroup31 {
		t.Fatal("x25519 response proposal missing DH group 31")
	}
	serverShared, err := serverDH.Shared(ourKEr)
	if err != nil {
		t.Fatal(err)
	}
	want := initS.ikeSA.DeriveChildKeysPFS(serverShared, serverNi, ourNr, espEncrKeyLen, espIntegKeyLen)
	if !bytes.Equal(u.OutEncr, want.EncrRI) || !bytes.Equal(u.InEncr, want.EncrIR) {
		t.Fatal("x25519 PFS responder key orientation incorrect")
	}
}

// TestChildRekeyInitiatorX25519RoundTrip drives a client-initiated PFS Child rekey
// over x25519 (group 31) against a cooperating responder: our request carries a
// group-31 KE, the responder answers in kind, and both ends install
// mirror-consistent keys (which hold only if both folded the same x25519 secret).
func TestChildRekeyInitiatorX25519RoundTrip(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initConn := initS.conn
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	respS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initS.childPFS = true
	initS.childPFSGroup = ikemsg.DH_X25519 // offer x25519 on our rekey
	initDP, respDP := &fakeDataPlane{}, &fakeDataPlane{}
	initS.SetDataPlane(initDP)
	respS.SetDataPlane(respDP)

	ctx, cancel := recvCtx(t)
	defer cancel()

	if err := initS.initiateChildRekey(ctx, false); err != nil {
		t.Fatal(err)
	}
	reqRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hdr, inner, dec, err := respS.decodeIKE(reqRaw)
	if err != nil {
		t.Fatal(err)
	}
	var keGroup uint16
	var keLen int
	for _, p := range inner {
		if ke, ok := p.(*ikemsg.KEPayload); ok {
			keGroup = ke.Group
			keLen = len(ke.Data)
		}
	}
	if keGroup != ikemsg.DH_X25519 || keLen != 32 {
		t.Fatalf("initiator rekey KE group=%d len=%d, want 31/32", keGroup, keLen)
	}

	if err := respS.handleChildRekeyRequest(ctx, hdr, inner, dec, false); err != nil {
		t.Fatal(err)
	}
	if respS.childPFSGroup != ikemsg.DH_X25519 {
		t.Fatalf("responder childPFSGroup = %d, want 31", respS.childPFSGroup)
	}

	respRaw, err := initConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if exit := initS.handleInbound(ctx, respRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}

	if len(initDP.updates) != 1 || len(respDP.updates) != 1 {
		t.Fatalf("installs: init=%d resp=%d", len(initDP.updates), len(respDP.updates))
	}
	iu, ru := initDP.updates[0], respDP.updates[0]
	if !bytes.Equal(iu.OutEncr, ru.InEncr) || !bytes.Equal(iu.InEncr, ru.OutEncr) ||
		!bytes.Equal(iu.OutInteg, ru.InInteg) || !bytes.Equal(iu.InInteg, ru.OutInteg) {
		t.Fatal("x25519-rekeyed Child SA keys are not mirror-consistent")
	}
}

// TestIKERekeyX25519RoundTrip drives a full IKE SA rekey we initiate over x25519
// (group 31) and checks both ends cut over to an identical new IKE SA.
func TestIKERekeyX25519RoundTrip(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initConn := initS.conn
	initS.ikeDHGroup = ikemsg.DH_X25519 // rekey reuses the established group
	oldInitSA := initS.ikeSA

	ctx, cancel := recvCtx(t)
	defer cancel()

	if err := initS.initiateIKERekey(ctx); err != nil {
		t.Fatal(err)
	}
	reqRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hdr, inner, dec, err := respS.decodeIKE(reqRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !isIKERekey(inner) {
		t.Fatal("expected an IKE rekey request")
	}
	var keGroup uint16
	for _, p := range inner {
		if ke, ok := p.(*ikemsg.KEPayload); ok {
			keGroup = ke.Group
		}
	}
	if keGroup != ikemsg.DH_X25519 {
		t.Fatalf("IKE rekey KE group = %d, want 31", keGroup)
	}
	if err := respS.handleIKERekeyRequest(ctx, hdr, inner, dec, false); err != nil {
		t.Fatal(err)
	}

	respRaw, err := initConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if exit := initS.handleInbound(ctx, respRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if initS.ikeSA == oldInitSA {
		t.Fatal("initiator did not swap the IKE SA")
	}
	if initS.oldIKE == nil {
		t.Fatal("initiator did not retain the old IKE SA for grace decode")
	}
	// The two new IKE SAs must agree: a message encoded by the initiator's new SA
	// decodes under the responder's new SA.
	probe, err := initS.encodeSKEmpty(ikemsg.ExchangeInformational, ikemsg.FlagInitiator, initS.messageID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := respS.decodeIKE(probe); err != nil {
		t.Fatalf("new IKE SAs disagree: %v", err)
	}
}

// TestServerIKERekeyX25519: a server-initiated IKE SA rekey carrying an x25519
// (group 31) KE is accepted and the responder cuts over to a new IKE SA.
func TestServerIKERekeyX25519(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)

	dh, err := ikesa.NewDH(ikemsg.DH_X25519)
	if err != nil {
		t.Fatal(err)
	}
	serverNi := bytes.Repeat([]byte{0xE7}, nonceLen)
	reqRaw := serverIKERekey(t, respS, 0, 0x6161, ikemsg.DH_X25519, dh.Public, serverNi)

	ctx, cancel := recvCtx(t)
	defer cancel()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if initS.oldIKE == nil {
		t.Fatal("did not cut over to a new IKE SA on a server x25519 IKE rekey")
	}
	// Drain and decode our rekey response; its KE must be group 31.
	respRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, respInner, _, err := respS.decodeIKE(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	var keGroup uint16
	for _, p := range respInner {
		if ke, ok := p.(*ikemsg.KEPayload); ok {
			keGroup = ke.Group
		}
	}
	if keGroup != ikemsg.DH_X25519 {
		t.Fatalf("our IKE rekey response KE group = %d, want 31", keGroup)
	}
}

// beUint32 is a tiny local helper for the tests.
func beUint32(b []byte) uint32 {
	if len(b) != 4 {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
