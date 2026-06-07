package ikesa

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestPRF_RFC4231 pins PRF_HMAC_SHA2_256 to RFC 4231 test case 2.
func TestPRF_RFC4231(t *testing.T) {
	got := prf([]byte("Jefe"), []byte("what do ya want for nothing?"))
	want := mustHex(t, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
	if !bytes.Equal(got, want) {
		t.Fatalf("prf mismatch:\n got %x\nwant %x", got, want)
	}
}

// TestInteg_RFC4868 checks AUTH_HMAC_SHA2_256_128 truncates to the first 128
// bits of the RFC 4231 case-2 HMAC.
func TestInteg_RFC4868(t *testing.T) {
	got := integ([]byte("Jefe"), []byte("what do ya want for nothing?"))
	want := mustHex(t, "5bdcc146bf60754e6a042426089575c7")
	if !bytes.Equal(got, want) {
		t.Fatalf("integ mismatch:\n got %x\nwant %x", got, want)
	}
	if len(got) != integICVLen {
		t.Fatalf("ICV len = %d, want %d", len(got), integICVLen)
	}
}

// TestAESCBC_RFC3602 decrypts the RFC 3602 §4 case-1 vector.
func TestAESCBC_RFC3602(t *testing.T) {
	key := mustHex(t, "06a9214036b8a15b512e03d534120006")
	iv := mustHex(t, "3dafba429d9eb430b422da802c9fac41")
	ct := mustHex(t, "e353779c1079aeb82708942dbe77181a")
	pt, err := aesCBCDecrypt(key, append(iv, ct...))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "Single block msg" {
		t.Fatalf("decrypt = %q, want %q", pt, "Single block msg")
	}
	// And the encrypt direction round-trips (random IV).
	enc, err := aesCBCEncrypt(mustHex(t, "0000000000000000000000000000000000000000000000000000000000000000"),
		bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		t.Fatal(err)
	}
	back, err := aesCBCDecrypt(mustHex(t, "0000000000000000000000000000000000000000000000000000000000000000"), enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, bytes.Repeat([]byte{0xAB}, 32)) {
		t.Fatal("AES-CBC round-trip mismatch")
	}
}

// TestPrfPlus checks the prf+ chaining against an independent reference
// computed straight from the prf primitive.
func TestPrfPlus(t *testing.T) {
	key := []byte("0123456789abcdef")
	seed := []byte("seed-material")
	const n = 100

	ref := func() []byte {
		var out, prev []byte
		for i := byte(1); len(out) < n; i++ {
			h := hmac.New(sha256.New, key)
			h.Write(prev)
			h.Write(seed)
			h.Write([]byte{i})
			prev = h.Sum(nil)
			out = append(out, prev...)
		}
		return out[:n]
	}()

	got := prfPlus(key, seed, n)
	if !bytes.Equal(got, ref) {
		t.Fatalf("prf+ mismatch:\n got %x\nwant %x", got, ref)
	}
	if len(got) != n {
		t.Fatalf("prf+ len = %d, want %d", len(got), n)
	}
}

// TestDH checks the MODP-2048 constant is well-formed and the exchange agrees.
func TestDH(t *testing.T) {
	if modp2048P.BitLen() != 2048 {
		t.Fatalf("MODP-2048 prime bit length = %d, want 2048", modp2048P.BitLen())
	}
	// g^2 mod p == 4, a cheap sanity check that the prime is intact.
	if got := new(big.Int).Exp(modp2048G, big.NewInt(2), modp2048P); got.Cmp(big.NewInt(4)) != 0 {
		t.Fatalf("g^2 mod p = %s, want 4", got)
	}

	a, err := NewDH(DHGroup14)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDH(DHGroup14)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Public) != modp2048Len {
		t.Fatalf("public value length = %d, want %d", len(a.Public), modp2048Len)
	}
	sa, err := a.Shared(b.Public)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.Shared(a.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa, sb) {
		t.Fatal("DH shared secrets disagree")
	}
	if len(sa) != modp2048Len {
		t.Fatalf("shared secret length = %d, want %d", len(sa), modp2048Len)
	}
	// Degenerate peer values must be rejected.
	for _, bad := range [][]byte{{}, {1}, leftPad([]byte{1}, modp2048Len)} {
		if _, err := a.Shared(bad); err == nil {
			t.Fatalf("Shared(%x) accepted a degenerate peer value", bad)
		}
	}
}

// TestDeriveRekeyIKE checks that the IKE-SA rekey derivation (RFC 7296 §2.18)
// agrees across roles and differs from the initial derivation.
func TestDeriveRekeyIKE(t *testing.T) {
	ni := bytes.Repeat([]byte{0x77}, 32)
	nr := bytes.Repeat([]byte{0x88}, 32)
	dh := bytes.Repeat([]byte{0x99}, modp2048Len)

	// An initial SA gives us an SK_d to key the rekey SKEYSEED.
	base := &IKESA{}
	if err := base.Derive(Initiator, 1, 2, ni, nr, dh); err != nil {
		t.Fatal(err)
	}

	newNi := bytes.Repeat([]byte{0xAA}, 32)
	newNr := bytes.Repeat([]byte{0xBB}, 32)
	newDH := bytes.Repeat([]byte{0xCC}, modp2048Len)
	const spii, spir = 0xDEAD, 0xBEEF

	ri, err := DeriveRekeyIKE(base.SKd, Initiator, spii, spir, newNi, newNr, newDH)
	if err != nil {
		t.Fatal(err)
	}
	rr, err := DeriveRekeyIKE(base.SKd, Responder, spii, spir, newNi, newNr, newDH)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ri.SKei, rr.SKei) || !bytes.Equal(ri.SKar, rr.SKar) || !bytes.Equal(ri.SKd, rr.SKd) {
		t.Fatal("rekey derivation disagrees across roles")
	}
	if bytes.Equal(ri.SKd, base.SKd) {
		t.Fatal("rekeyed SK_d must differ from the original")
	}
	// And the rekeyed SAs encrypt/decrypt across roles.
	sk, err := ri.EncryptToSK([]byte("rekey payload"))
	if err != nil {
		t.Fatal(err)
	}
	msg := append([]byte{}, sk...)
	if err := ri.Checksum(msg); err != nil {
		t.Fatal(err)
	}
	if !rr.VerifyChecksum(msg) {
		t.Fatal("rekeyed responder failed to verify initiator ICV")
	}
	got, err := rr.DecryptSK(msg)
	if err != nil || string(got) != "rekey payload" {
		t.Fatalf("rekey SK round-trip failed: %v %q", err, got)
	}
}

// TestDeriveChildKeysPFS checks the PFS Child-key derivation folds the DH shared
// secret into KEYMAT (RFC 7296 §2.17): it is deterministic, differs from the
// non-PFS derivation over the same nonces, and changes when the shared secret
// changes.
func TestDeriveChildKeysPFS(t *testing.T) {
	ni := bytes.Repeat([]byte{0x11}, 32)
	nr := bytes.Repeat([]byte{0x22}, 32)
	dhShared := bytes.Repeat([]byte{0x33}, modp2048Len)

	sa := &IKESA{}
	if err := sa.Derive(Initiator, 1, 2, ni, nr, bytes.Repeat([]byte{0x44}, modp2048Len)); err != nil {
		t.Fatal(err)
	}

	pfs := sa.DeriveChildKeysPFS(dhShared, ni, nr, 32, 32)
	// Deterministic.
	if again := sa.DeriveChildKeysPFS(dhShared, ni, nr, 32, 32); !bytes.Equal(pfs.EncrIR, again.EncrIR) {
		t.Fatal("PFS child key derivation is not deterministic")
	}
	// Differs from the non-PFS derivation over the same nonces.
	if nonpfs := sa.DeriveChildKeys(ni, nr, 32, 32); bytes.Equal(pfs.EncrIR, nonpfs.EncrIR) {
		t.Fatal("PFS derivation must differ from non-PFS (DH secret not folded)")
	}
	// Changes when the shared secret changes.
	if other := sa.DeriveChildKeysPFS(bytes.Repeat([]byte{0x55}, modp2048Len), ni, nr, 32, 32); bytes.Equal(pfs.EncrIR, other.EncrIR) {
		t.Fatal("PFS derivation insensitive to the DH shared secret")
	}
	// All four directional keys are populated at the requested length.
	for _, k := range [][]byte{pfs.EncrIR, pfs.IntegIR, pfs.EncrRI, pfs.IntegRI} {
		if len(k) != 32 {
			t.Fatalf("key length = %d, want 32", len(k))
		}
	}
}

// TestDHSharedRejectsWrongLength: a peer DH public must be exactly the group's
// public length; a short/long value (a different group, or a truncated/malformed
// KE) is rejected rather than SetBytes-parsed into an in-range integer the peer
// never sent (group 14) or fed to X25519 with a non-32-byte key (group 31), either
// of which would silently mismatch KEYMAT.
func TestDHSharedRejectsWrongLength(t *testing.T) {
	dh, err := NewDH(DHGroup14)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dh.Shared(dh.Public); err != nil {
		t.Fatalf("valid-length Shared rejected: %v", err)
	}
	// Wrong-length but otherwise in-range values, so only the length check (not the
	// degenerate-value range check) can reject them: drop the trailing byte, and
	// prepend a zero byte (same magnitude, padded to 257 bytes).
	short := dh.Public[:modp2048Len-1]
	long := append([]byte{0}, dh.Public...)
	if _, err := dh.Shared(short); err == nil {
		t.Fatalf("Shared accepted a %d-byte (short) public", len(short))
	}
	if _, err := dh.Shared(long); err == nil {
		t.Fatalf("Shared accepted a %d-byte (long) public", len(long))
	}

	// Group 31: a 32-byte public is accepted; 31 and 33 bytes are rejected.
	x, err := NewDH(DHGroup31)
	if err != nil {
		t.Fatal(err)
	}
	if len(x.Public) != x25519Len {
		t.Fatalf("x25519 public length = %d, want %d", len(x.Public), x25519Len)
	}
	if _, err := x.Shared(x.Public); err != nil {
		t.Fatalf("valid-length x25519 Shared rejected: %v", err)
	}
	if _, err := x.Shared(x.Public[:x25519Len-1]); err == nil {
		t.Fatalf("x25519 Shared accepted a %d-byte (short) public", x25519Len-1)
	}
	if _, err := x.Shared(append([]byte{0}, x.Public...)); err == nil {
		t.Fatalf("x25519 Shared accepted a %d-byte (long) public", x25519Len+1)
	}
}

// TestX25519DHRoundTrip checks the group-31 exchange agrees across both ends and
// yields a 32-byte shared secret (RFC 7748).
func TestX25519DHRoundTrip(t *testing.T) {
	a, err := NewDH(DHGroup31)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDH(DHGroup31)
	if err != nil {
		t.Fatal(err)
	}
	if a.Group != DHGroup31 || len(a.Public) != x25519Len {
		t.Fatalf("group=%d publicLen=%d, want group 31 / %d-byte public", a.Group, len(a.Public), x25519Len)
	}
	sa, err := a.Shared(b.Public)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.Shared(a.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa, sb) {
		t.Fatal("x25519 shared secrets disagree")
	}
	if len(sa) != x25519Len {
		t.Fatalf("x25519 shared secret length = %d, want %d", len(sa), x25519Len)
	}
}

// TestNewDHUnsupportedGroup: NewDH rejects a group the client cannot run.
func TestNewDHUnsupportedGroup(t *testing.T) {
	for _, g := range []uint16{0, 1, 19, 30, 32} {
		if _, err := NewDH(g); err == nil {
			t.Fatalf("NewDH(%d) accepted an unsupported group", g)
		}
	}
}

// TestSKRoundTrip exercises the full SK{} envelope: derive keys, encrypt a
// plaintext, checksum, verify, decrypt — and reject a tampered ICV.
func TestSKRoundTrip(t *testing.T) {
	ni := bytes.Repeat([]byte{0x11}, 32)
	nr := bytes.Repeat([]byte{0x22}, 32)
	dh := bytes.Repeat([]byte{0x33}, modp2048Len)

	init := &IKESA{}
	if err := init.Derive(Initiator, 0xAAAA, 0xBBBB, ni, nr, dh); err != nil {
		t.Fatal(err)
	}
	resp := &IKESA{}
	if err := resp.Derive(Responder, 0xAAAA, 0xBBBB, ni, nr, dh); err != nil {
		t.Fatal(err)
	}
	// Both ends must derive identical key material.
	if !bytes.Equal(init.SKei, resp.SKei) || !bytes.Equal(init.SKar, resp.SKar) {
		t.Fatal("derived keys disagree across roles")
	}

	for _, ptLen := range []int{0, 1, 15, 16, 17, 31, 200} {
		plain := bytes.Repeat([]byte{0x5A}, ptLen)
		sk, err := init.EncryptToSK(plain)
		if err != nil {
			t.Fatalf("encrypt len %d: %v", ptLen, err)
		}
		// SK body must be IV + ≥1 block + ICV and block-aligned in the middle.
		if (len(sk)-integICVLen-aesBlock)%aesBlock != 0 {
			t.Fatalf("SK body not block aligned for len %d", ptLen)
		}

		// Wrap as a minimal message: [body | ICV]; checksum then verify.
		msg := append([]byte{}, sk...)
		if err := init.Checksum(msg); err != nil {
			t.Fatal(err)
		}
		if !resp.VerifyChecksum(msg) {
			t.Fatalf("responder failed to verify ICV for len %d", ptLen)
		}

		got, err := resp.DecryptSK(msg)
		if err != nil {
			t.Fatalf("decrypt len %d: %v", ptLen, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("round-trip mismatch len %d:\n got %x\nwant %x", ptLen, got, plain)
		}

		// Tamper the ICV → must be rejected.
		bad := append([]byte{}, msg...)
		bad[len(bad)-1] ^= 0xFF
		if resp.VerifyChecksum(bad) {
			t.Fatalf("tampered ICV accepted for len %d", ptLen)
		}
	}
}

// TestPRFPlusBlockCount is finding #3: prf+ supports up to the RFC 7296 §2.13
// maximum of 255 blocks; requesting a 256th block would wrap the single-byte
// counter, so the guard panics rather than emit silently-wrong key material.
func TestPRFPlusBlockCount(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 32)
	seed := []byte("prf+ block-count seed")

	if got := prfPlus(key, seed, 255*sha256.Size); len(got) != 255*sha256.Size {
		t.Fatalf("prfPlus(255 blocks) = %d bytes, want %d", len(got), 255*sha256.Size)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("prfPlus did not panic past 255 blocks")
		}
	}()
	_ = prfPlus(key, seed, 256*sha256.Size)
}
