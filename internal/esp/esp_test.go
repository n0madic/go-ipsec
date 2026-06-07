package esp

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"testing"
)

func newTestSA(t *testing.T, window uint32) (*SA, *SA) {
	t.Helper()
	// initiator: out=0x1111 (peer's SPI), in=0x2222 (ours)
	encrIR := bytes.Repeat([]byte{0x01}, 32)
	integIR := bytes.Repeat([]byte{0x02}, 32)
	encrRI := bytes.Repeat([]byte{0x03}, 32)
	integRI := bytes.Repeat([]byte{0x04}, 32)

	// init sends with encrIR/integIR, receives with encrRI/integRI.
	init, err := NewSA(0x1111, 0x2222, encrIR, integIR, encrRI, integRI, window)
	if err != nil {
		t.Fatal(err)
	}
	// responder is the mirror: out=0x2222, in=0x1111; its outbound = init's inbound.
	resp, err := NewSA(0x2222, 0x1111, encrRI, integRI, encrIR, integIR, window)
	if err != nil {
		t.Fatal(err)
	}
	return init, resp
}

func TestESPRoundTrip(t *testing.T) {
	init, resp := newTestSA(t, 64)
	for _, n := range []int{0, 1, 14, 15, 16, 20, 1400} {
		inner := bytes.Repeat([]byte{0xAB}, n)
		pkt, err := init.Encrypt(inner)
		if err != nil {
			t.Fatalf("encrypt len %d: %v", n, err)
		}
		got, err := resp.Decrypt(pkt)
		if err != nil {
			t.Fatalf("decrypt len %d: %v", n, err)
		}
		if !bytes.Equal(got, inner) {
			t.Fatalf("round-trip mismatch len %d", n)
		}
	}
}

func TestESPICVTamper(t *testing.T) {
	init, resp := newTestSA(t, 64)
	pkt, _ := init.Encrypt([]byte("hello world inner ip"))
	bad := append([]byte(nil), pkt...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := resp.Decrypt(bad); err == nil {
		t.Fatal("tampered ICV accepted")
	}
	// flip a ciphertext byte → ICV must catch it
	bad2 := append([]byte(nil), pkt...)
	bad2[30] ^= 0xFF
	if _, err := resp.Decrypt(bad2); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestESPWrongSPI(t *testing.T) {
	init, resp := newTestSA(t, 64)
	pkt, _ := resp.Encrypt([]byte("from responder")) // SPI=0x1111 (init's inSPI)
	if _, err := init.Decrypt(pkt); err != nil {
		t.Fatalf("init should accept responder packet: %v", err)
	}
	// init's own packet has SPI 0x1111 too... craft mismatch: resp can't decode
	// a packet addressed to itself by init? init.Encrypt → SPI 0x1111 == resp.inSPI,
	// so resp accepts. Verify a deliberately wrong SPI is rejected.
	p := init.mustEncrypt(t, []byte("x"))
	p[0] ^= 0xFF // corrupt SPI
	if _, err := resp.Decrypt(p); err == nil {
		t.Fatal("wrong SPI accepted")
	}
}

func (sa *SA) mustEncrypt(t *testing.T, b []byte) []byte {
	t.Helper()
	p, err := sa.Encrypt(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// encryptNH mirrors Encrypt but stamps an arbitrary Next Header so the decode
// path's protocol check can be exercised. Test-only.
func (sa *SA) encryptNH(t *testing.T, inner []byte, nextHdr byte) []byte {
	t.Helper()
	seq := sa.seq.Add(1)
	padLen := (espBlock - (len(inner)+2)%espBlock) % espBlock
	plainLen := len(inner) + padLen + 2
	out := make([]byte, espHeaderLen+espIVLen+plainLen+espICVLen)
	binary.BigEndian.PutUint32(out[0:4], sa.outSPI)
	binary.BigEndian.PutUint32(out[4:8], seq)
	iv := out[espHeaderLen : espHeaderLen+espIVLen]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		t.Fatal(err)
	}
	ctStart := espHeaderLen + espIVLen
	plain := out[ctStart : ctStart+plainLen]
	copy(plain, inner)
	for i := range padLen {
		plain[len(inner)+i] = byte(i + 1)
	}
	plain[plainLen-2] = byte(padLen)
	plain[plainLen-1] = nextHdr
	cipher.NewCBCEncrypter(sa.outBlock, iv).CryptBlocks(plain, plain)
	mac := hmac.New(sha256.New, sa.outInteg)
	mac.Write(out[:ctStart+plainLen])
	copy(out[ctStart+plainLen:], mac.Sum(nil)[:espICVLen])
	return out
}

func TestESPSeqExhaustion(t *testing.T) {
	init, _ := newTestSA(t, 64)
	init.seq.Store(^uint32(0)) // next Add(1) wraps 0xFFFFFFFF → 0
	if _, err := init.Encrypt([]byte("x")); !errors.Is(err, ErrSeqExhausted) {
		t.Fatalf("expected ErrSeqExhausted on wrap, got %v", err)
	}
	// The counter stays pinned, so every subsequent Encrypt also refuses.
	if _, err := init.Encrypt([]byte("y")); !errors.Is(err, ErrSeqExhausted) {
		t.Fatalf("expected ErrSeqExhausted to persist, got %v", err)
	}
}

// TestESPSeqNoReuseAtExhaustion seeds the counter near the top of the space and
// checks the final packets carry the last valid sequence numbers, then every
// further Encrypt refuses — never emitting 0 or a reused value (finding #11).
func TestESPSeqNoReuseAtExhaustion(t *testing.T) {
	init, _ := newTestSA(t, 64)
	const max = ^uint32(0)
	init.seq.Store(max - 2) // two valid seqs remain: max-1 and max

	var got []uint32
	for range 4 {
		pkt, err := init.Encrypt([]byte("x"))
		if err != nil {
			if !errors.Is(err, ErrSeqExhausted) {
				t.Fatalf("unexpected error: %v", err)
			}
			continue
		}
		got = append(got, binary.BigEndian.Uint32(pkt[4:8]))
	}
	if len(got) != 2 || got[0] != max-1 || got[1] != max {
		t.Fatalf("emitted seqs = %v, want [%d %d]", got, max-1, max)
	}
	for _, s := range got {
		if s == 0 {
			t.Fatal("Encrypt emitted sequence number 0")
		}
	}
}

// TestESPConcurrentEncryptUnique runs many concurrent Encrypts across the
// exhaustion boundary and checks every emitted sequence number is unique and
// non-zero, with exactly the available slots succeeding. The two-step Add+Store
// could hand two goroutines the same seq at the wrap; the CAS loop cannot
// (finding #11). Run under -race.
func TestESPConcurrentEncryptUnique(t *testing.T) {
	init, _ := newTestSA(t, 64)
	const (
		max        = ^uint32(0)
		slots      = 200
		goroutines = 512
	)
	init.seq.Store(max - slots) // exactly `slots` sequence numbers remain

	var wg sync.WaitGroup
	seqs := make(chan uint32, goroutines)
	var exhausted, otherErr atomic.Int64
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pkt, err := init.Encrypt([]byte("y"))
			switch {
			case err == nil:
				seqs <- binary.BigEndian.Uint32(pkt[4:8])
			case errors.Is(err, ErrSeqExhausted):
				exhausted.Add(1)
			default:
				otherErr.Add(1)
			}
		}()
	}
	wg.Wait()
	close(seqs)

	if otherErr.Load() != 0 {
		t.Fatalf("%d Encrypts failed with an unexpected error", otherErr.Load())
	}
	seen := make(map[uint32]bool)
	for s := range seqs {
		if s == 0 {
			t.Fatal("Encrypt emitted sequence number 0")
		}
		if seen[s] {
			t.Fatalf("sequence number %d emitted twice (reuse)", s)
		}
		seen[s] = true
	}
	if len(seen) != slots {
		t.Fatalf("emitted %d unique seqs, want exactly %d", len(seen), slots)
	}
	if got := exhausted.Load(); got != int64(goroutines-slots) {
		t.Fatalf("got %d ErrSeqExhausted, want %d", got, goroutines-slots)
	}
}

func TestESPNextHeader(t *testing.T) {
	init, resp := newTestSA(t, 64)
	// IPv6 inner (Next Header 41) is accepted.
	if _, err := resp.Decrypt(init.encryptNH(t, []byte("ipv6 inner pkt!!"), nextHeaderIPv6)); err != nil {
		t.Fatalf("IPv6 next header rejected: %v", err)
	}
	// An unexpected Next Header (50 = ESP) is rejected even with a valid ICV.
	if _, err := resp.Decrypt(init.encryptNH(t, []byte("bad inner pkt!!!"), 50)); err == nil {
		t.Fatal("packet with next header 50 accepted")
	}
}

// nextHeaderOf decrypts pkt with sa's inbound key and returns the ESP trailer's
// Next Header byte, so a test can assert Encrypt stamped the inner IP family.
func (sa *SA) nextHeaderOf(t *testing.T, pkt []byte) byte {
	t.Helper()
	ctStart := espHeaderLen + espIVLen
	iv := pkt[espHeaderLen:ctStart]
	ct := pkt[ctStart : len(pkt)-espICVLen]
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(sa.inBlock, iv).CryptBlocks(plain, ct)
	return plain[len(plain)-1]
}

// TestESPEncryptNextHeaderByInnerVersion is finding #1: Encrypt must stamp the ESP
// Next Header from the inner packet's IP version (41 for IPv6, 4 for IPv4) so a
// dual-stack peer routes inner IPv6 correctly instead of dropping it.
func TestESPEncryptNextHeaderByInnerVersion(t *testing.T) {
	init, resp := newTestSA(t, 64)
	v6 := append([]byte{0x60}, bytes.Repeat([]byte{0xab}, 39)...) // 0x6x → IPv6
	if nh := resp.nextHeaderOf(t, init.mustEncrypt(t, v6)); nh != nextHeaderIPv6 {
		t.Fatalf("inner IPv6: Next Header = %d, want %d", nh, nextHeaderIPv6)
	}
	v4 := append([]byte{0x45}, bytes.Repeat([]byte{0xcd}, 19)...) // 0x4x → IPv4
	if nh := resp.nextHeaderOf(t, init.mustEncrypt(t, v4)); nh != nextHeaderIPv4 {
		t.Fatalf("inner IPv4: Next Header = %d, want %d", nh, nextHeaderIPv4)
	}
}

// encryptBadPad mirrors Encrypt but writes non-monotonic pad octets (0xFF) with a
// valid ICV, so the decode path's RFC 4303 §2.4 pad-validation can be exercised.
// Test-only; requires an inner length that forces at least one pad octet.
func (sa *SA) encryptBadPad(t *testing.T, inner []byte) []byte {
	t.Helper()
	seq := sa.seq.Add(1)
	padLen := (espBlock - (len(inner)+2)%espBlock) % espBlock
	if padLen == 0 {
		t.Fatalf("inner length %d produces no padding; pick a padding length", len(inner))
	}
	plainLen := len(inner) + padLen + 2
	out := make([]byte, espHeaderLen+espIVLen+plainLen+espICVLen)
	binary.BigEndian.PutUint32(out[0:4], sa.outSPI)
	binary.BigEndian.PutUint32(out[4:8], seq)
	iv := out[espHeaderLen : espHeaderLen+espIVLen]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		t.Fatal(err)
	}
	ctStart := espHeaderLen + espIVLen
	plain := out[ctStart : ctStart+plainLen]
	copy(plain, inner)
	for i := range padLen {
		plain[len(inner)+i] = 0xFF // RFC 4303 wants 1,2,...,padLen; 0xFF is malformed
	}
	plain[plainLen-2] = byte(padLen)
	plain[plainLen-1] = nextHeaderIPv4
	cipher.NewCBCEncrypter(sa.outBlock, iv).CryptBlocks(plain, plain)
	mac := hmac.New(sha256.New, sa.outInteg)
	mac.Write(out[:ctStart+plainLen])
	copy(out[ctStart+plainLen:], mac.Sum(nil)[:espICVLen])
	return out
}

// TestESPDecryptRejectsMalformedPadding is finding #10: pad octets that are not the
// monotonic 1..padLen sequence are rejected even with a valid ICV.
func TestESPDecryptRejectsMalformedPadding(t *testing.T) {
	init, resp := newTestSA(t, 64)
	if _, err := resp.Decrypt(init.encryptBadPad(t, []byte("thirteenbytes"))); err == nil {
		t.Fatal("packet with non-monotonic padding accepted")
	}
	if _, err := resp.Decrypt(init.mustEncrypt(t, []byte("thirteenbytes"))); err != nil {
		t.Fatalf("valid packet of the same length rejected: %v", err)
	}
}

func TestReplayWindow(t *testing.T) {
	w := NewReplayWindow(64)
	if w.Accept(0) {
		t.Fatal("sequence 0 must be rejected")
	}
	if !w.Accept(1) {
		t.Fatal("first packet rejected")
	}
	if w.Accept(1) {
		t.Fatal("replay of 1 accepted")
	}
	// jump ahead
	if !w.Accept(100) {
		t.Fatal("100 rejected")
	}
	// in-window, not seen
	if !w.Accept(99) {
		t.Fatal("99 (in window) rejected")
	}
	if w.Accept(99) {
		t.Fatal("replay of 99 accepted")
	}
	// older than window (100 - 64 = 36; anything <= 36 too old)
	if w.Accept(36) {
		t.Fatal("36 (out of window) accepted")
	}
	if !w.Accept(37) {
		t.Fatal("37 (edge of window) rejected")
	}
	// far jump clears window
	if !w.Accept(1_000_000) {
		t.Fatal("big jump rejected")
	}
	if w.Accept(100) {
		t.Fatal("100 after big jump should be out of window")
	}
}

func TestReplayWindowLargerSize(t *testing.T) {
	w := NewReplayWindow(256)
	for _, s := range []uint32{500, 400, 300, 250} {
		if !w.Accept(s) {
			t.Fatalf("%d rejected", s)
		}
	}
	for _, s := range []uint32{500, 400, 300, 250} {
		if w.Accept(s) {
			t.Fatalf("replay of %d accepted", s)
		}
	}
	// 500-256 = 244 → 244 and below are out of window
	if w.Accept(244) {
		t.Fatal("244 (out of window) accepted")
	}
	if !w.Accept(245) {
		t.Fatal("245 (in window) rejected")
	}
}

// TestReplayWindowHugeSizeNoOverflow guards the uint32 word-count overflow: a
// size near math.MaxUint32 previously wrapped (size+63) to a tiny value, yielding
// a zero-length bitmap that panicked on the first packet. It must now clamp to
// MaxReplayWindow and still accept traffic.
func TestReplayWindowHugeSizeNoOverflow(t *testing.T) {
	for _, size := range []uint32{math.MaxUint32, math.MaxUint32 - 1, 0xFFFFFFC0, MaxReplayWindow + 1} {
		w := NewReplayWindow(size)
		if w.size == 0 || len(w.bits) == 0 {
			t.Fatalf("size %d: zero-length window (overflow)", size)
		}
		if w.size > MaxReplayWindow {
			t.Fatalf("size %d: not clamped, got window size %d", size, w.size)
		}
		if !w.Accept(1) {
			t.Fatalf("size %d: first packet rejected", size)
		}
	}
}
