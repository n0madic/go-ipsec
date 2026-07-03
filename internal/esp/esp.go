package esp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/n0madic/go-ipsec/internal/secretmem"
)

const (
	espHeaderLen = 8  // SPI(4) | SeqNum(4)
	espIVLen     = 16 // AES-CBC IV
	espICVLen    = 16 // HMAC-SHA2-256-128
	espBlock     = aes.BlockSize
	// nextHeaderIPv4 / nextHeaderIPv6 are the ESP Next Header values for a
	// tunnelled IPv4 / IPv6 packet (RFC 4303 tunnel mode).
	nextHeaderIPv4 = 4
	nextHeaderIPv6 = 41
)

// ErrReplay is returned by Decrypt when a packet fails the anti-replay check.
var ErrReplay = errors.New("esp: replay or out-of-window sequence")

// ErrSeqExhausted is returned by Encrypt when the 32-bit outbound sequence
// counter is about to wrap. RFC 4303 §3.3.3 forbids reusing a sequence number,
// so the SA must be rekeyed before this happens; Encrypt refuses to emit a
// wrapped (and therefore replayed) packet rather than silently stalling the peer.
var ErrSeqExhausted = errors.New("esp: outbound sequence number space exhausted, rekey required")

// SA is one directional pair of Child SA crypto contexts (outbound to the peer,
// inbound from the peer). It owns the outbound sequence counter and the inbound
// anti-replay window. Encrypt/Decrypt are safe for concurrent use.
type SA struct {
	outSPI uint32 // peer's SPI: goes in packets we send
	inSPI  uint32 // our SPI: expected in packets we receive

	outBlock cipher.Block
	inBlock  cipher.Block
	outInteg []byte
	inInteg  []byte

	seq    atomic.Uint32
	replay *ReplayWindow
}

// NewSA builds a Child SA transform. outSPI is the responder's SPI (placed in
// outbound packets); inSPI is our SPI (matched on inbound). The key arguments
// are the directional ESP keys (AES-256 encryption, HMAC-SHA2-256 integrity).
// Construction runs inside secretmem.Do so the AES key schedules and integrity
// key copies are runtime-tracked and erased once the SA is dropped on rekey or
// teardown (see internal/secretmem).
func NewSA(outSPI, inSPI uint32, outEncr, outInteg, inEncr, inInteg []byte, replayWindow uint32) (*SA, error) {
	var sa *SA
	var err error
	secretmem.Do(func() { sa, err = newSA(outSPI, inSPI, outEncr, outInteg, inEncr, inInteg, replayWindow) })
	return sa, err
}

func newSA(outSPI, inSPI uint32, outEncr, outInteg, inEncr, inInteg []byte, replayWindow uint32) (*SA, error) {
	ob, err := aes.NewCipher(outEncr)
	if err != nil {
		return nil, fmt.Errorf("esp: outbound cipher: %w", err)
	}
	ib, err := aes.NewCipher(inEncr)
	if err != nil {
		return nil, fmt.Errorf("esp: inbound cipher: %w", err)
	}
	return &SA{
		outSPI:   outSPI,
		inSPI:    inSPI,
		outBlock: ob,
		inBlock:  ib,
		outInteg: append([]byte(nil), outInteg...),
		inInteg:  append([]byte(nil), inInteg...),
		replay:   NewReplayWindow(replayWindow),
	}, nil
}

// OutSPI / InSPI expose the SA's SPIs for demux and DELETE.
func (sa *SA) OutSPI() uint32 { return sa.outSPI }
func (sa *SA) InSPI() uint32  { return sa.inSPI }

// Seq returns the last outbound sequence number used (for rekey heuristics).
func (sa *SA) Seq() uint32 { return sa.seq.Load() }

// Encrypt wraps one inner IP datagram (IPv4 or IPv6) in an ESP packet (RFC 4303
// tunnel mode): SPI | Seq | IV | AES-CBC(inner | pad | padLen | nextHdr) | ICV.
func (sa *SA) Encrypt(inner []byte) ([]byte, error) {
	// Allocate the next sequence number with a CAS loop so concurrent Encrypt
	// callers can never observe the same value: a two-step Add+Store could let a
	// second goroutine read the wrapped 0 before the pin lands. First packet is
	// sequence 1; 0 is never emitted, and once the counter reaches 2^32-1 it
	// stays pinned (exhausted) until the SA is replaced (RFC 4303 §3.3.3).
	var seq uint32
	for {
		cur := sa.seq.Load()
		if cur == ^uint32(0) {
			return nil, ErrSeqExhausted
		}
		seq = cur + 1
		if sa.seq.CompareAndSwap(cur, seq) {
			break
		}
	}

	// RFC 4303 §2.4 padding: monotonic 1,2,3,... so that the plaintext
	// (inner | pad | padLen(1) | nextHdr(1)) is a multiple of the block size.
	padLen := (espBlock - (len(inner)+2)%espBlock) % espBlock
	plainLen := len(inner) + padLen + 2

	out := make([]byte, espHeaderLen+espIVLen+plainLen+espICVLen)
	binary.BigEndian.PutUint32(out[0:4], sa.outSPI)
	binary.BigEndian.PutUint32(out[4:8], seq)

	iv := out[espHeaderLen : espHeaderLen+espIVLen]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Assemble plaintext in place at the ciphertext position, then encrypt it.
	ctStart := espHeaderLen + espIVLen
	plain := out[ctStart : ctStart+plainLen]
	copy(plain, inner)
	for i := range padLen {
		plain[len(inner)+i] = byte(i + 1)
	}
	plain[plainLen-2] = byte(padLen)
	// Next Header reflects the inner packet's IP version (RFC 4303 tunnel mode):
	// IPv6 (41) for a 0x6x datagram, IPv4 (4) otherwise. The peer's de-encapsulator
	// routes the decrypted inner packet by this field, so a v6 datagram mislabeled
	// as v4 is dropped at the far end (a one-way inner-IPv6 black hole).
	nextHdr := byte(nextHeaderIPv4)
	if len(inner) > 0 && inner[0]>>4 == 6 {
		nextHdr = nextHeaderIPv6
	}
	plain[plainLen-1] = nextHdr
	cipher.NewCBCEncrypter(sa.outBlock, iv).CryptBlocks(plain, plain)

	// ICV over SPI | Seq | IV | ciphertext.
	mac := hmac.New(sha256.New, sa.outInteg)
	mac.Write(out[:ctStart+plainLen])
	icv := mac.Sum(nil)[:espICVLen]
	copy(out[ctStart+plainLen:], icv)
	return out, nil
}

// Decrypt verifies and decrypts an inbound ESP packet, returning the inner IP
// datagram (IPv4 or IPv6). The returned slice is freshly allocated.
func (sa *SA) Decrypt(pkt []byte) ([]byte, error) {
	if len(pkt) < espHeaderLen+espIVLen+espBlock+espICVLen {
		return nil, errors.New("esp: packet too short")
	}
	if spi := binary.BigEndian.Uint32(pkt[0:4]); spi != sa.inSPI {
		return nil, fmt.Errorf("esp: unknown SPI %08x", spi)
	}
	seq := binary.BigEndian.Uint32(pkt[4:8])

	// Verify ICV before doing anything else with the contents.
	icvStart := len(pkt) - espICVLen
	mac := hmac.New(sha256.New, sa.inInteg)
	mac.Write(pkt[:icvStart])
	if !hmac.Equal(mac.Sum(nil)[:espICVLen], pkt[icvStart:]) {
		return nil, errors.New("esp: ICV verification failed")
	}
	if !sa.replay.Accept(seq) {
		return nil, ErrReplay
	}

	iv := pkt[espHeaderLen : espHeaderLen+espIVLen]
	ct := pkt[espHeaderLen+espIVLen : icvStart]
	if len(ct) == 0 || len(ct)%espBlock != 0 {
		return nil, errors.New("esp: ciphertext not block-aligned")
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(sa.inBlock, iv).CryptBlocks(plain, ct)

	padLen := int(plain[len(plain)-2])
	if padLen+2 > len(plain) {
		return nil, errors.New("esp: pad length out of range")
	}
	// RFC 4303 §2.4: the pad octets must be the monotonic sequence 1,2,...,padLen.
	// The ICV verified above already proves authenticity, so this is a defense-in-
	// depth / spec-conformance check against a buggy or tampering (key-holding)
	// sender rather than a guard against an unauthenticated attacker.
	for i, b := range plain[len(plain)-2-padLen : len(plain)-2] {
		if int(b) != i+1 {
			return nil, errors.New("esp: malformed self-describing padding")
		}
	}
	// plain[len-1] is NextHeader; for tunnel mode accept only IPv4 (4) and IPv6
	// (41) so a peer-controlled payload of any other protocol is rejected rather
	// than handed up to the netstack as if it were an IP datagram.
	if nh := plain[len(plain)-1]; nh != nextHeaderIPv4 && nh != nextHeaderIPv6 {
		return nil, fmt.Errorf("esp: unexpected next header %d", nh)
	}
	inner := plain[:len(plain)-padLen-2]
	return append([]byte(nil), inner...), nil
}
