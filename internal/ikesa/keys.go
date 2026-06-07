package ikesa

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
)

// Role identifies which end of the IKE SA this client plays. go-ipsec is
// initiator-only, but the role still selects the correct directional keys and
// makes the encrypt/decrypt round-trip testable from both ends.
type Role int

const (
	Initiator Role = iota
	Responder
)

// keyPad is the constant string mixed into shared-secret AUTH (RFC 7296 §2.15).
var keyPad = []byte("Key Pad for IKEv2")

// IKESA holds the derived IKE SA key material and the directional crypto state
// for the SK{} envelope.
type IKESA struct {
	Role         Role
	InitiatorSPI uint64
	ResponderSPI uint64

	SKd  []byte // child-SA key-derivation key
	SKai []byte // integrity, initiator → responder
	SKar []byte // integrity, responder → initiator
	SKei []byte // encryption, initiator → responder
	SKer []byte // encryption, responder → initiator
	SKpi []byte // AUTH, initiator
	SKpr []byte // AUTH, responder
}

// Derive runs the RFC 7296 §2.14 key schedule:
//
//	SKEYSEED = prf(Ni | Nr, g^ir)
//	{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
//	        = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
//
// nonceI/nonceR are the initiator/responder nonces, dhShared the MODP-2048
// shared secret, and spii/spir the negotiated SPIs.
func (s *IKESA) Derive(role Role, spii, spir uint64, nonceI, nonceR, dhShared []byte) error {
	if len(nonceI) == 0 || len(nonceR) == 0 {
		return errors.New("ikesa: empty nonce")
	}
	if len(dhShared) == 0 {
		return errors.New("ikesa: empty DH shared secret")
	}
	// Initial SKEYSEED = prf(Ni | Nr, g^ir) (RFC 7296 §2.14).
	skeyseed := prf(concat(nonceI, nonceR), dhShared)
	s.deriveFromSKEYSEED(role, spii, spir, nonceI, nonceR, skeyseed)
	return nil
}

// DeriveRekeyIKE derives a new IKE SA during a CREATE_CHILD_SA IKE-SA rekey
// (RFC 7296 §2.18):
//
//	SKEYSEED = prf(SK_d (old SA), g^ir (new) | Ni | Nr)
//	{SK_d | ... | SK_pr} = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)   (new SPIs)
//
// oldSKd is the SK_d of the IKE SA being rekeyed.
func DeriveRekeyIKE(oldSKd []byte, role Role, spii, spir uint64, nonceI, nonceR, dhShared []byte) (*IKESA, error) {
	if len(oldSKd) == 0 {
		return nil, errors.New("ikesa: empty old SK_d")
	}
	if len(nonceI) == 0 || len(nonceR) == 0 || len(dhShared) == 0 {
		return nil, errors.New("ikesa: empty rekey input")
	}
	seed := make([]byte, 0, len(dhShared)+len(nonceI)+len(nonceR))
	seed = append(seed, dhShared...)
	seed = append(seed, nonceI...)
	seed = append(seed, nonceR...)
	skeyseed := prf(oldSKd, seed)

	s := &IKESA{}
	s.deriveFromSKEYSEED(role, spii, spir, nonceI, nonceR, skeyseed)
	return s, nil
}

// deriveFromSKEYSEED expands SKEYSEED into the SK_* set, shared by the initial
// and rekey derivations.
func (s *IKESA) deriveFromSKEYSEED(role Role, spii, spir uint64, nonceI, nonceR, skeyseed []byte) {
	s.Role = role
	s.InitiatorSPI = spii
	s.ResponderSPI = spir

	seed := make([]byte, 0, len(nonceI)+len(nonceR)+16)
	seed = append(seed, nonceI...)
	seed = append(seed, nonceR...)
	seed = appendUint64(seed, spii)
	seed = appendUint64(seed, spir)

	total := prfKeyLen + 2*integKeyLen + 2*encrKeyLen + 2*prfKeyLen
	ks := prfPlus(skeyseed, seed, total)

	var off int
	// Copy each key into its own slice rather than aliasing the shared prf+
	// output buffer, so an in-place mutation of one key can never corrupt an
	// adjacent one (mirrors DeriveChildKeys in child.go).
	take := func(n int) []byte {
		b := make([]byte, n)
		copy(b, ks[off:off+n])
		off += n
		return b
	}
	s.SKd = take(prfKeyLen)
	s.SKai = take(integKeyLen)
	s.SKar = take(integKeyLen)
	s.SKei = take(encrKeyLen)
	s.SKer = take(encrKeyLen)
	s.SKpi = take(prfKeyLen)
	s.SKpr = take(prfKeyLen)
}

// outboundIntegKey / inboundIntegKey / outboundEncrKey / inboundEncrKey select
// the directional key for this role.
func (s *IKESA) outboundIntegKey() []byte {
	if s.Role == Initiator {
		return s.SKai
	}
	return s.SKar
}

func (s *IKESA) inboundIntegKey() []byte {
	if s.Role == Initiator {
		return s.SKar
	}
	return s.SKai
}

func (s *IKESA) outboundEncrKey() []byte {
	if s.Role == Initiator {
		return s.SKei
	}
	return s.SKer
}

func (s *IKESA) inboundEncrKey() []byte {
	if s.Role == Initiator {
		return s.SKer
	}
	return s.SKei
}

// EncryptToSK encrypts plaintext (the concatenated inner IKE payloads) into the
// body of an Encrypted (SK{}) payload: IV || AES-CBC(plaintext | pad | padlen)
// || zeroed-ICV. The ICV bytes are a placeholder; call Checksum on the fully
// encoded message to fill them in.
func (s *IKESA) EncryptToSK(plaintext []byte) ([]byte, error) {
	// RFC 7296 §3.14 self-describing padding: append padLen pad octets then a
	// one-octet Pad Length, making the total a multiple of the block size.
	padLen := (aesBlock - (len(plaintext)+1)%aesBlock) % aesBlock
	padded := make([]byte, 0, len(plaintext)+padLen+1)
	padded = append(padded, plaintext...)
	for i := 1; i <= padLen; i++ {
		padded = append(padded, byte(i))
	}
	padded = append(padded, byte(padLen))

	ivCT, err := aesCBCEncrypt(s.outboundEncrKey(), padded)
	if err != nil {
		return nil, err
	}
	return append(ivCT, make([]byte, integICVLen)...), nil
}

// DecryptSK reverses EncryptToSK for an inbound SK{} body. The caller MUST have
// already verified the message ICV (VerifyChecksum) before calling this.
func (s *IKESA) DecryptSK(skData []byte) ([]byte, error) {
	if len(skData) < integICVLen+aesBlock {
		return nil, errors.New("ikesa: SK payload too short")
	}
	ivCT := skData[:len(skData)-integICVLen]
	padded, err := aesCBCDecrypt(s.inboundEncrKey(), ivCT)
	if err != nil {
		return nil, err
	}
	padLen := int(padded[len(padded)-1])
	if padLen+1 > len(padded) {
		return nil, errors.New("ikesa: SK pad length out of range")
	}
	return padded[:len(padded)-padLen-1], nil
}

// Checksum computes the message ICV over msg[:len-ICV] with the outbound
// integrity key and writes it into the trailing ICV bytes in place. msg is the
// fully encoded IKE message whose last integICVLen bytes are the ICV field.
func (s *IKESA) Checksum(msg []byte) error {
	if len(msg) < integICVLen {
		return errors.New("ikesa: message shorter than ICV")
	}
	mac := integ(s.outboundIntegKey(), msg[:len(msg)-integICVLen])
	copy(msg[len(msg)-integICVLen:], mac)
	return nil
}

// VerifyChecksum recomputes the ICV over an inbound message with the inbound
// integrity key and constant-time compares it to the trailing ICV field.
func (s *IKESA) VerifyChecksum(msg []byte) bool {
	if len(msg) < integICVLen {
		return false
	}
	want := msg[len(msg)-integICVLen:]
	got := integ(s.inboundIntegKey(), msg[:len(msg)-integICVLen])
	return hmac.Equal(want, got)
}

// PRF exposes the negotiated PRF for the AUTH machinery (signed octets).
func (s *IKESA) PRF(key, data []byte) []byte { return prf(key, data) }

// AuthMAC computes a shared-secret AUTH value per RFC 7296 §2.15:
//
//	AUTH = prf( prf(secret, "Key Pad for IKEv2"), signedOctets )
//
// For EAP methods that derive an MSK, secret is the 64-byte EAP-MSK.
func (s *IKESA) AuthMAC(secret, signedOctets []byte) []byte {
	inner := prf(secret, keyPad)
	return prf(inner, signedOctets)
}

// ICVLen reports the integrity check value length of the negotiated suite.
func (s *IKESA) ICVLen() int { return integICVLen }

// concat returns a || b in a fresh slice.
func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

func appendUint64(b []byte, v uint64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	return append(b, tmp[:]...)
}
