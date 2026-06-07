package ipsec

import (
	"fmt"
	"net/netip"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

// IDKind is an IKEv2 Identification payload type (RFC 7296 §3.5).
type IDKind uint8

const (
	IDKindNone  IDKind = 0
	IDKindIPv4  IDKind = IDKind(ikemsg.IDTypeIPv4)
	IDKindFQDN  IDKind = IDKind(ikemsg.IDTypeFQDN)
	IDKindEmail IDKind = IDKind(ikemsg.IDTypeRFC822)
	IDKindIPv6  IDKind = IDKind(ikemsg.IDTypeIPv6)
	IDKindKeyID IDKind = IDKind(ikemsg.IDTypeKeyID)
)

// Identity is an IKE identity (IDi or IDr). The zero value is "unset"; for IDr
// that means accept whatever the server presents (subject to certificate trust).
type Identity struct {
	Kind IDKind
	Data []byte
}

// FQDN builds an ID_FQDN identity.
func FQDN(name string) Identity { return Identity{Kind: IDKindFQDN, Data: []byte(name)} }

// Email builds an ID_RFC822_ADDR identity.
func Email(addr string) Identity { return Identity{Kind: IDKindEmail, Data: []byte(addr)} }

// KeyID builds an ID_KEY_ID identity from opaque bytes.
func KeyID(id []byte) Identity { return Identity{Kind: IDKindKeyID, Data: append([]byte(nil), id...)} }

// IPv4 builds an ID_IPV4_ADDR identity. A non-IPv4 (or zero) addr yields the
// unset zero Identity rather than panicking; validate() then rejects it with a
// clear config-time error.
func IPv4(addr netip.Addr) Identity {
	addr = addr.Unmap()
	if !addr.Is4() {
		return Identity{}
	}
	a4 := addr.As4()
	return Identity{Kind: IDKindIPv4, Data: a4[:]}
}

// IsZero reports whether the identity is unset.
func (id Identity) IsZero() bool { return id.Kind == IDKindNone }

// String renders the identity for logging.
func (id Identity) String() string {
	switch id.Kind {
	case IDKindNone:
		return "<unset>"
	case IDKindIPv4, IDKindIPv6:
		if a, ok := netip.AddrFromSlice(id.Data); ok {
			return a.String()
		}
		return fmt.Sprintf("ip:%x", id.Data)
	case IDKindKeyID:
		return fmt.Sprintf("keyid:%x", id.Data)
	default:
		return string(id.Data)
	}
}

// idType / idData expose the wire fields for building Identification payloads.
func (id Identity) idType() uint8  { return uint8(id.Kind) }
func (id Identity) idData() []byte { return id.Data }

// identityFromWire reconstructs an Identity from a decoded Identification
// payload's type and data.
func identityFromWire(idType uint8, data []byte) Identity {
	return Identity{Kind: IDKind(idType), Data: append([]byte(nil), data...)}
}
