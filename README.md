# go-ipsec

Pure-Go **userspace** IKEv2 + ESP VPN client. No kernel XFRM, no `strongSwan`
daemon, no `TUN` device, no root — the IKEv2 control plane and the ESP data plane
run entirely in-process and expose the tunnel as a plain
`DialContext(ctx, network, addr) (net.Conn, error)`.

```
your code ──DialContext──▶ go-ipsec ──IKEv2/ESP (userspace)──▶ VPN server ──▶ internet
```

It was built to consume IKEv2-EAP-MSCHAPv2 realms that `mihomo`/`sing-box` cannot speak,
and to route them into proxy-service rotation via a SOCKS5 sidecar
([`ipsec2socks`](cmd/ipsec2socks/README.md)) or a `mihomo` injectable transport.

## Table of contents

- [Status](#status)
- [Why](#why)
- [Install](#install)
- [Usage](#usage)
  - [As a library](#as-a-library)
  - [As a SOCKS5 sidecar](#as-a-socks5-sidecar)
- [Configuration](#configuration)
- [Cipher suite](#cipher-suite)
- [Identities](#identities)
- [DNS through the tunnel](#dns-through-the-tunnel)
- [Lifecycle](#lifecycle)
- [Architecture](#architecture)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Hardening: key-material erasure](#hardening-key-material-erasure)
- [Limitations](#limitations)
- [License](#license)

## Status

**Working** for IKEv2 with **EAP-MSCHAPv2** or **pre-shared key (PSK)**
authentication, over the fixed transform suite (AES-CBC-256 / PRF-HMAC-SHA2-256 /
AUTH-HMAC-SHA2-256-128 / DH x25519 group 31, preferred, or MODP-2048 group 14,
fallback). Implemented and exercised end-to-end:

- **IKE_SA_INIT** + **IKE_AUTH** with either EAP-MSCHAPv2 (certificate-chain +
  AUTH payload verification) or a pre-shared key (single-round mutual AUTH, no
  certificate).
- **NAT-T** — UDP-encapsulation on port 4500 (mandatory: a userspace client
  cannot send raw ESP), with NAT detection at IKE_SA_INIT.
- A userspace **ESP data plane** — RFC 4303 framing with RFC 6479 anti-replay.
- **DPD** (Dead Peer Detection) over empty `INFORMATIONAL` exchanges, counting
  data-plane liveness so a tunnel busy on ESP but quiet on IKE is not torn down.
- **CHILD_SA and IKE_SA rekey** (`CREATE_CHILD_SA`) with a make-before-break,
  zero-loss cutover — both initiator- and responder-initiated, with optional
  per-Child PFS.
- **Graceful `DELETE`** on shutdown.
- **In-place auto-reconnect** when the IKE SA dies (e.g. a NAT mapping that
  expired during a laptop sleep): the tunnel redials on a fresh socket and
  re-addresses the existing netstack, so a long-lived `client.DialContext` binding
  stays valid. Set `Config.AutoReconnect` to a pointer to `false` for the legacy
  close-on-death behaviour.
- **Dual-stack inner IPv6** — requests `INTERNAL_IP6_ADDRESS` via CFG and offers
  `::/0` traffic selectors so v6 application traffic rides ESP. Enabled by
  default; set `Config.RequestIPv6` to a pointer to `false` for strict v4-only
  appliances (a v4-only server simply assigns no v6 address and the tunnel stays
  v4).
- The [`ipsec2socks`](cmd/ipsec2socks/README.md) SOCKS5 sidecar.

Every crypto path is gated by RFC known-answer tests; the full handshake, data
plane and rekey cutover are exercised offline (scripted in-memory responder,
two-stack ESP loopback) with zero live dials; and the whole stack is verified
end-to-end against a real **strongSwan** server (`test/strongswan/`): HTTP GET
exit-IP == server egress, an inner-IPv6 TCP round-trip completes over ESP,
client-initiated Child + IKE rekey survive a live `curl` loop, and Ctrl-C drives a
graceful `DELETE`.

**Not yet implemented:** SOCKS5 UDP ASSOCIATE. See [Limitations](#limitations).

## Why

Most IKEv2 stacks live in the kernel (XFRM) or behind a `strongSwan`/`charon`
daemon, which means root, a `TUN` device, and out-of-process configuration. Proxy
routers like `mihomo`/`sing-box` speak many protocols but not IKEv2-EAP-MSCHAPv2,
so realms that only offer that handshake are unreachable from them.

go-ipsec runs the whole thing — IKE negotiation, key derivation, ESP
encrypt/decrypt, anti-replay, rekey — in userspace, in your process, with no
privileges. The tunnel surfaces as an ordinary `net.Conn` dialer that drops
straight into any Go program or proxy router.

## Install

```sh
go get github.com/n0madic/go-ipsec
```

Requires Go 1.26+. The SOCKS5 sidecar:

```sh
go install github.com/n0madic/go-ipsec/cmd/ipsec2socks@latest
# or, from a checkout:
make bin            # → bin/ipsec2socks
```

## Usage

### As a library

```go
client, err := ipsec.Dial(ctx, ipsec.Config{
    Server:   "vpn.example.com:500",
    LocalID:  ipsec.Email("user@example.com"),
    EAP:      ipsec.EAPMSCHAPv2{Username: "user", Password: "secret"},
    RootCAs:  pool, // trust anchors for the server chain; nil = system roots
})
if err != nil {
    log.Fatal(err)
}
defer client.Close()

conn, err := client.DialContext(ctx, "tcp", "93.184.216.34:80") // literal IP
```

To authenticate with a **pre-shared key** instead of EAP, set `PSK` and leave
`EAP` unset. No server certificate is involved, so `RootCAs` is unused; the IKE
identities come from `LocalID` (IDi) and `RemoteID` (IDr):

```go
client, err := ipsec.Dial(ctx, ipsec.Config{
    Server:   "vpn.example.com:500",
    LocalID:  ipsec.FQDN("client.example.com"), // IDi
    RemoteID: ipsec.FQDN("vpn.example.com"),     // expected IDr (optional)
    PSK:      "a-strong-preshared-key",
})
```

`Dial` blocks until the first Child SA is installed (IKE_SA_INIT → IKE_AUTH →
CHILD_SA) or `ctx` is cancelled. After it returns, the tunnel is self-maintaining:
DPD, rekey and auto-reconnect all run on background goroutines until `Close`.

`client.DialContext` requires a **literal IP**. To resolve names through the
tunnel, get a `*net.Resolver`:

```go
res := client.Resolver("") // "" = responder-pushed DNS (v4, then v6), else 1.1.1.1
ips, err := res.LookupHost(ctx, "example.com")
```

Other handles on `*Client`:

| Method | Returns |
|---|---|
| `DialContext(ctx, net, addr)` | `net.Conn` through the tunnel (literal IP). |
| `Resolver(server)` | `*net.Resolver` that queries DNS over the tunnel. |
| `Net()` | the internal `*tun2net.Net` stack. |
| `Tunnel()` | the raw `PacketTunnel` for wiring a custom `go-tun2net` stack. |
| `LocalIP()` / `LocalIP6()` | the inner v4 address / v6 prefix the responder assigned. |
| `DNS()` / `DNS6()` | the responder-pushed v4 / v6 resolver addresses. |
| `OnRekey(fn)` | register a callback fired after every successful rekey. |
| `RxDrops()` | count of inbound ESP packets dropped by decrypt/replay failures. |
| `Close()` | graceful `DELETE` + full teardown. |

Advanced consumers can wire their own `go-tun2net` stack with
`tun2net.New(client.Tunnel(), logger)` instead of using `DialContext`. Do not mix
the two over the same `Client`.

### As a SOCKS5 sidecar

`ipsec2socks` is a thin frontend over this library: it dials the VPN, brings up
the userspace ESP tunnel, and exposes it as a local SOCKS5 proxy, so any
SOCKS-aware program (`curl`, browsers, `mihomo`/`sing-box`, scrapers) can route
traffic through the VPN with no root and no `TUN` device.

```sh
ipsec2socks -server vpn.example.com:500 -ca ca.pem \
  -eap-user user -eap-pass secret -listen 127.0.0.1:1080

curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

With a pre-shared key instead of EAP (mutually exclusive with `-eap-*`):

```sh
ipsec2socks -server vpn.example.com:500 -psk 'a-strong-preshared-key' \
  -local-id client.example.com -listen 127.0.0.1:1080
```

> Use `--socks5-hostname` (not `--socks5`) so the hostname is resolved through
> the tunnel and DNS does not leak.

See **[`cmd/ipsec2socks/README.md`](cmd/ipsec2socks/README.md)** for the full
flag reference, credential handling, security notes, and lifecycle details.

## Configuration

The `Config` struct passed to `ipsec.Dial`:

| Field | Type | Default | Description |
|---|---|---|---|
| `Server` | `string` | *(required)* | Responder endpoint `host:port`; port defaults to 500. |
| `LocalID` | `Identity` | unset | Local IKE identity (IDi) announced to the server. |
| `RemoteID` | `Identity` | unset | Expected server identity (IDr); when set, also matched against the certificate SANs. |
| `EAP` | `EAPMSCHAPv2` | *(one-of)* | `{Username, Password}` for EAP-MSCHAPv2. Set this **or** `PSK`. |
| `PSK` | `string` | *(one-of)* | Pre-shared key for PSK auth (RFC 7296 §2.15). Set this **or** `EAP`. |
| `RootCAs` | `*x509.CertPool` | system roots | Trust anchors for the server certificate chain (EAP only; unused with PSK). |
| `Transport` | `PacketDialer` | host UDP | Injects the underlying packet socket (e.g. for `mihomo`). |
| `MTU` | `uint32` | `1400` | Inner tunnel MTU hint (clamped by the data plane). |
| `Logger` | `*slog.Logger` | discard | Structured diagnostics sink. |
| `KeepAlive` | `time.Duration` | `20s` | NAT-keepalive interval. |
| `DPDTimeout` | `time.Duration` | `30s` | Dead Peer Detection interval. |
| `RekeyLifetime` | `time.Duration` | `1h` | Child SA soft lifetime. |
| `IKERekeyLifetime` | `time.Duration` | `4h` | IKE SA soft lifetime. |
| `ReplayWindow` | `uint32` | `64` | Anti-replay window size (bits). |
| `RekeyMaxPackets` | `uint32` | `2^31` | Child SA rekey trigger by outbound ESP sequence number; floored to `4096` when non-zero. |
| `ChildSAPFS` | `bool` | `false` | Offer per-Child PFS (fresh MODP-2048 DH) on client-initiated Child rekeys. |
| `RequestIPv6` | `*bool` | enabled | Request inner IPv6 + offer `::/0` selectors. Pointer to `false` = strict v4-only. |
| `AutoReconnect` | `*bool` | enabled | Redial in place on peer death. Pointer to `false` = legacy close-on-death. |
| `ReconnectBackoffBase` | `time.Duration` | `1s` | Initial redial backoff. |
| `ReconnectBackoffMax` | `time.Duration` | `30s` | Capped redial backoff. |
| `ReconnectAttemptTimeout` | `time.Duration` | `20s` | Per-attempt redial timeout. |

Authentication is **one-of**: set `EAP` (username + password) **or** `PSK`, never
both — supplying both, or neither, is a config-time error.

Duration knobs default when `<= 0`. `RequestIPv6` and `AutoReconnect` are
tri-state pointers: `nil` or a pointer to `true` enables the feature; only a
pointer to `false` disables it.

## Cipher suite

The suite is **fixed and not configurable**, negotiated at IKE_SA_INIT:

| Role | Algorithm |
|---|---|
| Encryption | AES-CBC-256 |
| PRF | HMAC-SHA2-256 |
| Integrity | AUTH-HMAC-SHA2-256-128 |
| DH group | x25519 (group 31, preferred) or MODP-2048 (group 14, fallback) |

The Child SA reuses AES-CBC-256 + HMAC-SHA2-256-128. Per-Child PFS, when offered,
uses a fresh MODP-2048 (group 14) exchange.

## Identities

IKE identities are built with the `Identity` constructors:

```go
ipsec.Email("user@example.com") // ID_RFC822_ADDR
ipsec.FQDN("vpn.example.com")   // ID_FQDN
ipsec.IPv4(netip.MustParseAddr("203.0.113.4")) // ID_IPV4_ADDR
ipsec.IPv6(netip.MustParseAddr("2001:db8::4")) // ID_IPV6_ADDR
ipsec.KeyID([]byte{0xde, 0xad})  // ID_KEY_ID
```

The zero `Identity` is "unset". For `RemoteID` (IDr) that means "accept whatever
the server presents", subject to certificate trust. With EAP-MSCHAPv2 the real
client identity is the EAP username; an unset `LocalID` defaults to an identity
derived from it (`ID_RFC822_ADDR` when the username contains `@`, `ID_FQDN`
otherwise).

With **PSK** there is no EAP username, so `LocalID` (IDi) and `RemoteID` (IDr)
carry the IKE identities directly. PSK gateways select the key by the IDi, so
`LocalID` is required; `RemoteID`, when set, is the IDr the server must present.

`IPv4`/`IPv6` fed a wrong-family or zero address return an invalid `Identity`
that `Dial` rejects with a config-time error (never a deep handshake failure).

## DNS through the tunnel

`client.Resolver(server)` returns a `*net.Resolver` whose queries go over the
tunnel as UDP datagrams (`go-tun2net` exposes its UDP conns as `net.PacketConn`,
so Go's resolver picks datagram framing without an adapter). With an empty
`server` it selects the responder-pushed DNS — the IPv4 resolver first, then the
IPv6 one (so a v6-only assignment is honoured), falling back to `1.1.1.1:53`.

## Lifecycle

Once dialed, the `Client` maintains the tunnel automatically:

- **NAT-keepalive** — keeps the UDP-4500 mapping alive every `KeepAlive`.
- **DPD** — empty `INFORMATIONAL` probes every `DPDTimeout`; the peer is declared
  dead only when both IKE *and* the ESP data plane go quiet.
- **Rekey** — Child and IKE SAs are rekeyed before their soft lifetime with a
  make-before-break cutover; in-flight connections survive. A superseded inbound
  Child SA lingers for a 30s grace window so packets the peer sent before
  switching still decrypt (zero-loss). Server-initiated rekeys are answered too.
- **Auto-reconnect** — on peer death the supervisor stops the dead generation,
  redials with capped exponential backoff on a fresh socket (re-punching the NAT
  mapping), re-addresses the netstack in place, and restarts the workers — all
  transparent to existing `DialContext` bindings.
- **Graceful shutdown** — `Close` cancels the supervisor, sends an IKE `DELETE`
  while the socket is still open, then tears down the netstack, tunnel, grace
  timers and session.

## Architecture

The tunnel is split into a control plane (IKEv2) and a data plane (ESP), bridged
by a userspace `PacketTunnel` into a `go-tun2net` netstack:

```
                         ┌────────────────────────────────────────────┐
   DialContext / Resolver│            go-tun2net netstack             │
        ─────────────────▶  (gVisor TCP/IP, inner v4 + v6 dual-stack) │
                         └───────────────────┬────────────────────────┘
                                             │ IP packets
                                  ┌──────────▼───────────┐
                                  │   PacketTunnel       │  internal/tunnel
                                  │ (ESP encrypt/decrypt,│  internal/esp
                                  │  RFC 6479 replay)    │
                                  └──────────┬───────────┘
                          ESP-in-UDP (4500)  │  ▲ inbound ESP demux by SPI
                                  ┌──────────▼──┴────────┐
   IKE_SA_INIT / IKE_AUTH /       │   IKE session        │  internal/session
   INFORMATIONAL / rekey   ◀──────▶ (state machine, EAP, │  internal/ikesa
                                  │  AUTH, NAT-T, rekey) │  internal/eap
                                  └──────────┬───────────┘  internal/auth
                                             │ UDP 500 / 4500
                                  ┌──────────▼───────────┐
                                  │   UDP transport      │  internal/transport
                                  └──────────┬───────────┘  internal/natt
                                             ▼
                                        VPN server
```

- The **session** drives the IKE handshake and all subsequent protected
  exchanges; on a successful IKE_AUTH it yields the first Child SA.
- The **data plane** (`dataplane.go`) builds an `esp.SA` from the Child keys and a
  `PacketTunnel` that encrypts outbound IP packets and demuxes inbound ESP by SPI
  (both old and new SPIs are live during a rekey cutover).
- A **supervisor** goroutine (`reconnect.go`) owns generation swaps: it is the
  sole writer of the worker manager and session pointer between reconnects, so
  hot-path readers load the live session lock-free.

## Project layout

| Path | Responsibility |
|---|---|
| `ipsec.go`, `config.go`, `identity.go`, `resolver.go` | Public API: `Client`, `Config`, identities, resolver. |
| `dataplane.go`, `reconnect.go` | ESP data-plane wiring and the reconnect supervisor. |
| `internal/ikemsg` | IKEv2 message + payload codec (own implementation). |
| `internal/ikesa` | IKE SA crypto: DH (x25519/MODP), key derivation, Child SA keys. |
| `internal/eap` | EAP-MSCHAPv2 and MSK derivation. |
| `internal/auth` | AUTH payload (shared-key + certificate) + certificate-chain verification. |
| `internal/esp` | ESP framing (RFC 4303) + anti-replay window (RFC 6479). |
| `internal/session` | IKE session state machine: init, auth, informational, rekey, NAT-T. |
| `internal/natt` | NAT-T detection and UDP encapsulation. |
| `internal/transport` | UDP and in-memory packet transports. |
| `internal/tunnel` | `PacketTunnel` bridging ESP ↔ netstack. |
| `internal/workers` | Per-generation goroutine lifecycle manager. |
| `cmd/ipsec2socks` | SOCKS5 sidecar CLI — [README](cmd/ipsec2socks/README.md). |
| `test/strongswan` | Throwaway Dockerized strongSwan server for live interop. |
| `test/integration` | Build-tagged (`e2e_server`) live tests. |

## Testing

The `Makefile` is the entry point — run `make help` for the full list.

```sh
make test        # offline test suite (Go toolchain only)
make test-race   # offline suite under -race
make cover       # offline suite + coverage summary
make vet         # go vet, including the e2e package
```

The offline suite is hermetic: RFC known-answer tests for every crypto path, a
scripted in-memory IKE responder, and a two-stack ESP loopback exercise the full
handshake, data plane and rekey cutover with zero network access.

Live interop runs against a Dockerized strongSwan server configured to negotiate
exactly the suite go-ipsec implements:

```sh
make e2e         # start strongSwan, run live tests, always tear down
# or step by step:
make e2e-up      # build & start the server, wait until ready
make e2e-test    # run the e2e_server-tagged live tests
make e2e-down    # stop and remove the server
```

See [`test/strongswan/README.md`](test/strongswan/README.md) for running the
server by hand, exercising the lifecycle (DPD, rekey, graceful DELETE), and
capturing packets.

## Hardening: key-material erasure

Every key derivation (IKE SK_\*, ESP keys, DH private keys and shared secrets,
the EAP MSK and MSCHAPv2 password hashes) runs through a thin seam over the
experimental [`runtime/secret`](https://pkg.go.dev/runtime/secret) package.
Build with the experiment enabled and the runtime erases that key material —
registers, stack, and the heap allocations holding the keys — as soon as the
GC finds it unreachable (e.g. the old SA's keys right after a rekey, or
everything on teardown):

```sh
GOEXPERIMENT=runtimesecret go build ./...
make test-secret   # offline suite with the experiment enabled
```

Erasure is effective on **linux/amd64 and linux/arm64** (Go 1.26+); on other
platforms, and in the default build, the seam compiles to a direct call with
no overhead and no erasure guarantee. Caller-provided secrets (`Config.PSK`,
the EAP password string) are allocated outside the seam and are not tracked.

## Limitations

- **SOCKS5 UDP ASSOCIATE** is not implemented (the sidecar is TCP `CONNECT`
  only; no `BIND` either).
- **NAT-T is mandatory** — a userspace client cannot send raw ESP, so traffic is
  always UDP-encapsulated on port 4500.
- The **cipher suite is fixed** (see [Cipher suite](#cipher-suite)); there is no
  algorithm negotiation knob.
- **Initiator only** — go-ipsec dials out; it is not an IKEv2 responder.
- **No certificate revocation checking** — the server chain is verified for
  trust, expiry, EKU, and SAN/identity match, but OCSP and CRLs are not
  consulted (a common limitation among IKE clients). Pin a dedicated CA via
  `RootCAs` to narrow the exposure.
- Inner IPv6 delivery against mixed-family servers has a known strongSwan-side
  limitation; a v4-only server stays v4 transparently.

## License

MIT.
