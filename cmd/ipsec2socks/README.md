# ipsec2socks

A single-tunnel SOCKS5 sidecar for [go-ipsec](../../README.md). It dials an
**IKEv2** VPN server (authenticating with **EAP-MSCHAPv2** or a **pre-shared
key**), brings up the userspace ESP tunnel, and exposes it as a local **SOCKS5**
proxy — so any SOCKS-aware program (`curl`,
browsers, mihomo/sing-box, scrapers) can route traffic through the VPN with no
root, no kernel TUN device, and no strongSwan daemon.

```
client app ──SOCKS5──▶ ipsec2socks ──IKEv2/ESP(userspace)──▶ VPN server ──▶ internet
```

## Build

```sh
make bin                       # → bin/ipsec2socks
# or
go build -o ipsec2socks ./cmd/ipsec2socks
# or run directly
go run ./cmd/ipsec2socks -server vpn.example.com -ca ca.pem ...
```

## Quick start

```sh
export IPSEC_EAP_USER=alice
export IPSEC_EAP_PASS=s3cret

ipsec2socks \
  -server    vpn.example.com \
  -ca        ca.pem \
  -remote-id vpn.example.com \
  -listen    127.0.0.1:1080

# in another shell — note --socks5-hostname so DNS is resolved through the tunnel:
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

The proxy stays up until you press **Ctrl-C**, which sends a graceful IKE
`DELETE` and exits. A second Ctrl-C (or 5s) force-quits.

## Flags

| Flag | Default | Description |
|---|---|---|
| `-server` | *(required)* | VPN server `host[:port]` (port defaults to 500). |
| `-eap-user` | `$IPSEC_EAP_USER` | EAP-MSCHAPv2 username. Required for EAP — use `-eap-*` **or** `-psk`. |
| `-eap-pass` | `$IPSEC_EAP_PASS` | EAP-MSCHAPv2 password. Required for EAP — use `-eap-*` **or** `-psk`. |
| `-psk` | `$IPSEC_PSK` | Pre-shared key for PSK auth. Mutually exclusive with `-eap-*`. |
| `-ca` | *(system roots)* | PEM file of CA certificate(s) trusted for the server chain (EAP only; unused with `-psk`). |
| `-remote-id` | *(any)* | Expected server identity, matched against the certificate SAN (email / FQDN / IP). |
| `-local-id` | *(none)* | Local IKE identity (IDi) announced to the server (email / FQDN / IP). With EAP-MSCHAPv2 the real identity is `-eap-user`; this is only a server-side policy selector. When unset an empty IDi is sent. |
| `-listen` | `127.0.0.1:1080` | SOCKS5 listen address. |
| `-socks-auth` | *(none)* | Require SOCKS5 `username:password` (RFC 1929). |
| `-dns` | *(server-pushed)* | Override the in-tunnel DNS resolver (`IP` or `IP:53`). |
| `-idle` | `10m` | Close an idle proxied TCP connection after this long (`0` disables). |
| `-timeout` | `45s` | IKE handshake timeout. |
| `-rekey` | `1h` | Child SA soft lifetime (`0` = library default). Low values force client-initiated rekeys — useful for testing. |
| `-ike-rekey` | `4h` | IKE SA soft lifetime (`0` = library default). |
| `-dpd` | `30s` | Dead Peer Detection interval (`0` = library default). |
| `-v` | off | Verbose (`slog` Debug) logging to stderr. |
| `-insecure-allow-public-bind` | off | Allow `-listen` on a non-loopback address (see Security). |

## Credentials

Pass the EAP password via `$IPSEC_EAP_PASS` rather than `-eap-pass` so it does
not show up in `ps` / shell history. `-eap-user`/`-eap-pass` override the
environment when given.

For **PSK** auth, pass the key via `$IPSEC_PSK` rather than `-psk` for the same
reason. Supply exactly one of `-psk` or `-eap-user`/`-eap-pass`; with PSK no `-ca`
is needed, since there is no server certificate.

## Name resolution

`CONNECT` requests with a **domain name** are resolved through the tunnel using
the server-pushed DNS server — the IPv4 resolver first, then the IPv6 one — (or
`-dns` if set, falling back to `1.1.1.1`), so DNS does not leak outside the VPN.
A resolved IPv4 address is preferred; an IPv6-only name is dialled over inner
IPv6 when the server assigned a v6 address. Use `curl --socks5-hostname` (not
`--socks5`) so the client hands the hostname to the proxy instead of resolving it
locally.

## Security

- The listener **refuses to bind to a non-loopback address** by default — an
  open SOCKS5 proxy on a public interface is an open relay. Bind only to
  `127.0.0.1` / `localhost`, or set `-socks-auth` and pass
  `-insecure-allow-public-bind` if you really mean to expose it.
- For **EAP**, always supply `-ca` (and ideally `-remote-id`) so the server
  certificate chain and identity are verified; without `-ca` the system trust
  roots are used. (PSK does not use a certificate; mutual trust comes from the
  shared key.)

## Lifecycle

While running, the client maintains the tunnel automatically:

- **DPD** — empty `INFORMATIONAL` probes every `-dpd`; if the peer stops
  answering, the client declares it dead and exits.
- **Rekey** — Child and IKE SAs are rekeyed before their soft lifetime
  (`-rekey` / `-ike-rekey`) with a make-before-break, zero-loss cutover;
  in-flight connections survive. Server-initiated rekeys are answered too.
- **Graceful shutdown** — Ctrl-C / `SIGTERM` sends an IKE `DELETE` and tears the
  tunnel down cleanly.

## Limitations

- **TCP `CONNECT` only** — no SOCKS5 `BIND` or `UDP ASSOCIATE`.

Inner traffic is **dual-stack**: a `CONNECT` to an IPv6 target rides ESP when the
server assigns an inner IPv6 address (CFG `INTERNAL_IP6_ADDRESS`); against a
v4-only server it stays IPv4.

## Try it locally

The repo ships a throwaway strongSwan server for end-to-end testing:

```sh
cd test/strongswan && docker compose up --build   # generates certs + serves :500/:4500
# then, from the repo root:
go run ./cmd/ipsec2socks \
  -server 127.0.0.1:500 -ca test/strongswan/pki/caCert.pem \
  -remote-id vpn.example.com -eap-user testuser -eap-pass testpass -v
```

See [`test/strongswan/README.md`](../../test/strongswan/README.md) for details.

## Using go-ipsec directly

`ipsec2socks` is a thin frontend over the `ipsec` library. To embed the tunnel
in your own program (custom dialer, mihomo/sing-box injectable transport, etc.),
use `ipsec.Dial` and `client.DialContext` directly — see the
[top-level README](../../README.md).
