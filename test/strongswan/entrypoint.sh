#!/bin/sh
# Generate a fresh CA + server certificate, install them where strongSwan
# expects, and export ONLY the CA to the bind-mounted /pki so the host-side
# client (go-ipsec) can trust this server. Then enable forwarding + NAT for the
# assigned client pool and run charon in the foreground.
set -e

# --- certificates -------------------------------------------------------------
# Regenerated on every start so the exported CA always matches the server cert
# this container presents. Private keys never leave the container.
WORK=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/caKey.pem" \
	-out "$WORK/caCert.pem" -days 825 -subj "/CN=go-ipsec Test CA"

openssl req -newkey rsa:2048 -nodes -keyout "$WORK/serverKey.pem" \
	-out "$WORK/server.csr" -subj "/CN=vpn.example.com"

openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/caCert.pem" \
	-CAkey "$WORK/caKey.pem" -CAcreateserial -out "$WORK/serverCert.pem" \
	-days 825 -extfile /dev/stdin <<-EXT
		subjectAltName=DNS:vpn.example.com
		keyUsage=digitalSignature,keyEncipherment
		extendedKeyUsage=serverAuth
	EXT

install -m 0644 "$WORK/caCert.pem"     /etc/ipsec.d/cacerts/caCert.pem
install -m 0644 "$WORK/serverCert.pem" /etc/ipsec.d/certs/serverCert.pem
install -m 0600 "$WORK/serverKey.pem"  /etc/ipsec.d/private/serverKey.pem

# Export the CA for the host-side client. Write-then-rename so the Makefile's
# readiness probe never observes a half-written file.
install -m 0644 "$WORK/caCert.pem" /pki/.caCert.pem.tmp
mv /pki/.caCert.pem.tmp /pki/caCert.pem
rm -rf "$WORK"

# --- forwarding + NAT ---------------------------------------------------------
# Route decrypted client traffic (10.10.10.0/24) out to the internet.
POOL=10.10.10.0/24
WAN=$(ip route show default | awk '/default/ {print $5; exit}')
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -t nat -C POSTROUTING -s "$POOL" -o "$WAN" -j MASQUERADE 2>/dev/null ||
	iptables -t nat -A POSTROUTING -s "$POOL" -o "$WAN" -j MASQUERADE
iptables -C FORWARD -s "$POOL" -j ACCEPT 2>/dev/null || iptables -A FORWARD -s "$POOL" -j ACCEPT
iptables -C FORWARD -d "$POOL" -j ACCEPT 2>/dev/null || iptables -A FORWARD -d "$POOL" -j ACCEPT

# --- inner IPv6 ---------------------------------------------------------------
# Carry inner v6 over the tunnel and provide a self-contained v6 target so the
# v6 data path is testable without the Docker host having real v6 egress: the
# client routes ::/0 into the tunnel, strongSwan decrypts, and the packet is
# delivered locally to an address on `lo`. Tolerate read-only sysctls (|| true)
# so startup never aborts on a host that pins a particular knob.
V6_TARGET=fd00:cafe::1
V6_PORT=7777
sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.forwarding=1 >/dev/null 2>&1 || true
ip -6 addr add "$V6_TARGET/128" dev lo 2>/dev/null || true
# Forking TCP echo listener (raw echo via cat): the live test writes a token and
# expects it mirrored back over the tunnel. Bound to :: so the local-delivery to
# $V6_TARGET is accepted regardless of which address the kernel selects.
socat TCP6-LISTEN:"$V6_PORT",fork,reuseaddr EXEC:/bin/cat &

exec ipsec start --nofork
