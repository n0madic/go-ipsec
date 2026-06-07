# Local strongSwan interop server

A throwaway IKEv2-EAP-MSCHAPv2 server configured to negotiate exactly the suite
go-ipsec implements (AES-CBC-256 / HMAC-SHA2-256 / DH group 14). Use it to run
the build-tagged live tests and `ipsec2socks` against a real responder.

## 1. Start the server

```sh
cd test/strongswan
docker compose up --build      # serves UDP 500 + 4500
```

The entrypoint generates a fresh CA + server certificate on every start and
exports the CA to `pki/caCert.pem` for the host-side client — no separate cert
step. Default credentials (edit `ipsec.secrets`): user `testuser`, pass
`testpass`. Server identity: `vpn.example.com` (cert SAN). CA: `pki/caCert.pem`.

> **NAT-T:** go-ipsec is userspace and cannot send raw ESP, so it always uses
> UDP-encapsulation on port 4500. Because its NAT-detection source hash uses an
> unspecified local address, strongSwan reliably detects "NAT" and enables
> UDP-encap — even on localhost. If UDP return traffic misbehaves through Docker
> Desktop's port proxy on macOS, run the container in a routable Linux VM
> (Colima/Lima/UTM) and point `-server` at the VM IP instead of `127.0.0.1`.

## 2. Run the live test suite

```sh
cd ../..        # repo root
IPSEC_SERVER=127.0.0.1:500 \
IPSEC_EAP_USER=testuser IPSEC_EAP_PASS=testpass \
IPSEC_REMOTE_ID=vpn.example.com \
IPSEC_CA="$(pwd)/test/strongswan/pki/caCert.pem" \
go test -tags e2e_server -v ./test/integration -run Live
```

`IPSEC_CA` must be an ABSOLUTE path — `go test` runs each package with its own
directory as the working directory, so a repo-relative path is not found.

`TestLiveIPv6` hard-gates the inner-IPv6 round-trip (ESP carries inner v6 with the
correct Next Header); `IPSEC_V6_TARGET` overrides the in-container echo target if
you point the suite at a different server.

`TestLiveHandshake` asserts the Child SA + CP address; `TestLiveIPv6` round-trips
a TCP connection over inner IPv6; `TestLiveHTTPGet` routes an HTTP GET through the
tunnel and logs the exit IP; `TestLiveDiag` dumps the gVisor IP/TCP stack counters
after a dial, for debugging packet-path issues.

## 3. Run the SOCKS5 sidecar

```sh
IPSEC_EAP_USER=testuser IPSEC_EAP_PASS=testpass \
go run ./cmd/ipsec2socks \
  -server 127.0.0.1:500 -ca test/strongswan/pki/caCert.pem \
  -remote-id vpn.example.com -listen 127.0.0.1:1080 -v

# in another shell:
curl --socks5-hostname 127.0.0.1:1080 http://api.ipify.org
```

## 4. Exercise the lifecycle

- **DPD:** leave the proxy idle; go-ipsec sends an empty INFORMATIONAL every
  `-dpd` (default 30s) and strongSwan answers. Stop the container and within a
  few probes the client logs `peer unresponsive, declaring dead` and exits.

- **Client-initiated rekey:** add `-rekey 90s` (Child) and/or `-ike-rekey 3m`
  (IKE) to `ipsec2socks`. Watch the client logs for `Child SA rekeyed` /
  `IKE SA rekeyed (initiator)`; an in-flight `curl` (or `curl` in a loop) keeps
  working across the cutover.

- **Server-initiated rekey:** set `lifetime=90s` (and `rekeymargin=30s`) in
  `ipsec.conf`, restart the container. strongSwan drives the CREATE_CHILD_SA;
  the client logs `answered server Child SA rekey`.

- **Graceful DELETE:** Ctrl-C `ipsec2socks`; strongSwan logs a received DELETE
  and closes the SA cleanly.

## 5. Capture packets (optional)

```sh
docker compose exec vpn tcpdump -i any -w /tmp/ike.pcap udp port 500 or udp port 4500
```
