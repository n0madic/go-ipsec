FROM alpine:3.20

RUN apk add --no-cache strongswan iptables openssl socat \
 && mkdir -p /etc/ipsec.d/cacerts /etc/ipsec.d/certs /etc/ipsec.d/private

COPY ipsec.conf ipsec.secrets /etc/
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 500/udp 4500/udp

ENTRYPOINT ["/entrypoint.sh"]
