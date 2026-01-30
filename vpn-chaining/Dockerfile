FROM alpine:3.20

RUN sed -i 's#dl-cdn.alpinelinux.org#dl-2.alpinelinux.org#g' /etc/apk/repositories && \
    apk add --no-cache \
    bash \
    iproute2 \
    iptables \
    ip6tables \
    wireguard-tools \
    curl \
    traceroute

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

