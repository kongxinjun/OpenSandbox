# Hunt-only egress sidecar: host-built binaries on debian slim, no mitmproxy
# (credential vault MITM paths are not exercised).
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      iptables iproute2 nftables ca-certificates curl dnsutils procps \
    && rm -rf /var/lib/apt/lists/*
COPY egress supervisor egress-trace cleanup.sh /opt/opensandbox-egress/
RUN chmod 0755 /opt/opensandbox-egress/* && ln -s /opt/opensandbox-egress/egress /egress \
    && ln -s /opt/opensandbox-egress/egress-trace /usr/local/bin/egress-trace
ENTRYPOINT ["/opt/opensandbox-egress/supervisor", "--pre-start=/opt/opensandbox-egress/cleanup.sh", \
            "--name=egress", "--grace-period=20s", "--", "/opt/opensandbox-egress/egress"]
