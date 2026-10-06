# Disposable competition fixtures. No systemd or host namespace access.
FROM alpine:3.22 AS hatchery
RUN apk add --no-cache openssh python3 sudo nginx nftables iproute2 \
        libcap-utils coreutils findutils grep procps shadow socat \
    && rm -f /etc/ssh/ssh_host_* \
    && mkdir -p /run/sshd /var/lib/ccdc-lab/www
COPY entrypoint.sh /usr/local/bin/ccdc-lab-entrypoint
ENTRYPOINT ["/bin/sh", "/usr/local/bin/ccdc-lab-entrypoint"]

FROM debian:bookworm AS tarpit
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 0755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server python3 sudo nginx-light nftables iproute2 libcap2-bin \
        coreutils findutils grep procps cron socat \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/ssh/ssh_host_* \
    && mkdir -p /run/sshd /var/lib/ccdc-lab/www
COPY entrypoint.sh /usr/local/bin/ccdc-lab-entrypoint
ENTRYPOINT ["/bin/sh", "/usr/local/bin/ccdc-lab-entrypoint"]
