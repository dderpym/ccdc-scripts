# Disposable competition hosts using their distribution's normal init system.
FROM alpine:3.22 AS hatchery
RUN apk add --no-cache alpine-base busybox-openrc openssh python3 sudo nginx \
        nftables iproute2 libcap-utils coreutils findutils grep procps shadow socat \
    && rm -f /etc/ssh/ssh_host_* \
    && mkdir -p /run/sshd /var/lib/ccdc-lab/www \
    && printf '\nrc_sys="docker"\nrc_cgroup_mode="none"\n' >> /etc/rc.conf \
    && sed -i '/^[^#].*::respawn:/d' /etc/inittab
COPY services/openrc/ /etc/init.d/
COPY services/relay /usr/local/bin/ccdc-lab-relay
RUN chmod 0755 /etc/init.d/ccdc-* /usr/local/bin/ccdc-lab-relay \
    && for name in ssh http app; do \
        ln -s ccdc-relay /etc/init.d/ccdc-relay-$name; \
        rc-update add ccdc-relay-$name default; \
    done \
    && for name in sshd nginx crond syslog ccdc-app; do rc-update add "$name" default; done
COPY entrypoint.sh /usr/local/bin/ccdc-lab-entrypoint
STOPSIGNAL SIGUSR1
ENTRYPOINT ["/bin/sh", "/usr/local/bin/ccdc-lab-entrypoint"]

FROM debian:bookworm AS tarpit
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 0755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus rsyslog openssh-server python3 sudo nginx-light \
        nftables iproute2 libcap2-bin coreutils findutils grep procps cron socat \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/sbin/policy-rc.d /etc/ssh/ssh_host_* /var/lib/dbus/machine-id \
    && mkdir -p /run/sshd /var/lib/ccdc-lab/www \
    && truncate -s 0 /etc/machine-id \
    && ln -s /etc/machine-id /var/lib/dbus/machine-id \
    && sed -i '/^module(load="imklog")/d' /etc/rsyslog.conf
COPY services/systemd/ /etc/systemd/system/
COPY services/relay /usr/local/bin/ccdc-lab-relay
RUN chmod 0755 /usr/local/bin/ccdc-lab-relay \
    && systemctl enable ssh nginx cron rsyslog ccdc-app \
        ccdc-relay@ssh ccdc-relay@http ccdc-relay@app \
    && systemctl set-default multi-user.target
COPY entrypoint.sh /usr/local/bin/ccdc-lab-entrypoint
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/bin/sh", "/usr/local/bin/ccdc-lab-entrypoint"]
