# Disposable "mirror" hosts: same distros as the real competition boxes, systemd as PID 1.
# One image per distro family; the container's hostname selects its role at boot.
ARG BASE=debian:trixie

FROM ${BASE} AS deb
ARG DEBIAN_FRONTEND=noninteractive
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 0755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus rsyslog openssh-server openssh-client python3 sudo \
        nftables iproute2 libcap2-bin coreutils findutils grep procps cron socat less passwd \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /var/lib/apt/lists/partial \
    && rm -f /usr/sbin/policy-rc.d /etc/ssh/ssh_host_* /var/lib/dbus/machine-id \
    && mkdir -p /run/sshd /var/lib/ccdc-lab \
    && truncate -s 0 /etc/machine-id \
    && ln -sf /etc/machine-id /var/lib/dbus/machine-id \
    && sed -i '/^module(load="imklog")/d' /etc/rsyslog.conf \
    && systemctl mask getty.target console-getty.service systemd-logind.service \
        systemd-udevd.service systemd-udev-trigger.service apt-daily.timer \
        apt-daily-upgrade.timer motd-news.timer
COPY units/ /etc/systemd/system/
COPY bin/ /usr/local/bin/
COPY hosts/ /usr/local/lib/ccdc-lab/hosts/
COPY faults.sh /usr/local/lib/ccdc-lab/faults.sh
COPY entrypoint.sh /usr/local/bin/ccdc-lab-entrypoint
RUN chmod 0755 /usr/local/bin/ccdc-lab-* \
    && systemctl enable ssh cron rsyslog ccdc-listeners ccdc-birdcage \
        ccdc-relay@ssh ccdc-relay@http ccdc-relay@app \
    && systemctl set-default multi-user.target
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/bin/sh", "/usr/local/bin/ccdc-lab-entrypoint"]

FROM rockylinux:9 AS rpm
RUN dnf -y install --setopt=install_weak_deps=False \
        systemd openssh-server openssh-clients python3 sudo nftables iproute libcap \
        procps-ng cronie rsyslog socat findutils less passwd shadow-utils dbus-broker \
    && dnf clean all \
    && rm -f /etc/ssh/ssh_host_* \
    && mkdir -p /var/lib/ccdc-lab \
    && truncate -s 0 /etc/machine-id \
    && systemctl mask getty.target console-getty.service systemd-logind.service \
        systemd-udevd.service systemd-udev-trigger.service dnf-makecache.timer
COPY units/ /etc/systemd/system/
COPY bin/ /usr/local/bin/
COPY hosts/ /usr/local/lib/ccdc-lab/hosts/
COPY faults.sh /usr/local/lib/ccdc-lab/faults.sh
COPY entrypoint.sh /usr/local/bin/ccdc-lab-entrypoint
RUN chmod 0755 /usr/local/bin/ccdc-lab-* \
    && systemctl enable sshd crond rsyslog ccdc-listeners ccdc-birdcage \
        ccdc-relay@ssh ccdc-relay@http ccdc-relay@app \
    && systemctl set-default multi-user.target
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/bin/sh", "/usr/local/bin/ccdc-lab-entrypoint"]
