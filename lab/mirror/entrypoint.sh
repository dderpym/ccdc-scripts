#!/bin/sh
# ONLY for disposable containers: these are intentional security faults.
set -eu
host=$(hostname)
cfg=/usr/local/lib/ccdc-lab/hosts/$host
[ -d "$cfg" ] || { echo "unknown lab host: $host" >&2; exit 1; }
case "${LAB_SOCKET_OWNER:-}" in
    ''|*[!0-9]*) echo 'LAB_SOCKET_OWNER must be a numeric UID' >&2; exit 1 ;;
esac
mkdir -p /run/sshd /var/lib/ccdc-lab /etc/ccdc-lab
printf '%s\n' "$LAB_SOCKET_OWNER" > /var/lib/ccdc-lab/socket-owner
cp "$cfg"/ports /etc/ccdc-lab/ports
[ -f "$cfg"/listeners ] && cp "$cfg"/listeners /etc/ccdc-lab/listeners || : > /etc/ccdc-lab/listeners
printf '%s - disposable CCDC mirror lab\n' "$host" > /var/lib/ccdc-lab/index.txt

if ! id oski >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash oski
fi
# '*' permits key login without unlocking a usable account password.
usermod --password '*' oski
install -d -m 0700 -o oski -g oski /home/oski/.ssh
install -m 0600 -o oski -g oski /run/lab-key.pub /home/oski/.ssh/authorized_keys
install -d -m 0700 /root/.ssh
install -m 0600 /run/lab-key.pub /root/.ssh/authorized_keys
mkdir -p /etc/sudoers.d
printf 'oski ALL=(ALL:ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/oski
chmod 0440 /etc/sudoers.d/oski
if ! grep -Eq '^[#@]includedir[[:space:]]+/etc/sudoers.d' /etc/sudoers; then
    printf '\n@includedir /etc/sudoers.d\n' >> /etc/sudoers
fi
visudo -c >/dev/null

# Unique container host keys at first boot; never bake shared keys into images.
ssh-keygen -A
if [ ! -f /var/lib/ccdc-lab/faults-applied ]; then
    sh /usr/local/lib/ccdc-lab/faults.sh
    touch /var/lib/ccdc-lab/faults-applied
fi
/usr/sbin/sshd -t

# Docker mounts this container's private cgroup namespace read-only; remount only that namespace.
[ "$(stat -f -c %T /sys/fs/cgroup)" = cgroup2fs ] || {
    echo 'The systemd lab requires Docker with private cgroup v2 namespaces' >&2
    exit 1
}
mount -o remount,rw /sys/fs/cgroup
exec /sbin/init
