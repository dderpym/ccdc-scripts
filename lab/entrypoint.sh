#!/bin/sh
# ONLY for disposable containers: these are intentional security faults.
set -eu
mkdir -p /run/sshd /run/nginx /var/log/nginx
case "$LAB_SOCKET_OWNER" in
    ''|*[!0-9]*) echo 'LAB_SOCKET_OWNER must be a numeric UID' >&2; exit 1 ;;
esac
printf '%s\n' "$LAB_SOCKET_OWNER" > /var/lib/ccdc-lab/socket-owner

if ! id oski >/dev/null 2>&1; then
    useradd --create-home --shell /bin/sh oski
fi
# '*' permits key login without unlocking a usable account password on Alpine.
usermod --password '*' oski
install -d -m 0700 -o oski -g oski /home/oski/.ssh
install -m 0600 -o oski -g oski /run/lab-key.pub /home/oski/.ssh/authorized_keys
install -d -m 0700 /root/.ssh
install -m 0600 /run/lab-key.pub /root/.ssh/authorized_keys
mkdir -p /etc/sudoers.d
printf 'oski ALL=(ALL:ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/oski
chmod 0440 /etc/sudoers.d/oski
# Retain distribution sudoers and ensure the fixture drop-in is read.
if ! grep -Eq '^[#@]includedir[[:space:]]+/etc/sudoers.d' /etc/sudoers; then
    printf '\n@includedir /etc/sudoers.d\n' >> /etc/sudoers
fi
visudo -c

# Generate unique container keys at first boot, never bake shared keys into images.
ssh-keygen -A
if [ ! -f /var/lib/ccdc-lab/faults-applied ]; then
cat > /etc/ssh/sshd_config <<'SSH'
Port 22
ListenAddress 0.0.0.0
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
UsePAM no
UseDNS no
PidFile /run/sshd.pid
Subsystem sftp internal-sftp
SSH
fi

printf '%s - disposable CCDC lab\n' "$(hostname)" > /var/lib/ccdc-lab/www/index.html
# Apply fixtures once; restarts must not append unlimited tamper bytes/comments.
if [ ! -f /var/lib/ccdc-lab/faults-applied ]; then
    printf '\nCCDC-LAB-INTENTIONALLY-MODIFIED\n' >> /usr/bin/ssh
    chmod 0777 /usr/bin/ssh
    rm -f /usr/bin/scp
    chmod 0666 /etc/passwd
    sed -i 's/^worker_processes .*/worker_processes 1;/' /etc/nginx/nginx.conf
    printf '\n# CCDC lab: intentional vendor-config difference\n' >> /etc/nginx/nginx.conf
    if [ -d /etc/nginx/http.d ]; then
        site=/etc/nginx/http.d/default.conf
    else
        site=/etc/nginx/sites-available/default
    fi
    cat > "$site" <<'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/lib/ccdc-lab/www;
    index index.html;
    location / { try_files $uri $uri/ =404; }
}
NGINX
    mkdir -p /etc/cron.d
    printf '* * * * * root /bin/true\n' > /etc/cron.d/ccdc-lab
    chmod 0666 /etc/cron.d/ccdc-lab
    touch /var/lib/ccdc-lab/faults-applied
fi

nginx -t
/usr/sbin/sshd -t
if [ -x /lib/systemd/systemd ]; then
    # Docker mounts this container's private cgroup namespace read-only.
    # Remount only that namespace, never bind-mount the host's cgroup tree.
    [ "$(stat -f -c %T /sys/fs/cgroup)" = cgroup2fs ] || {
        echo 'The systemd lab requires Docker with private cgroup v2 namespaces' >&2
        exit 1
    }
    mount -o remount,rw /sys/fs/cgroup
fi
# BusyBox init + OpenRC on Alpine; systemd on Debian. No shell supervision.
exec /sbin/init
