#!/bin/sh
# ONLY for disposable containers: these are intentional security faults.
set -eu
mkdir -p /run/sshd /run/nginx /var/log/nginx

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
# Separate scoring-like service on tcp/9000. nginx remains on tcp/80.
python3 -m http.server 9000 --bind 0.0.0.0 --directory /var/lib/ccdc-lab/www &
app=$!

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
nginx -g 'daemon off;' &
web=$!
/usr/sbin/sshd -D -e &
ssh=$!
# Private bind-mounted Unix sockets avoid host VPN routing entirely.
# Only the invoking host UID can connect; no host key/password is mounted here.
socat "UNIX-LISTEN:/run/lab-sockets/ssh,fork,unlink-early,mode=0600,user=$LAB_SOCKET_OWNER" TCP:127.0.0.1:22 &
ssh_relay=$!
socat "UNIX-LISTEN:/run/lab-sockets/http,fork,unlink-early,mode=0600,user=$LAB_SOCKET_OWNER" TCP:127.0.0.1:80 &
web_relay=$!
socat "UNIX-LISTEN:/run/lab-sockets/app,fork,unlink-early,mode=0600,user=$LAB_SOCKET_OWNER" TCP:127.0.0.1:9000 &
app_relay=$!
trap 'kill "$app" "$web" "$ssh" "$ssh_relay" "$web_relay" "$app_relay" 2>/dev/null || true; wait' TERM INT
wait
