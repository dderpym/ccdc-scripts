"""Manifest of every issue planted in the mirror lab: the single source of truth for `check`.

An issue is something that *sounds autofixable* (a file mode, a setuid bit, an sshd setting, a secret in a
readable file, a service running as root). `check` only reports whether each one is still present or has been
fixed; it does not care which tool detects or fixes it. When you plant something new (faults.sh), add a line
here. IDs (M-001...) follow declaration order, so append new issues at the end to keep IDs stable.
"""
import functools
import subprocess
from dataclasses import dataclass
from pathlib import Path

LAB = Path(__file__).resolve().parent
HOSTS = ('daffy', 'elmer', 'foghorn', 'sylvester', 'marvin', 'taz')
ADDRESS = {'daffy': '172.31.133.11', 'elmer': '172.31.133.77', 'foghorn': '172.31.133.13',
           'sylvester': '172.31.133.69', 'marvin': '172.31.133.199', 'taz': '172.31.133.169'}
BIRDCAGE_PORTS = (48215, 48216, 52113)


@dataclass(frozen=True)
class Issue:
    key: str
    title: str
    category: str
    severity: str            # high | medium | low | info
    hosts: tuple
    probe: object            # host -> observed string
    present: object          # observed -> bool (True while the planted problem is still there)
    informational: bool = False   # reported, never counted as a failure (e.g. open ports)


def sh(host, command, timeout=30):
    try:
        result = subprocess.run(['docker', 'exec', 'ccdc-mirror-' + host, 'sh', '-c', command],
                                capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return 'ERR'


@functools.lru_cache(maxsize=None)
def _sshd(host):
    return sh(host, 'sshd -T 2>/dev/null')


def sshd(key):
    def probe(host):
        for line in _sshd(host).splitlines():
            name, _, value = line.partition(' ')
            if name == key:
                return value
        return 'ERR'
    return probe


def mode(path):
    return lambda host: sh(host, f'stat -c %a {path} 2>/dev/null') or 'missing'


def setuid(path):
    return lambda host: 'setuid' if sh(host, f'stat -c %a {path} 2>/dev/null').startswith('4') else 'clean'


def exists(path):
    return lambda host: sh(host, f'[ -e {path} ] && echo yes || echo no')


def contains(path, text):
    return lambda host: sh(host, f'grep -c {text} {path} 2>/dev/null') or '0'


def service_user(unit):
    return lambda host: sh(host, f'systemctl show -p User --value {unit}') or 'root'


def is_(value):
    return lambda out: out == value


def over(limit):
    return lambda out: out.isdigit() and int(out) > limit


def peer_of(host):
    return HOSTS[(HOSTS.index(host) + 1) % len(HOSTS)]


def tcp_open(source, target, port):
    code = ("import socket,sys;s=socket.socket();s.settimeout(2);"
            f"sys.exit(0 if s.connect_ex(('{ADDRESS[target]}',{port}))==0 else 1)")
    result = subprocess.run(['docker', 'exec', 'ccdc-mirror-' + source, 'python3', '-c', code],
                            capture_output=True, text=True, timeout=15)
    return result.returncode == 0


def icmp_ping(source, target):
    """One ICMP echo from a peer container (raw socket; the images carry no ping binary)."""
    code = (
        "import socket,struct,sys,time\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP);s.settimeout(2)\n"
        "def ck(b):\n"
        "    t=sum(struct.unpack('!%dH'%(len(b)//2),b))\n"
        "    t=(t>>16)+(t&0xffff);t+=t>>16;return ~t&0xffff\n"
        "h=struct.pack('!BBHHH',8,0,0,0x4c42,1);p=b'ccdc-lab';c=ck(h+p)\n"
        "s.sendto(struct.pack('!BBHHH',8,0,c,0x4c42,1)+p,(sys.argv[1],0))\n"
        "try:\n"
        "    while True:\n"
        "        d,a=s.recvfrom(1024)\n"
        "        if a[0]==sys.argv[1] and d[20]==0: sys.exit(0)\n"
        "except Exception: sys.exit(1)\n")
    result = subprocess.run(['docker', 'exec', 'ccdc-mirror-' + source, 'python3', '-c', code, ADDRESS[target]],
                            capture_output=True, text=True, timeout=15)
    return result.returncode == 0


def peer_reachable(port):
    return lambda host: 'open' if tcp_open(peer_of(host), host, port) else 'blocked'


ISSUES = [
    # --- SSH policy (all hosts) -------------------------------------------------------------
    Issue('ssh.permitrootlogin', 'sshd allows root login (PermitRootLogin yes)', 'ssh', 'high', HOSTS,
          sshd('permitrootlogin'), is_('yes')),
    Issue('ssh.passwordauth', 'sshd allows password authentication', 'ssh', 'medium', HOSTS,
          sshd('passwordauthentication'), is_('yes')),
    Issue('ssh.x11', 'sshd X11Forwarding enabled', 'ssh', 'low', HOSTS, sshd('x11forwarding'), is_('yes')),
    Issue('ssh.agentfwd', 'sshd AllowAgentForwarding enabled', 'ssh', 'low', HOSTS,
          sshd('allowagentforwarding'), is_('yes')),
    Issue('ssh.tcpfwd', 'sshd AllowTcpForwarding enabled', 'ssh', 'low', HOSTS,
          sshd('allowtcpforwarding'), is_('yes')),
    Issue('ssh.maxauthtries', 'sshd MaxAuthTries above 3', 'ssh', 'low', HOSTS,
          sshd('maxauthtries'), over(3)),
    Issue('ssh.logingrace', 'sshd LoginGraceTime above 30s', 'ssh', 'low', HOSTS,
          sshd('logingracetime'), over(30)),

    # --- Permissions and setuid (common) ----------------------------------------------------
    Issue('perm.find-setuid', '/usr/bin/find is setuid', 'setuid', 'high', HOSTS,
          setuid('/usr/bin/find'), is_('setuid')),
    Issue('perm.crontab', '/etc/crontab is group/other writable (mode 666)', 'permissions', 'high', HOSTS,
          mode('/etc/crontab'), is_('666')),
    Issue('perm.ssh-mode', '/usr/bin/ssh is group/other writable (mode 777)', 'permissions', 'high', HOSTS,
          mode('/usr/bin/ssh'), is_('777')),
    Issue('tamper.ssh-content', '/usr/bin/ssh content differs from its package', 'tamper', 'high', HOSTS,
          contains('/usr/bin/ssh', 'CCDC-LAB-INTENTIONALLY-MODIFIED'), is_('1')),
    Issue('perm.cron-file', '/etc/cron.d/lab-backup is group/other writable (mode 666)', 'permissions', 'high',
          HOSTS, mode('/etc/cron.d/lab-backup'), is_('666')),
    Issue('cron.writable-script', 'cron runs /usr/local/bin/lab-backup.sh which is mode 777', 'cron', 'medium',
          HOSTS, mode('/usr/local/bin/lab-backup.sh'), is_('777')),
    Issue('secret.history', 'credential in /root/.bash_history', 'secrets', 'medium', HOSTS,
          contains('/root/.bash_history', 'LabPassw0rd'), is_('1')),

    # --- Per-host stories -------------------------------------------------------------------
    Issue('perm.shadow', '/etc/shadow is world-readable (mode 644)', 'permissions', 'high', ('daffy',),
          mode('/etc/shadow'), is_('644')),
    Issue('perm.passwd', '/etc/passwd is world-writable (mode 666)', 'permissions', 'high', ('elmer',),
          mode('/etc/passwd'), is_('666')),
    Issue('sudo.deploy', 'user deploy has NOPASSWD: ALL', 'sudo', 'high', ('elmer',),
          exists('/etc/sudoers.d/90-deploy'), is_('yes')),
    Issue('perm.cp-setuid', '/usr/bin/cp is setuid', 'setuid', 'high', ('foghorn',),
          setuid('/usr/bin/cp'), is_('setuid')),
    Issue('perm.env-setuid', '/usr/bin/env is setuid', 'setuid', 'high', ('marvin',),
          setuid('/usr/bin/env'), is_('setuid')),
    Issue('perm.tar-setuid', '/usr/bin/tar is setuid', 'setuid', 'high', ('taz',),
          setuid('/usr/bin/tar'), is_('setuid')),
    Issue('sudo.sudo-group', '%sudo group has NOPASSWD: ALL', 'sudo', 'high', ('taz',),
          exists('/etc/sudoers.d/90-sudo-nopasswd'), is_('yes')),
    Issue('secret.db-cnf', 'database password in world-readable /etc/ccdc-lab/db.cnf', 'secrets', 'medium',
          ('marvin',), mode('/etc/ccdc-lab/db.cnf'), is_('644')),
    Issue('app.root', 'aviary service runs as root', 'service', 'medium', ('sylvester',),
          service_user('ccdc-birdcage'), lambda out: out in ('root', '')),
    Issue('app.env-readable', '/etc/birdcage.env (default secrets) is world-readable (mode 644)', 'secrets',
          'medium', ('sylvester',), mode('/etc/birdcage.env'), is_('644')),
    Issue('app.state-777', '/var/lib/birdcage is world-writable (mode 777)', 'permissions', 'medium',
          ('sylvester',), mode('/var/lib/birdcage'), is_('777')),
]


def _stand_in_ports():
    ports = {}
    for host in HOSTS:
        found = set()
        listeners = LAB / 'hosts' / host / 'listeners'
        if listeners.exists():
            found |= {int(line.split()[1]) for line in listeners.read_text().splitlines() if line.strip()}
        if host == 'sylvester':
            found |= set(BIRDCAGE_PORTS)
        ports[host] = sorted(found)
    return ports


STAND_IN_PORTS = _stand_in_ports()

# One informational exposure item per stand-in port: a firewall review decides each; never a failure.
for _host, _ports in STAND_IN_PORTS.items():
    for _port in _ports:
        ISSUES.append(Issue(f'net.{_port}', f'port {_port} reachable from peers (no firewall policy yet)',
                            'exposure', 'info', (_host,), peer_reachable(_port), is_('open'), informational=True))


def expand():
    """Flat, ordered (id, issue, host) list; IDs are stable while new issues are appended."""
    rows, number = [], 0
    for issue in ISSUES:
        for host in issue.hosts:
            number += 1
            rows.append((f'M-{number:03d}', issue, host))
    return rows
