#!/usr/bin/env python3
"""Apply authoritative SSH settings, validate, then reload (never restart).

Usage: apply-ssh yes|no  (PasswordAuthentication). Requires root and oski.
SSH_CONNECTION supplies the current oski test context; CCDC_SSH_CONTEXT can
supply explicit sshd -C fields instead. Owned directives are removed from all
parsed sources, including Match blocks. Conditional Includes and authentication/
config/port startup overrides are refused.
Socket-activated service authentication is reloaded; socket bindings are unchanged.
"""
import fcntl
import glob
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

CONFIG = "/etc/ssh/sshd_config"
BEGIN = "# BEGIN CCDC managed SSH policy\n"
END = "# END CCDC managed SSH policy\n"
SAFE_FLAGS = {"-D", "-e", "-4", "-6"}
CRYPTO_OPTIONS = {"ciphers", "macs", "kexalgorithms", "hostkeyalgorithms",
                  "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes",
                  "gssapikexalgorithms", "casignaturealgorithms", "requiredrsasize"}


def directive(line):
    # OpenSSH strdelim allows a quoted keyword or suffix: Ma"tch", too.
    match = re.match(r'^\s*(?:([^"\s=#]*)"([^"]*)"|([^"\s=#]+))[\s=]*(.*)$', line)
    if not match:
        return "", ""
    return (match[3] or (match[1] + match[2])).lower(), match[4]


def arguments(text):
    """OpenSSH argv_split semantics, not shell escaping/comment semantics.

    Keep in sync with discover-ssh: targets receive each script standalone.
    """
    result, index = [], 0
    text = text.rstrip("\r\n")
    while index < len(text):
        if text[index] in " \t":
            index += 1
            continue
        if text[index] == "#":
            break
        token, quote = [], None
        while index < len(text):
            char = text[index]
            if char == "\\" and index + 1 < len(text) and (
                    text[index + 1] in "\\\"'" or (quote is None and text[index + 1] == " ")):
                index += 1
                token.append(text[index])
            elif quote is None and char in " \t":
                break
            elif quote is None and char in "\"'":
                quote = char
            elif char == quote:
                quote = None
            else:
                token.append(char)
            index += 1
        if quote is not None:
            raise ValueError("Unclosed quote in SSH directive")
        result.append("".join(token))
    return result


def include_files(pattern):
    # Python glob does not implement glob(3)'s backslash escapes. Fail closed.
    if "\\" in pattern:
        raise RuntimeError("Unsupported escaped SSH Include pattern: " + pattern)
    if not os.path.isabs(pattern):
        pattern = os.path.join("/etc/ssh", pattern)
    return sorted(glob.glob(pattern))


def strip_policy(text, desired):
    keys = set(desired) | {"challengeresponseauthentication"}
    return "".join(line for line in text.splitlines(keepends=True)
                   if directive(line)[0] not in keys)


def policy_config(main, desired):
    # An owned top-of-file layer also works on OpenSSH <8.2 (no server Include).
    if main.startswith(BEGIN):
        if END not in main:
            raise RuntimeError("Truncated managed SSH policy; inspect manually")
        main = main.split(END, 1)[1]
    if BEGIN in main or END in main:
        raise RuntimeError("Unexpected managed SSH policy position; inspect manually")
    policy = "".join(key + " " + value + "\n" for key, value in desired.items())
    # Older OpenSSH has a separate ChallengeResponseAuthentication switch.
    policy += "ChallengeResponseAuthentication " + desired["kbdinteractiveauthentication"] + "\n"
    return BEGIN + policy + END + strip_policy(main, desired)


def run(args, check=True):
    p = subprocess.run(args, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if check and p.returncode:
        raise RuntimeError("%s: %s" % (" ".join(args), p.stderr.strip() or p.stdout.strip() or "failed"))
    return p


def daemon():
    for pidfile in ('/run/sshd.pid', '/run/ssh.pid', '/var/run/sshd.pid'):
        try:
            pid = Path(pidfile).read_text().strip()
            if pid.isdigit() and os.stat(pidfile).st_uid == 0:
                path = os.readlink('/proc/' + pid + '/exe')
                if os.path.basename(path) in ('sshd', 'sshd.pam', 'sshd.krb5') and os.access(path, os.X_OK):
                    return path
        except OSError:
            pass
    for path in ("/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd", shutil.which("sshd")):
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return os.path.abspath(path)
    raise RuntimeError("Cannot find sshd")


def connection_context():
    explicit = os.environ.get("CCDC_SSH_CONTEXT", "")
    if explicit:
        fields = {}
        for pair in explicit.split(","):
            key, sep, value = pair.partition("=")
            if not sep or key in fields or not value or re.search(r"\s", value):
                raise RuntimeError("Invalid CCDC_SSH_CONTEXT")
            fields[key] = value
        if set(fields) != {"user", "host", "addr", "laddr", "lport"} or fields["user"] != "oski":
            raise RuntimeError("CCDC_SSH_CONTEXT must specify user=oski,host,addr,laddr,lport")
    else:
        parts = os.environ.get("SSH_CONNECTION", "").split()
        if len(parts) != 4:
            raise RuntimeError("SSH_CONNECTION is required; alternatively set a full CCDC_SSH_CONTEXT for user=oski")
        addr, client_port, laddr, lport = parts
        if not client_port.isdigit() or not 1 <= int(client_port) <= 65535:
            raise RuntimeError("Invalid SSH_CONNECTION client port")
        fields = dict(user="oski", host=addr, addr=addr, laddr=laddr, lport=lport)
    for key in ("addr", "laddr"):
        ipaddress.ip_address(fields[key])
    if not fields["lport"].isdigit() or not 1 <= int(fields["lport"]) <= 65535:
        raise RuntimeError("Invalid connection port")
    return ",".join(key + "=" + fields[key] for key in ("user", "host", "addr", "laddr", "lport"))


def expand_args(text, environment, files):
    """Read only literal assignments; never execute service environment files."""
    refs = set(re.findall(r"\$\{?(\w+)\}?", text))
    values = {}
    for path in files:
        if not os.path.exists(path):
            continue
        for line in Path(path).read_text().splitlines():
            match = re.match(r"^\s*(?:export\s+)?(\w+)\s*=(.*)$", line)
            if match and match.group(1) in refs:
                key, value = match.groups()
                tokens = shlex.split(value, comments=True)
                if len(tokens) > 1 or any(c in value for c in "$`"):
                    raise RuntimeError("Nonliteral service options in " + path)
                values[key] = tokens[0] if tokens else ""
    # systemd Environment= takes precedence over the initial environment;
    # EnvironmentFile= then overrides it (already parsed above).
    for assignment in shlex.split(environment):
        key, sep, value = assignment.partition("=")
        if sep and key not in values:
            values[key] = value
    for ref in refs:
        value = values.get(ref, "")
        if any(c in value for c in "$`\n"):
            raise RuntimeError("Unsafe service options for " + ref)
        text = re.sub(r"\$\{" + re.escape(ref) + r"\}|\$" + re.escape(ref) + r"\b", value, text)
    args = shlex.split(text)
    executable = shutil.which(args[0]) if args and not os.path.isabs(args[0]) else (args[0] if args else '')
    if not executable or os.path.realpath(executable) != os.path.realpath(daemon()):
        raise RuntimeError("Ambiguous/custom sshd startup executable: " + text)
    remaining = iter(args[1:])
    for arg in remaining:
        if arg in SAFE_FLAGS:
            continue
        if arg == "-o":
            option = next(remaining, "")
        elif arg.startswith("-o"):
            option = arg[2:]
        else:
            raise RuntimeError("Unsafe sshd startup argument: " + arg)
        key = re.split(r"[=\s]", option, maxsplit=1)[0].lower()
        if key not in CRYPTO_OPTIONS:
            raise RuntimeError("Startup option can alter access policy: " + option)
    return args


def check_shell_options(path):
    """Sourced service files must be literal assignments, not executable logic."""
    values = {}
    if not os.path.exists(path):
        return values
    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if not re.fullmatch(r"\s*(?:export\s+)?\w+\s*=\s*(?:\"[^\"$`\n]*\"|'[^'\n]*'|[A-Za-z0-9_./:=-]*)\s*(?:#.*)?", line):
            raise RuntimeError("Unsafe/nonliteral sourced service options in " + path)
        match = re.match(r"\s*(?:export\s+)?(\w+)\s*=(.*)", line)
        tokens = shlex.split(match.group(2), comments=True)
        if len(tokens) > 1:
            raise RuntimeError("Nonliteral service assignment in " + path)
        values[match.group(1)] = tokens[0] if tokens else ""
    return values


def openrc_options(init, conf):
    """Stock Alpine openrc-run defaults, without evaluating a shell script."""
    settings = check_shell_options(conf)
    for key in ("cfgfile", "SSHD_CONFIG", "sshd_config", "configfile"):
        if key in settings and settings[key] != CONFIG:
            raise RuntimeError("Custom OpenRC config path: " + key)
    if settings.get("SSHD_CONFDIR", "/etc/ssh") != "/etc/ssh":
        raise RuntimeError("Custom OpenRC SSH configuration directory")
    for text in re.findall(r"(?m)^(?:cfgfile|sshd_config|SSHD_CONFIG|configfile)\s*=([^\n]+)", init):
        if shlex.split(text, comments=True) != [CONFIG]:
            raise RuntimeError("Custom OpenRC configuration default")
    commands = re.findall(r"(?m)^command\s*=([^\n]+)", init)
    arguments = re.findall(r"(?m)^command_args\s*=([^\n]+)", init)
    if len(commands) != 1 or len(arguments) > 1:
        raise RuntimeError("Cannot inspect OpenRC command")
    tokens = shlex.split(commands[0], comments=True)
    if len(tokens) != 1:
        raise RuntimeError("Ambiguous OpenRC command")
    command = tokens[0]
    default = re.fullmatch(r"\$\{SSHD_BINARY:-([^{}]+)\}", command)
    if default:
        command = settings.get("SSHD_BINARY") or default[1]
    command = settings.get("command") or command
    actual = daemon()
    if (command == '/usr/sbin/sshd' and os.path.basename(actual) in ('sshd.pam', 'sshd.krb5')
            and actual in init and not settings.get('command') and not settings.get('SSHD_BINARY')):
        command = actual  # Alpine's update_command selected a PAM/Kerberos variant.
    text = " ".join(shlex.split(arguments[0], comments=True)) if arguments else ""
    if text == "${command_args:-${SSHD_OPTS:-}}":
        text = settings.get("command_args") or settings.get("SSHD_OPTS", "")
    elif text in ("${sshd_opts:-}", "${command_args:-}"):
        text = settings.get(text[2:-3], "")
    elif "command_args" in settings:
        text = settings["command_args"]
    return expand_args(command + " " + text, "", [conf])


def service():
    """Select an already-running service and reject configuration overrides."""
    systemctl = shutil.which("systemctl")
    if systemctl and os.path.isdir("/run/systemd/system"):
        active = []
        for name in ("ssh.service", "sshd.service"):
            output = run([systemctl, "show", name, "--property=ActiveState,Id,ExecStart,Environment,EnvironmentFiles,PassEnvironment"], check=False)
            fields = dict(line.split("=", 1) for line in output.stdout.splitlines() if "=" in line)
            if fields.get("ActiveState") == "active":
                ident = fields.get("Id", name)
                if any(item[0] == ident for item in active):
                    continue  # Debian's sshd.service may be an alias of ssh.service.
                match = re.search(r"argv\[\]=(.*?)\s*;", fields.get("ExecStart", ""))
                if not match:
                    raise RuntimeError("Cannot inspect systemd ExecStart for " + name)
                if set(re.findall(r"\$\{?(\w+)\}?", match.group(1))) & set(fields.get("PassEnvironment", "").split()):
                    raise RuntimeError("Inherited systemd SSH startup options cannot be verified for " + name)
                files = re.findall(r"(\S+)\s+\(ignore_errors=(?:yes|no)\)", fields.get("EnvironmentFiles", ""))
                if fields.get("EnvironmentFiles") and not files:
                    raise RuntimeError("Cannot inspect systemd EnvironmentFiles for " + name)
                expand_args(match.group(1), fields.get("Environment", ""), files)
                active.append((ident, [systemctl, "reload", ident], [systemctl, "is-active", "--quiet", ident]))
        if len(active) != 1:
            raise RuntimeError("Expected exactly one running ssh/sshd systemd service")
        return active[0]

    rc = shutil.which("rc-service")
    if rc and os.path.exists("/run/openrc"):
        active = []
        for name in ("sshd", "ssh"):
            if run([rc, name, "status"], check=False).returncode == 0:
                init = Path("/etc/init.d/" + name).read_text()
                openrc_options(init, '/etc/conf.d/' + name)
                active.append((name, [rc, name, "reload"], [rc, name, "status"]))
        if len(active) != 1:
            raise RuntimeError("Expected exactly one running ssh/sshd OpenRC service")
        return active[0]

    sv = shutil.which("sv")
    if sv:
        active = []
        seen = set()
        for directory in ("/var/service", "/run/runit/service", "/etc/service"):
            for name in ("sshd", "ssh"):
                path = os.path.join(directory, name)
                real = os.path.realpath(path)
                if real in seen or not os.path.exists(path):
                    continue
                seen.add(real)
                status = run([sv, "status", path], check=False)
                if status.returncode or not status.stdout.startswith("run:"):
                    continue
                script = Path(path, "run").read_text()
                commands = [line.strip() for line in script.splitlines()
                            if re.match(r"\s*exec\s+(?:/[^\s]+/)?sshd\b", line)]
                if len(commands) != 1:
                    raise RuntimeError("Cannot inspect runit SSH exec in " + path)
                # Void's standard service sources ./conf and expands $OPTS.
                check_shell_options(os.path.join(path, 'conf'))
                referenced = set(re.findall(r"\$\{?(\w+)\}?", commands[0]))
                if any(re.search(r"(?m)^\s*(?:export\s+)?" + re.escape(ref) + r"\s*=", script) for ref in referenced):
                    raise RuntimeError("Inline runit SSH option assignments are ambiguous in " + path)
                expand_args(commands[0][5:], "", [os.path.join(path, "conf")])
                if re.search(r"(?:^|[;&]\s*)\s*(?:source|\.)\s+(?!\.?/?conf(?:\s|$))", script, re.MULTILINE):
                    raise RuntimeError("Unknown sourced runit startup options in " + path)
                active.append((path, [sv, "hup", path], [sv, "status", path]))
        if len(active) == 1:
            return active[0]
        if len(active) > 1:
            raise RuntimeError("Multiple running SSH runit services")
    raise RuntimeError("No unambiguous running systemd, OpenRC, or runit SSH service; nothing changed")


def inspect(path, desired):
    """Track local Match scope; conflicting conditional settings fail closed."""
    hashes, stack = {}, []

    def visit(filename, conditional=False):
        filename = os.path.abspath(filename)
        if filename in stack or len(stack) >= 32 or len(hashes) >= 512:
            raise RuntimeError("Include cycle or excessive SSH config graph")
        raw = Path(filename).read_bytes()
        hashes[filename] = hashlib.sha256(raw).hexdigest()
        stack.append(filename)
        for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
            key, text = directive(line)
            if not key:
                continue
            if key == "challengeresponseauthentication":
                key = "kbdinteractiveauthentication"
            values = arguments(text)
            if key == "match":
                conditional = True
            elif key == "include":
                if conditional:
                    raise RuntimeError("Unsafe conditional Include at %s:%d" % (filename, number))
                for pattern in values:
                    for included in include_files(pattern):
                        visit(included, conditional)
            elif conditional and key in desired:
                value = " ".join(values)
                if key != "authorizedkeysfile":
                    value = value.lower()
                if value != desired[key]:
                    raise RuntimeError("Match can defeat %s=%s at %s:%d; remove/align that rule first" %
                                       (key, desired[key], filename, number))
        stack.pop()

    visit(path)
    return hashes


def stage_configs(configs, directory):
    """Validate the entire proposed include graph without changing live files."""
    staged = {path: os.path.join(directory, str(index)) for index, path in enumerate(configs)}
    for path, content in configs.items():
        lines = []
        for line in content.decode("utf-8").splitlines(keepends=True):
            key, text = directive(line)
            if key == "include":
                included = []
                for pattern in arguments(text):
                    included.extend(staged[os.path.abspath(source)] for source in include_files(pattern))
                # An unmatched Include contributes no settings.
                line = "Include " + " ".join(json.dumps(source) for source in included) + "\n" if included else ""
            lines.append(line)
        Path(staged[path]).write_text("".join(lines))
    return staged


def verify(sshd, path, desired, context):
    run([sshd, "-t", "-f", path])
    for label, extra in (("global", []), ("oski connection", ["-C", context]),
                         ("root connection", ["-C", context.replace("user=oski,", "user=root,", 1)])):
        values = {}
        output = run([sshd, "-T", "-f", path] + extra).stdout
        for line in output.splitlines():
            key, _, value = line.partition(" ")
            values.setdefault(key.lower(), []).append(value.strip())
        if ("challengeresponseauthentication" in values and
                values["challengeresponseauthentication"] != [desired["kbdinteractiveauthentication"]]):
            raise RuntimeError("Legacy ChallengeResponseAuthentication did not match policy")
        for key, value in desired.items():
            if values.get(key) != [value]:
                raise RuntimeError("%s policy mismatch: %s expected %s, got %r" % (label, key, value, values.get(key)))
        if label == "oski connection":
            methods = " ".join(values.get("authenticationmethods", ["any"])).split()
            if "any" not in methods and "publickey" not in methods:
                raise RuntimeError("oski AuthenticationMethods does not permit a single public key; refusing possible lockout")


def snapshot(path):
    if not os.path.lexists(path):
        return None
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("Refusing nonregular, non-root-owned, or writable-by-others config: " + path)
    attrs = {name: os.getxattr(path, name) for name in os.listxattr(path)}
    return Path(path).read_bytes(), info, attrs


def install(path, content, original):
    fd, temporary = tempfile.mkstemp(prefix=".ccdc-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if original:
            _, info, attrs = original
            os.chown(temporary, info.st_uid, info.st_gid)
            os.chmod(temporary, stat.S_IMODE(info.st_mode))
            for name, value in attrs.items():
                os.setxattr(temporary, name, value)
        else:
            os.chown(temporary, 0, 0)
            os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        restorecon = shutil.which("restorecon")
        if restorecon:
            run([restorecon, path])
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def restore(path, original):
    if original is None:
        if os.path.exists(path):
            os.unlink(path)
    else:
        install(path, original[0], original)


def apply(password):
    if os.geteuid() != 0:
        raise RuntimeError("Run as root")
    pwd.getpwnam("oski")
    context = connection_context()
    sshd = daemon()
    desired = {"permitrootlogin": "no", "passwordauthentication": password,
               "kbdinteractiveauthentication": password, "pubkeyauthentication": "yes"}
    with open(os.path.join(os.path.dirname(CONFIG), ".ccdc-ssh.lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        main_original = snapshot(CONFIG)
        if main_original is None:
            raise RuntimeError("Missing " + CONFIG)
        name, reload_command, status_command = service()
        hashes = inspect(CONFIG, {})
        raw = {path: Path(path).read_bytes() for path in hashes}
        if raw[CONFIG] != main_original[0]:
            raise RuntimeError("Main SSH config changed during discovery")
        configs = {path: (policy_config(content.decode("utf-8"), desired) if path == CONFIG
                          else strip_policy(content.decode("utf-8"), desired)).encode()
                   for path, content in raw.items()}
        changed_paths = [path for path in configs if configs[path] != raw[path]]
        # Only files we will replace need writable-file safety checks and backups.
        # Unchanged crypto-policy Includes may legitimately be symlinks.
        originals = {path: snapshot(path) for path in changed_paths}
        if any(original is None or original[0] != raw[path] for path, original in originals.items()):
            raise RuntimeError("SSH config source changed during discovery")
        with tempfile.TemporaryDirectory(prefix=".ccdc-config-", dir=os.path.dirname(CONFIG)) as directory:
            staged = stage_configs(configs, directory)
            inspect(staged[CONFIG], desired)
            verify(sshd, staged[CONFIG], desired, context)
            # Also catch new Includes or files added to an Include glob.
            if inspect(CONFIG, {}) != hashes or any(
                    hashlib.sha256(content).hexdigest() != hashes[path]
                    for path, content in raw.items()):
                raise RuntimeError("Configuration changed during validation")
            if not changed_paths:
                verify(sshd, CONFIG, desired, context)
                print(json.dumps({"changed": False, "password_auth": password, "service": name}, sort_keys=True))
                return
            attempted = []
            try:
                for path in changed_paths:
                    attempted.append(path)
                    install(path, configs[path], originals[path])
                inspect(CONFIG, desired)
                verify(sshd, CONFIG, desired, context)
                run(reload_command)
                run(status_command)
                verify(sshd, CONFIG, desired, context)
            except Exception as exc:
                errors = []
                for path in reversed(attempted):
                    original = originals[path]
                    try:
                        restore(path, original)
                    except Exception as rollback_exc:
                        errors.append(str(rollback_exc))
                try:
                    run([sshd, "-t", "-f", CONFIG])
                    run(reload_command)
                    run(status_command)
                except Exception as rollback_exc:
                    errors.append(str(rollback_exc))
                suffix = "rollback FAILED: " + "; ".join(errors) if errors else "original configuration restored and reloaded"
                raise RuntimeError(str(exc) + "; " + suffix) from exc
            print(json.dumps({"changed": True, "password_auth": password, "service": name}, sort_keys=True))


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("yes", "no"):
            raise RuntimeError("Usage: apply-ssh yes|no")
        apply(sys.argv[1])
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print("apply-ssh: " + str(exc), file=sys.stderr)
        sys.exit(1)
