#!/usr/bin/env python3
"""fix_sshd_hardening apply OPTION=VALUE... | confirm TOKEN | revert [TOKEN]: enforce declared sshd settings safely.

apply   writes ALL given settings as one change and proves it before sshd reloads:
          1. sshd_config.d/00-hardening.conf, when the main file includes sshd_config.d
             and sets none of these options before that Include (sshd keeps the FIRST
             value it reads);
          2. otherwise, or when `sshd -T -C user=...` still shows another value, a marked
             block at the very top of sshd_config.
        `sshd -t` must accept it and `sshd -T -C` (root and oski) must show every declared
        value, else everything is restored and the reason is reported (a Match block
        overriding the setting is the usual cause). Then sshd reloads and a detached
        watchdog restores the previous files unless `confirm` runs within the timeout.
confirm TOKEN cancels that change's watchdog (run only after a fresh key login worked).
revert [TOKEN] restores the previous files (or removes our drop-in/block) and reloads.
Prints one JSON object.
"""
import glob
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import time

MAIN = "/etc/ssh/sshd_config"
DROPIN_DIR = "/etc/ssh/sshd_config.d"
DROPIN = DROPIN_DIR + "/00-hardening.conf"
PREV_PREFIX = "/etc/ssh/.ccdc-prev-"  # pre-change copies, one directory per change, only while unconfirmed
TIMEOUT = 90
BEGIN = "# BEGIN CCDC managed: sshd settings declared in the inventory"
END = "# END CCDC managed"
NAME = re.compile(r"[A-Za-z][A-Za-z0-9]*")
VALUE = re.compile(r"[A-Za-z0-9_.,:@/+*-]+")  # no whitespace or newlines: nothing else can ride along
CHECK_USERS = ("root", "oski")


def parse_settings(pairs):
    """['Option=value', ...] -> {'option': 'value'}; refuses anything that is not a plain keyword/value."""
    settings = {}
    for pair in pairs:
        name, sep, value = pair.partition("=")
        if not sep or not NAME.fullmatch(name) or not VALUE.fullmatch(value):
            raise ValueError("invalid setting: %r" % pair)
        settings[name.lower()] = value
    if not settings:
        raise ValueError("no settings given")
    return settings


def parse_lines(text):
    return {parts[0].lower(): parts[1].strip() for parts in (line.split(None, 1) for line in text.splitlines()
                                                              if line.strip() and not line.lstrip().startswith("#"))
            if len(parts) == 2}


def render(settings):
    return "".join(f"{k} {v}\n" for k, v in sorted(settings.items()))


def split_block(text):
    """(text without our block, settings the block held)."""
    match = re.search(r"^%s\n(.*?)^%s\n?" % (re.escape(BEGIN), re.escape(END)), text, re.M | re.S)
    if not match:
        return text, {}
    return text[:match.start()] + text[match.end():].lstrip("\n"), parse_lines(match.group(1))


def with_block(text, settings):
    return f"{BEGIN}\n{render(settings)}{END}\n\n{text}"


def include_index(text):
    """Line index of the Include of sshd_config.d, or None."""
    for index, line in enumerate(text.splitlines()):
        if re.match(r"^\s*Include\s+.*sshd_config\.d/", line, re.I):
            return index
    return None


def set_before_include(text, names):
    """Options an earlier active line of the main file already sets (first value wins)."""
    stop = include_index(text)
    lines = text.splitlines()[: len(text.splitlines()) if stop is None else stop]
    return sorted({line.split()[0].lower() for line in lines
                   if line.strip() and not line.lstrip().startswith("#") and line.split()[0].lower() in names})


def parse_effective(output):
    values = {}
    for line in output.splitlines():
        key, _, value = line.partition(" ")
        if key:
            values.setdefault(key.lower(), value.strip().lower())
    return values


def mismatches(settings, effective_by_user):
    """[(user, option, wanted, got)] where the effective value differs from the declared one."""
    return [(user, option, wanted, effective.get(option))
            for user, effective in effective_by_user.items()
            for option, wanted in settings.items() if effective.get(option) != wanted.lower()]


# ---- system access, kept in small functions so they are easy to replace ----

def sshd_binary():
    return shutil.which("sshd") or next((p for p in ("/usr/sbin/sshd", "/usr/local/sbin/sshd") if os.path.exists(p)), None)


def sshd_test(sshd):
    result = subprocess.run([sshd, "-t"], stderr=subprocess.PIPE, text=True)
    return result.returncode == 0, result.stderr.strip()


def effective_for(sshd, user):
    result = subprocess.run([sshd, "-T", "-C", f"user={user},host=localhost,addr=127.0.0.1"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        raise RuntimeError("sshd -T failed: " + result.stderr.strip())
    return parse_effective(result.stdout)


def login_users():
    users = ["root"]
    try:
        pwd.getpwnam("oski")
        users.append("oski")
    except KeyError:
        pass
    return users


def reload_sshd():
    for unit in ("sshd", "ssh"):
        if subprocess.run(["systemctl", "reload", unit], stderr=subprocess.DEVNULL).returncode == 0:
            return True
    return False


def watchdog_command(token, timeout=TIMEOUT):
    prev, ok = PREV_PREFIX + token, PREV_PREFIX + token + ".ok"
    return ("sleep %d; if [ -f %s ]; then rm -rf %s %s; exit 0; fi; "
            "[ -f %s/main ] && cp -p %s/main %s; "
            "if [ -f %s/dropin ]; then cp -p %s/dropin %s; else rm -f %s; fi; rm -rf %s; "
            "systemctl reload sshd 2>/dev/null || systemctl reload ssh"
            % (timeout, ok, prev, ok, prev, prev, MAIN, prev, prev, DROPIN, DROPIN, prev))


def start_watchdog(token):
    subprocess.Popen(["sh", "-c", watchdog_command(token)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)


def write_atomic(path, text, like=None):
    temporary = path + ".ccdc-tmp"
    with open(temporary, "w") as handle:
        handle.write(text)
    info = os.stat(like or path) if os.path.exists(like or path) else None
    os.chmod(temporary, info.st_mode & 0o7777 if info else 0o644)
    os.replace(temporary, path)


def read(path):
    try:
        with open(path) as handle:
            return handle.read()
    except FileNotFoundError:
        return None


def restore(main_text, dropin_text):
    write_atomic(MAIN, main_text)
    if dropin_text is None:
        if os.path.exists(DROPIN):
            os.unlink(DROPIN)
    else:
        os.makedirs(DROPIN_DIR, exist_ok=True)
        write_atomic(DROPIN, dropin_text)


def pending():
    return sorted(d for d in glob.glob(PREV_PREFIX + "*") if os.path.isdir(d))


def clear_stale():
    """A change older than the watchdog timeout is a leftover (the watchdog already acted); a fresh one blocks us."""
    for directory in pending():
        if time.time() - os.stat(directory).st_mtime < TIMEOUT + 10:
            raise RuntimeError("another sshd change is still waiting for confirmation")
        shutil.rmtree(directory, ignore_errors=True)


def stage(strategy, main_text, dropin_text, settings):
    """Write `settings` using the strategy; returns nothing, raises on I/O errors."""
    stripped, _ = split_block(main_text)
    if strategy == "dropin":
        os.makedirs(DROPIN_DIR, exist_ok=True)
        write_atomic(DROPIN, "# Managed by CCDC: sshd settings declared in the inventory\n" + render(settings))
        write_atomic(MAIN, stripped)
    else:
        write_atomic(MAIN, with_block(stripped, settings))
        if dropin_text is not None and os.path.exists(DROPIN):
            os.unlink(DROPIN)  # the block now owns every managed setting


def apply(pairs):
    new = parse_settings(pairs)
    sshd = sshd_binary()
    if not sshd:
        raise RuntimeError("sshd not found")
    main_text = read(MAIN)
    if main_text is None:
        raise RuntimeError("no " + MAIN)
    dropin_text = read(DROPIN)
    stripped, block_settings = split_block(main_text)
    settings = {**block_settings, **parse_lines(dropin_text or ""), **new}
    clear_stale()
    token = os.urandom(4).hex()
    prev = PREV_PREFIX + token
    os.makedirs(prev, mode=0o700)
    write_atomic(prev + "/main", main_text, like=MAIN)
    if dropin_text is not None:
        write_atomic(prev + "/dropin", dropin_text)
    include = include_index(stripped) is not None
    first = "dropin" if include and not set_before_include(stripped, set(settings)) else "block"
    attempts = [first] + (["block"] if first == "dropin" else [])
    problems = []
    try:
        for strategy in attempts:
            stage(strategy, main_text, dropin_text, settings)
            ok, error = sshd_test(sshd)
            if not ok:
                problems.append(f"{strategy}: sshd -t rejected the configuration: {error}")
                continue
            wrong = mismatches(settings, {user: effective_for(sshd, user) for user in login_users()})
            if wrong:
                problems.append(f"{strategy}: effective value differs for " + ", ".join(
                    f"{u} {o}={g} (wanted {w})" for u, o, w, g in wrong) + "; a Match block or earlier directive wins")
                continue
            if not reload_sshd():
                problems.append(f"{strategy}: could not reload sshd")
                continue
            start_watchdog(token)
            return {"applied": True, "token": token, "strategy": strategy, "settings": settings,
                    "watchdog_seconds": TIMEOUT}
        raise RuntimeError("; ".join(problems) + "; nothing changed")
    except BaseException:
        restore(main_text, dropin_text)
        shutil.rmtree(prev, ignore_errors=True)
        raise


def confirm(token):
    """Tell the watchdog this change stays, and forget the backup so the next change can start."""
    if not re.fullmatch(r"[0-9a-f]{8}", token or ""):
        raise ValueError("bad token")
    with open(PREV_PREFIX + token + ".ok", "w"):
        pass
    shutil.rmtree(PREV_PREFIX + token, ignore_errors=True)
    return {"confirmed": True}


def revert(token=None):
    directories = [PREV_PREFIX + token] if token else pending()
    prev = directories[-1] if directories else None
    main_text = read(prev + "/main") if prev else None
    if main_text is not None:
        restore(main_text, read(prev + "/dropin"))
        shutil.rmtree(prev, ignore_errors=True)
    else:  # nothing pending: drop whatever we manage
        current = read(MAIN)
        if current is not None:
            write_atomic(MAIN, split_block(current)[0])
        if os.path.exists(DROPIN):
            os.unlink(DROPIN)
    return {"reverted": reload_sshd()}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    actions = {"apply": lambda: apply(argv[1:]), "confirm": lambda: confirm(argv[1] if len(argv) == 2 else None),
               "revert": lambda: revert(argv[1] if len(argv) == 2 else None)}
    if not argv or argv[0] not in actions or (argv[0] != "apply" and len(argv) > 2):
        print("usage: fix_sshd_hardening apply OPTION=VALUE... | confirm TOKEN | revert [TOKEN]", file=sys.stderr)
        return 2
    try:
        print(json.dumps(actions[argv[0]]()))
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
