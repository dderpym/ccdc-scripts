#!/usr/bin/env python3
"""Read-only SSH discovery. --context accepts sshd -C syntax; --config is diagnostic.

Ansible: ansible.builtin.script: scripts/discover-ssh (stdout is one JSON object).
No context means global defaults, NOT the policy for all possible Match blocks.
"""
import argparse
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

REQUIRED = "permitrootlogin passwordauthentication kbdinteractiveauthentication pubkeyauthentication authorizedkeysfile allowusers allowgroups denyusers denygroups port listenaddress".split()


def run(args):
    p = subprocess.run(args, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if p.returncode:
        raise RuntimeError(p.stderr.strip() or "command failed: " + " ".join(args))
    return p.stdout


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
    raise RuntimeError("Cannot find sshd; bootstrap does not install or reconfigure SSH")


def effective(output):
    result = {key: [] for key in REQUIRED}
    for line in output.splitlines():
        key, _, value = line.partition(" ")
        result.setdefault(key.lower(), []).append(value.strip())
    return result


def directive(line):
    # Keep in sync with apply-ssh; strdelim allows Ma"tch", too.
    match = re.match(r'^\s*(?:([^"\s=#]*)"([^"]*)"|([^"\s=#]+))[\s=]*(.*)$', line)
    if not match:
        return "", ""
    return (match[3] or (match[1] + match[2])).lower(), match[4]


def arguments(text):
    """OpenSSH argv_split semantics, not shell escaping/comment semantics.

    Keep in sync with apply-ssh: targets receive each script standalone.
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


def sources(config):
    hashes, caveats, stack = {}, [], []

    def visit(path, conditional=False):
        path = os.path.abspath(path)
        if path in stack or len(stack) >= 32 or len(hashes) >= 512:
            raise RuntimeError("Include cycle or excessive config graph at " + path)
        raw = Path(path).read_bytes()
        hashes[path] = hashlib.sha256(raw).hexdigest()
        stack.append(path)
        match_rules = []
        for line in raw.decode("utf-8", errors="replace").splitlines():
            key, text = directive(line)
            if not key:
                continue
            values = arguments(text)
            if key == "match":
                conditional = True
                caveats.append("Match in %s: %s" % (path, text))
            if conditional:
                # Keep conditional semantics even when no connection context was supplied.
                name = "kbdinteractiveauthentication" if key == "challengeresponseauthentication" else key
                match_rules.append({"directive": name, "arguments": values})
            if key == "include":
                if conditional:
                    caveats.append("Conditional Include in " + path + "; sources are potential, not necessarily active")
                for pattern in values:
                    for included in include_files(pattern):
                        rules = visit(included, conditional)
                        if rules:
                            # sshd restores the caller's Match scope after each file.
                            match_rules.append({"directive": "include", "rules": rules})
        stack.pop()
        return match_rules

    match_rules = visit(config)
    return hashes, sorted(set(caveats)), match_rules


def socket_listeners():
    result = {}
    tool = shutil.which('systemctl')
    if tool and os.path.isdir('/run/systemd/system'):
        for name in ('ssh.socket', 'sshd.socket'):
            output = run([tool, 'show', name, '--property=Id,ActiveState,Listen'])
            fields = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
            if fields.get('ActiveState') == 'active':
                result[fields.get('Id', name)] = fields.get('Listen', '')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/ssh/sshd_config")
    parser.add_argument("--context", default=os.environ.get("CCDC_SSH_CONTEXT") or None,
                        help="sshd -C user=oski,host=...,addr=...,laddr=...,lport=...")
    args = parser.parse_args()
    sshd = daemon()
    hashes, caveats, match_rules = sources(args.config)
    command = [sshd, "-T", "-f", args.config]
    if args.context:
        command += ["-C", args.context]
    caveats.append("Effective values describe only the specified context, or global defaults if context is null; Match may differ for other connections")
    caveats.append("Service command-line overrides are not represented by sshd -T -f; socket_listeners separately reports active systemd SSH socket bindings")
    dropins = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
               for path in sorted(glob.glob('/etc/ssh/sshd_config.d/*')) if os.path.isfile(path)}
    print(json.dumps({"effective": effective(run(command)), "sources": hashes, "dropins": dropins,
                      "context": args.context, "socket_listeners": socket_listeners(),
                      "match_rules": match_rules, "caveats": sorted(set(caveats)),
                      "sshd": sshd}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print("discover-ssh: " + str(exc), file=sys.stderr)
        sys.exit(1)
