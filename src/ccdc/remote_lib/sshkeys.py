"""authorized_keys / .pub line parsing shared by the ssh scan and the key-removal fix."""
import base64
import binascii
import hashlib
import re

KEY_TYPE = re.compile(r"^(ssh-[a-z0-9]+|ecdsa-sha2-nistp\d+|sk-[a-z0-9@.-]+)$")


def fingerprint(blob):
    raw = base64.b64decode(blob, validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def parse_key_line(line):
    """(fingerprint, comment) for an authorized_keys/.pub line, else None. Options may precede the key."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    tokens = line.split()
    for index, token in enumerate(tokens[:-1]):
        if KEY_TYPE.match(token):
            try:
                return fingerprint(tokens[index + 1]), " ".join(tokens[index + 2:])
            except (binascii.Error, ValueError):
                return None
    return None
