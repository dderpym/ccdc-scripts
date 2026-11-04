"""Comment-preserving edits to inventory.yml (ruamel round-trip; never rewritten through PyYAML)."""
import copy
import io
import os
from pathlib import Path
import tempfile
import time

import yaml
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

from ccdc.runner import ROOT

INVENTORY = ROOT / "inventory.yml"
BACKUPS = ROOT / "state" / "backups"


class InventoryError(RuntimeError):
    pass


def _round_trip():
    rt = YAML()
    rt.preserve_quotes = True
    rt.width = 4096
    rt.indent(mapping=2, sequence=4, offset=2)
    return rt


def _host_maps(node, found=None):
    """Every `hosts:` mapping in the group tree: [(name, host mapping)]."""
    found = [] if found is None else found
    if isinstance(node, dict):
        hosts = node.get("hosts")
        if isinstance(hosts, dict):
            found.extend(hosts.items())
        for child in (node.get("children") or {}).values():
            _host_maps(child, found)
    return found


def _ordered(services):
    return sorted(services, key=lambda s: (s["proto"], int(s["port"])))


def _service(item):
    flow = CommentedMap([("port", int(item["port"])), ("proto", item["proto"]), ("name", item.get("name") or "unknown")])
    flow.fa.set_flow_style()
    return flow


def set_services(host, services, path=INVENTORY, backups=BACKUPS):
    """Replace host's `services:` list with `services` ([{port, proto, name}, ...]).

    Every comment and the file's ordering survive. The new text is parsed again and must
    equal the old data apart from this one key, otherwise nothing is written.
    Returns True when the file changed.
    """
    path = Path(path)
    original = path.read_text()
    rt = _round_trip()
    document = rt.load(original)
    matches = [mapping for name, mapping in _host_maps(document.get("all", document)) if name == host]
    if len(matches) != 1:
        raise InventoryError(f"cannot edit inventory safely: {host!r} appears {len(matches)} times under a hosts: mapping")
    if matches[0] is None:
        raise InventoryError(f"cannot edit inventory safely: host {host!r} has no mapping to attach services to")
    matches[0]["services"] = CommentedSeq(_service(item) for item in _ordered(services))
    out = io.StringIO()
    rt.dump(document, out)
    updated = out.getvalue()
    # Guard: only this host's services key may differ.
    expected = copy.deepcopy(yaml.safe_load(original))
    for name, mapping in _host_maps(expected.get("all", expected)):
        if name == host:
            mapping["services"] = [dict(port=int(s["port"]), proto=s["proto"], name=s.get("name") or "unknown")
                                   for s in _ordered(services)]
    if yaml.safe_load(updated) != expected:
        raise InventoryError("refusing to write: the edit would change more than the services list")
    if updated == original:
        return False
    backups = Path(backups)
    backups.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = time.strftime("%Y%m%d-%H%M%S") + "-%06d" % (time.time_ns() % 10**6)
    (backups / f"inventory.yml.{stamp}.bak").write_text(original)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=".inventory-", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(updated)
    try:
        os.chmod(temporary, path.stat().st_mode & 0o777)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return True
