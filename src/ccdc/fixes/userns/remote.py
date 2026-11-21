#!/usr/bin/env python3
"""fix_sysctl NAME...: set each allow-listed sysctl to 0 now and persist it; prints JSON."""
import json
import sys

import sysctls


def main(argv=None):
    names = sys.argv[1:] if argv is None else argv
    try:
        sysctls.apply_sysctl({"kind": "sysctl", "settings": dict.fromkeys(names, "0")})
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps({"disabled": sorted(names)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
