#!/usr/bin/env python3
"""Files in system dirs that no package owns (logic in remote_lib/unowned.py, shared with the quarantine fix)."""
import sys

import unowned

if __name__ == "__main__":
    unowned.main()
