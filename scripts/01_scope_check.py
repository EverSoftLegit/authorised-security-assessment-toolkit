#!/usr/bin/env python3
"""Check that supplied URLs, IPs, or host[:port] values are in an explicit scope file.

No network connections or DNS lookups are made.
Exit codes: 0 all in scope, 1 at least one target out of scope, 2 bad scope file.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import Scope, check_target, result_document, write_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="JSON file containing authorised domains/CIDRs/ports")
    parser.add_argument("targets", nargs="+", help="URLs, IPs, or host[:port] values to validate")
    parser.add_argument("--output", help="Write JSON results to this path")
    args = parser.parse_args()
    try:
        scope = Scope.from_file(args.scope)
    except (OSError, ValueError) as exc:
        parser.error(f"Cannot load scope file: {exc}")  # exits with status 2

    checks = []
    for target in args.targets:
        try:
            check_target(scope, target)
            checks.append({"target": target, "status": "IN_SCOPE", "reason": "Matched explicit allow-list"})
        except ValueError as exc:  # ScopeError is a ValueError; urlsplit raises ValueError on bad brackets
            checks.append({"target": target, "status": "OUT_OF_SCOPE", "reason": str(exc)})

    denied = sum(1 for check in checks if check["status"] != "IN_SCOPE")
    document = result_document("scope-check", ", ".join(args.targets), [], checks=checks)
    write_json(document, args.output)
    return 1 if denied else 0


if __name__ == "__main__":
    raise SystemExit(main())
