#!/usr/bin/env python3
"""Check that supplied hosts/URLs are explicitly present in a scope file."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import Scope, ScopeError, result_document, write_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="JSON file containing authorised domains/CIDRs/ports")
    parser.add_argument("targets", nargs="+", help="URLs or host/IP values to validate; no connections are made")
    parser.add_argument("--output", help="Write JSON results to this path")
    args = parser.parse_args()
    scope = Scope.from_file(args.scope)
    checks = []
    denied = 0
    for target in args.targets:
        try:
            if "://" in target:
                scope.check_url(target)
            else:
                if not scope.allows_host(target):
                    raise ScopeError(f"Host {target!r} is outside the authorised scope")
            checks.append({"target": target, "status": "IN_SCOPE", "reason": "Matched explicit allow-list"})
        except (ScopeError, ValueError) as exc:
            denied += 1
            checks.append({"target": target, "status": "OUT_OF_SCOPE", "reason": str(exc)})
    document = result_document("scope-check", ", ".join(args.targets), [], checks=checks)
    write_json(document, args.output)
    return 1 if denied else 0


if __name__ == "__main__":
    raise SystemExit(main())
