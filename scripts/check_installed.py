"""Fail if a clean install pulled in anything besides this package."""

import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    entries = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    installed = {str(entry["name"]).replace("_", "-") for entry in entries}
    if installed != {"shim-audit-verify"}:
        print(f"clean install contains {sorted(installed)}", file=sys.stderr)
        return 1
    print("clean install carries nothing but shim-audit-verify")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
