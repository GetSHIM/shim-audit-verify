"""Guard the invariants a release must satisfy before anything is published.

Every release job re-runs this against the tree it is about to act on, so a
mismatch cannot slip through by being checked once, early, somewhere else.
"""

import argparse
import os
import sys
import tomllib
from pathlib import Path


def _version(root: Path) -> str:
    manifest = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return str(manifest["project"]["version"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="the source tree to check")
    parser.add_argument(
        "--artifacts",
        type=Path,
        default=None,
        help="a directory that must hold exactly the versioned wheel and sdist",
    )
    arguments = parser.parse_args(argv)

    tag = os.environ.get("GITHUB_REF_NAME")
    if not tag:
        print("GITHUB_REF_NAME is not set", file=sys.stderr)
        return 1
    version = _version(arguments.root)
    if tag != f"v{version}":
        print(f"tag {tag} does not match project version {version}", file=sys.stderr)
        return 1

    changelog = (arguments.root / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## [{version}]" not in changelog:
        print(f"CHANGELOG.md has no section for {version}", file=sys.stderr)
        return 1

    if arguments.artifacts is not None:
        expected = {
            f"shim_audit_verify-{version}-py3-none-any.whl",
            f"shim_audit_verify-{version}.tar.gz",
        }
        found = {path.name for path in arguments.artifacts.iterdir()}
        if found != expected:
            print(
                f"expected {sorted(expected)}, found {sorted(found)}", file=sys.stderr
            )
            return 1

    print(f"release metadata for {tag} is consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
