"""Fail if the package gained a way to talk to anything but its input file.

The verifier's whole value is that a stranger can run it on an untrusted file
without wondering what else it did. That is a property of the import graph, so
it is checked mechanically rather than promised in a README.
"""

import ast
import sys
from pathlib import Path

BANNED_MODULES = frozenset(
    {
        "http",
        "os",
        "requests",
        "shutil",
        "socket",
        "ssl",
        "subprocess",
        "tempfile",
        "urllib",
        "webbrowser",
    }
)


def _imported_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def main(argv: list[str]) -> int:
    root = Path(argv[0] if argv else "src")
    offences: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for module in sorted(_imported_roots(tree) & BANNED_MODULES):
            offences.append(f"{path}: imports {module}")
    for offence in offences:
        print(offence, file=sys.stderr)
    if offences:
        return 1
    print("no network, subprocess or environment access in the package")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
