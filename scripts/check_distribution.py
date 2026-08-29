"""Fail if a built distribution declares any runtime dependency.

"Zero dependencies" is a promise this package makes to auditors, so it is
checked against the built artefact rather than against the source that was
supposed to produce it.
"""

import sys
from pathlib import Path
from zipfile import ZipFile


def main(argv: list[str]) -> int:
    wheels = sorted(Path(argv[0] if argv else "dist").glob("*.whl"))
    if len(wheels) != 1:
        print(f"expected exactly one wheel, found {wheels}", file=sys.stderr)
        return 1
    archive = ZipFile(wheels[0])
    names = archive.namelist()
    if "shim_audit_verify/hashing.py" not in names:
        print("the wheel does not contain the package", file=sys.stderr)
        return 1
    metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
    metadata = archive.read(metadata_name).decode("utf-8")
    requires = [
        line for line in metadata.splitlines() if line.startswith("Requires-Dist:")
    ]
    if requires:
        print(f"the wheel declares dependencies: {requires}", file=sys.stderr)
        return 1
    print(f"{wheels[0].name} declares no runtime dependencies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
