"""Regenerate the published example bundles.

Everything here is synthetic and built in memory. No database is read, so no
production salt, real tenant id or real traffic can reach a published file.

``python scripts/generate_examples.py --check`` fails if the committed examples
no longer match what the current code produces.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import chain

from shim_audit_verify.verify import verify_bundle

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
SAMPLE = EXAMPLES / "shim-audit-sample.json"
TAMPERED = EXAMPLES / "shim-audit-sample-tampered.json"

# Five days, a few hundred rows: enough to carry several anchors and to make the
# tampered copy's break land somewhere a reader has to trust the tool to find.
SHAPE = [58, 64, 51, 72, 60]
TAMPERED_SEQ = 173


def _require_coverage(bundle: dict[str, object]) -> None:
    """Fail loudly if the sample stops demonstrating what it is published to show."""
    rows = bundle["rows"]
    assert isinstance(rows, list)
    anchors = bundle["anchors"]
    assert isinstance(anchors, list)
    assert len(anchors) >= 3, "the sample must span at least three anchored days"
    assert any(row["pii_detected"] for row in rows), "no PII detection in the sample"
    assert any(row["policy_verdicts"] for row in rows), (
        "no policy verdict in the sample"
    )
    assert any(row["cost_usd"] == "0E-8" for row in rows), "no zero-cost row"
    exponents = {str(row["cost_usd"]) for row in rows if "E-" in str(row["cost_usd"])}
    assert exponents - {"0E-8"}, "no sub-microcent cost in the sample"
    assert any(row["api_key_id"] is None for row in rows), "no console-origin row"
    assert any(not str(row["extra"]["tag"]).isascii() for row in rows), (
        "no non-ASCII extra in the sample"
    )
    assert verify_bundle(bundle).ok, "the sample must verify"


def build() -> dict[Path, str]:
    """Return both example files mapped to their exact serialized content."""
    sample = chain.build_bundle(SHAPE)
    _require_coverage(sample)

    tampered = json.loads(json.dumps(sample))
    target = next(row for row in tampered["rows"] if row["seq"] == TAMPERED_SEQ)
    target["prompt_tokens"] = int(target["prompt_tokens"]) + 1
    report = verify_bundle(tampered)
    assert report.first_break is not None
    assert report.first_break.seq == TAMPERED_SEQ
    assert report.first_break.reason == "row_hash_mismatch"

    return {
        SAMPLE: json.dumps(sample, indent=2, ensure_ascii=False, sort_keys=True),
        TAMPERED: json.dumps(tampered, indent=2, ensure_ascii=False, sort_keys=True),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="fail if committed examples are stale"
    )
    arguments = parser.parse_args(argv)
    files = build()
    if arguments.check:
        stale = [
            path
            for path, content in files.items()
            if not path.exists() or path.read_text(encoding="utf-8") != content + "\n"
        ]
        for path in stale:
            print(f"stale: {path.relative_to(ROOT)}", file=sys.stderr)
        return 1 if stale else 0
    EXAMPLES.mkdir(exist_ok=True)
    for path, content in files.items():
        path.write_text(content + "\n", encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
