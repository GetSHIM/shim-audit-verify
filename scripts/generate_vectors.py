"""Regenerate the golden test vectors.

The vectors are the single source of truth shared with the shim server's own
test suite: the server proves it reproduces them, so the published verifier can
never quietly become a liar about the server's format.

Run ``python scripts/generate_vectors.py --check`` to fail if the committed
vectors no longer match what the current code produces.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from shim_audit_verify.hashing import (
    canonical_row,
    compute_row_hash,
    genesis_hash,
    merkle_root,
)

ROOT = Path(__file__).resolve().parent.parent
ROW_DIR = ROOT / "tests" / "vectors" / "rows"
MERKLE_DIR = ROOT / "tests" / "vectors" / "merkle"
MANIFEST = ROOT / "tests" / "vectors" / "SHA256SUMS"

# A published constant, never a deployment salt. Its only job is to make the
# vectors reproducible by anyone who checks out this repository.
TEST_SALT = "shim-audit-verify-test-salt"
ORG = "3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
GENESIS = genesis_hash(TEST_SALT, ORG)
SECOND_PREV = "a" * 64


def _row(**overrides: object) -> dict[str, object]:
    """Return a canonical field object with the given fields replaced."""
    base: dict[str, object] = {
        "seq": 1,
        "organization_id": ORG,
        "created_at": "2026-08-01T09:00:00+00:00",
        "event_type": "ai_request",
        "request_id": "req-0001",
        "api_key_id": "11111111-2222-4333-8444-555555555555",
        "actor": "auditor@example.test",
        "model": "claude-sonnet-4",
        "provider": "anthropic",
        "gateway_version": "shim-gateway/1.4.2",
        "endpoint": "/v1/chat/completions",
        "input_hash": "b" * 64,
        "output_hash": "c" * 64,
        "prompt_tokens": 120,
        "completion_tokens": 340,
        "pii_detected": False,
        "pii_entities": {},
        "policy_verdicts": [],
        "is_cache_hit": False,
        "latency_ms": 87,
        "cost_usd": "0.00120000",
        "extra": {},
    }
    base.update(overrides)
    return base


ROW_VECTORS: list[tuple[str, str, dict[str, object]]] = [
    ("minimal", GENESIS, _row()),
    (
        "empty-extra-and-zero-cost",
        GENESIS,
        _row(cost_usd="0E-8", is_cache_hit=True, extra={}),
    ),
    (
        "cost-eight-decimals",
        SECOND_PREV,
        _row(seq=2, cost_usd="123.45678900", request_id="req-0002"),
    ),
    (
        "cost-one-significant-digit-exponent",
        SECOND_PREV,
        _row(seq=3, cost_usd="1E-8", request_id="req-0003"),
    ),
    (
        "cost-two-significant-digit-exponent",
        SECOND_PREV,
        _row(seq=5, cost_usd="1.2E-7", request_id="req-0005"),
    ),
    (
        "cost-smallest-plain-form",
        SECOND_PREV,
        _row(seq=6, cost_usd="0.00000123", request_id="req-0006"),
    ),
    (
        "all-nullable-fields-null",
        SECOND_PREV,
        _row(
            seq=7,
            request_id=None,
            api_key_id=None,
            actor=None,
            model=None,
            provider=None,
            gateway_version=None,
            endpoint=None,
            input_hash=None,
            output_hash=None,
        ),
    ),
    (
        "unicode-turkish",
        GENESIS,
        _row(
            actor="ölçüm.uzmanı@örnek.tr",
            model="şahin-1",
            extra={"etiket": "müşteri-görüşmesi", "not": "İzmir şubesi, çağrı #7"},
        ),
    ),
    (
        "unicode-astral",
        GENESIS,
        _row(extra={"emoji": "🔐🇹🇷", "mixed": "ok — 完了"}),
    ),
    (
        "nested-extra",
        GENESIS,
        _row(
            extra={
                "tag": "team-a",
                "route": {"attempt": 2, "fallback": {"provider": "openai", "ok": True}},
                "scores": [0.85, 0.5, 1.0],
                "empty_list": [],
                "empty_object": {},
                "null_value": None,
            }
        ),
    ),
    (
        "pii-entities-unsorted-input",
        GENESIS,
        _row(
            pii_detected=True,
            # Written out of order on purpose: sort_keys must make this irrelevant.
            pii_entities={"TR_TCKN": 2, "CREDIT_CARD": 1, "EMAIL_ADDRESS": 3},
        ),
    ),
    (
        "policy-verdicts",
        GENESIS,
        _row(
            policy_verdicts=[
                {"code": "pii.redact", "outcome": "applied", "severity": 2},
                {"code": "budget.cap", "outcome": "allow"},
            ]
        ),
    ),
    (
        "created-at-with-microseconds",
        GENESIS,
        _row(created_at="2026-08-01T09:00:00.123456+00:00"),
    ),
    (
        "created-at-without-microseconds",
        GENESIS,
        _row(created_at="2026-08-01T09:00:00+00:00", seq=4),
    ),
    (
        "large-counters",
        SECOND_PREV,
        _row(
            seq=9_007_199_254_740_993,
            prompt_tokens=2_000_000,
            completion_tokens=0,
            latency_ms=0,
            cost_usd="9999.99999999",
        ),
    ),
]

MERKLE_VECTORS: list[tuple[str, int]] = [
    ("single-leaf", 1),
    ("two-leaves", 2),
    ("three-leaves-odd", 3),
    ("four-leaves", 4),
    ("five-leaves-odd-twice", 5),
    ("seven-leaves", 7),
    ("sixteen-leaves", 16),
]


def _leaves(count: int) -> list[str]:
    return [compute_row_hash(GENESIS, _row(seq=index)) for index in range(1, count + 1)]


def build() -> dict[Path, str]:
    """Return every vector file path mapped to its exact serialized content."""
    files: dict[Path, str] = {}
    for name, prev_hash, fields in ROW_VECTORS:
        canonical = canonical_row(fields)
        files[ROW_DIR / f"{name}.json"] = json.dumps(
            {
                "name": name,
                "prev_hash": prev_hash,
                "fields": fields,
                "canonical_utf8": canonical.decode("utf-8"),
                "canonical_hex": canonical.hex(),
                "row_hash": compute_row_hash(prev_hash, fields),
            },
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
    for name, count in MERKLE_VECTORS:
        leaves = _leaves(count)
        files[MERKLE_DIR / f"{name}.json"] = json.dumps(
            {"name": name, "leaves": leaves, "root_hash": merkle_root(leaves)},
            indent=2,
            sort_keys=True,
        )
    # The manifest is what the shim server's test suite compares its copy of
    # these vectors against. Without it the two sides could drift apart and each
    # stay internally consistent, which is the one failure mode that would make
    # the published verifier quietly wrong about the producer.
    digests = sorted(
        (
            str(path.relative_to(MANIFEST.parent)),
            hashlib.sha256((content + "\n").encode("utf-8")).hexdigest(),
        )
        for path, content in files.items()
    )
    files[MANIFEST] = "\n".join(f"{digest}  {name}" for name, digest in digests)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="fail if committed vectors are stale"
    )
    arguments = parser.parse_args(argv)
    files = build()
    if arguments.check:
        stale = [
            path
            for path, content in files.items()
            if not path.exists() or path.read_text(encoding="utf-8") != content + "\n"
        ]
        existing = (
            set(ROW_DIR.glob("*.json")) | set(MERKLE_DIR.glob("*.json")) | {MANIFEST}
        )
        orphaned = sorted(existing - set(files))
        for path in [*stale, *orphaned]:
            print(f"stale: {path.relative_to(ROOT)}", file=sys.stderr)
        return 1 if stale or orphaned else 0
    ROW_DIR.mkdir(parents=True, exist_ok=True)
    MERKLE_DIR.mkdir(parents=True, exist_ok=True)
    for path, content in files.items():
        path.write_text(content + "\n", encoding="utf-8")
    print(f"wrote {len(files)} vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
