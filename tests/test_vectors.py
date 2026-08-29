"""Golden vectors.

These files are the shared source of truth with the shim server's own test
suite. If a change here is not mirrored by a server change, the published
verifier and the producer have diverged and one of them is lying.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from shim_audit_verify.bundle import CANONICAL_KEYS
from shim_audit_verify.hashing import canonical_row, compute_row_hash, merkle_root

ROOT = Path(__file__).resolve().parent.parent
ROW_VECTORS = sorted((ROOT / "tests" / "vectors" / "rows").glob("*.json"))
MERKLE_VECTORS = sorted((ROOT / "tests" / "vectors" / "merkle").glob("*.json"))

REQUIRED_ROW_CASES = frozenset(
    {
        "minimal",
        "empty-extra-and-zero-cost",
        "cost-eight-decimals",
        "cost-one-significant-digit-exponent",
        "cost-two-significant-digit-exponent",
        "cost-smallest-plain-form",
        "all-nullable-fields-null",
        "unicode-turkish",
        "unicode-astral",
        "nested-extra",
        "pii-entities-unsorted-input",
        "policy-verdicts",
        "created-at-with-microseconds",
        "created-at-without-microseconds",
        "large-counters",
    }
)
REQUIRED_MERKLE_CASES = frozenset(
    {"single-leaf", "two-leaves", "three-leaves-odd", "five-leaves-odd-twice"}
)


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", ROW_VECTORS, ids=lambda path: path.stem)
def test_row_vector_reproduces_its_canonical_bytes(path: Path) -> None:
    vector = _load(path)
    fields = vector["fields"]
    assert isinstance(fields, dict)
    canonical = canonical_row(fields)
    assert canonical.hex() == vector["canonical_hex"]
    assert canonical.decode("utf-8") == vector["canonical_utf8"]


@pytest.mark.parametrize("path", ROW_VECTORS, ids=lambda path: path.stem)
def test_row_vector_reproduces_its_row_hash(path: Path) -> None:
    vector = _load(path)
    fields = vector["fields"]
    assert isinstance(fields, dict)
    assert compute_row_hash(str(vector["prev_hash"]), fields) == vector["row_hash"]


@pytest.mark.parametrize("path", ROW_VECTORS, ids=lambda path: path.stem)
def test_row_vector_carries_exactly_the_canonical_keys(path: Path) -> None:
    fields = _load(path)["fields"]
    assert isinstance(fields, dict)
    assert tuple(sorted(fields)) == tuple(sorted(CANONICAL_KEYS))


@pytest.mark.parametrize("path", MERKLE_VECTORS, ids=lambda path: path.stem)
def test_merkle_vector_reproduces_its_root(path: Path) -> None:
    vector = _load(path)
    leaves = vector["leaves"]
    assert isinstance(leaves, list)
    assert merkle_root([str(leaf) for leaf in leaves]) == vector["root_hash"]


def test_the_required_cases_are_all_present() -> None:
    assert {path.stem for path in ROW_VECTORS} >= REQUIRED_ROW_CASES
    assert {path.stem for path in MERKLE_VECTORS} >= REQUIRED_MERKLE_CASES


def test_the_zero_cost_vector_really_carries_the_0e8_form() -> None:
    vector = _load(
        ROOT / "tests" / "vectors" / "rows" / "empty-extra-and-zero-cost.json"
    )
    fields = vector["fields"]
    assert isinstance(fields, dict)
    assert fields["cost_usd"] == "0E-8"


def test_the_turkish_vector_is_not_ascii_escaped() -> None:
    vector = _load(ROOT / "tests" / "vectors" / "rows" / "unicode-turkish.json")
    assert "ı" in str(vector["canonical_utf8"])
    assert "\\u" not in str(vector["canonical_utf8"])


def test_committed_vectors_are_not_stale() -> None:
    completed = subprocess.run(  # noqa: S603
        [sys.executable, str(ROOT / "scripts" / "generate_vectors.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
