"""The published examples must behave exactly as the README claims.

These files are what a stranger downloads. If the README's expected output and
the committed file ever disagree, the whole exercise is worthless.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from shim_audit_verify.cli import EXIT_FAILED, EXIT_OK, main

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "shim-audit-sample.json"
TAMPERED = ROOT / "examples" / "shim-audit-sample-tampered.json"


def test_the_sample_verifies(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(SAMPLE)]) == EXIT_OK
    lines = capsys.readouterr().out.splitlines()
    assert lines[1] == (
        "chain    OK          rows 1..305 (305 checked)   anchored to genesis"
    )
    assert lines[2] == "anchors  OK          5 verified, 0 skipped"


def test_the_tampered_copy_names_the_altered_row(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([str(TAMPERED)]) == EXIT_FAILED
    lines = capsys.readouterr().out.splitlines()
    assert lines[1] == "chain    BROKEN      first break at seq 173: row_hash_mismatch"
    assert lines[2] == "                     last verified seq 172"


def test_the_tampered_copy_differs_from_the_sample_in_exactly_one_field() -> None:
    sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
    tampered = json.loads(TAMPERED.read_text(encoding="utf-8"))
    differing = [
        (row["seq"], key)
        for row, other in zip(sample["rows"], tampered["rows"], strict=True)
        for key in row
        if row[key] != other[key]
    ]
    assert differing == [(173, "prompt_tokens")]


def test_the_sample_carries_no_production_looking_data() -> None:
    text = SAMPLE.read_text(encoding="utf-8")
    sample = json.loads(text)
    assert sample["organization_id"] == "3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
    # Every address in the sample is on the reserved .test TLD.
    actors = {row["actor"] for row in sample["rows"]}
    assert all(actor.endswith("@example.test") for actor in actors)
    assert "getshim.tech" not in text
    assert "supabase" not in text.casefold()


def test_the_sample_demonstrates_what_it_is_published_to_show() -> None:
    sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
    rows = sample["rows"]
    assert len({str(row["created_at"])[:10] for row in rows}) >= 3
    assert any(row["pii_detected"] for row in rows)
    assert any(row["policy_verdicts"] for row in rows)
    assert any(row["cost_usd"] == "0E-8" for row in rows)
    # Sub-microcent costs render in scientific notation. A sample without one
    # would let a reimplementation look correct while getting them wrong.
    assert {row["cost_usd"] for row in rows if "E-" in row["cost_usd"]} - {"0E-8"}
    assert any(not str(row["extra"]["tag"]).isascii() for row in rows)


def test_committed_examples_are_not_stale() -> None:
    completed = subprocess.run(  # noqa: S603
        [sys.executable, str(ROOT / "scripts" / "generate_examples.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
