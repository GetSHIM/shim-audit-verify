"""Output and exit-code contract.

The exit codes are what a CI pipeline or an auditor's script keys on, so they
are pinned as tightly as the hashes are.
"""

import io
import json
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from shim_audit_verify.cli import EXIT_FAILED, EXIT_INPUT, EXIT_OK, main

Writer = Callable[[dict[str, Any]], str]


@pytest.fixture
def written(tmp_path: Path) -> Writer:
    """Serialize a bundle to a temporary file and return its path."""

    def write(bundle: dict[str, Any]) -> str:
        path = tmp_path / "bundle.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        return str(path)

    return write


def test_a_valid_bundle_exits_zero_and_reports_ok(
    bundle: dict[str, Any], written: Writer, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([written(bundle)]) == EXIT_OK
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("bundle   shim.audit.bundle v1   org 3f2b…   gateway ")
    assert lines[1] == (
        f"chain    OK          rows 1..{bundle['row_count']} "
        f"({bundle['row_count']} checked)   anchored to genesis"
    )
    assert lines[2] == "anchors  OK          4 verified, 0 skipped"


def test_a_broken_chain_exits_one_and_names_the_row(
    bundle: dict[str, Any], written: Writer, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle["rows"][11]["prompt_tokens"] += 1
    assert main([written(bundle)]) == EXIT_FAILED
    lines = capsys.readouterr().out.splitlines()
    assert lines[1] == ("chain    BROKEN      first break at seq 12: row_hash_mismatch")
    assert lines[2] == "                     last verified seq 11"


def test_a_break_on_the_first_row_says_nothing_was_verified(
    bundle: dict[str, Any], written: Writer, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle["genesis_hash"] = "0" * 64
    assert main([written(bundle)]) == EXIT_FAILED
    assert "no rows verified" in capsys.readouterr().out


def test_an_anchor_mismatch_shows_both_roots(
    bundle: dict[str, Any], written: Writer, capsys: pytest.CaptureFixture[str]
) -> None:
    stored = "9" * 64
    bundle["anchors"][2]["root_hash"] = stored
    assert main([written(bundle)]) == EXIT_FAILED
    output = capsys.readouterr().out
    assert "anchors  MISMATCH    " in output
    assert f"root differs (stored {stored[:4]}…, recomputed " in output


def test_several_anchor_mismatches_each_get_a_line(
    bundle: dict[str, Any], written: Writer, capsys: pytest.CaptureFixture[str]
) -> None:
    for index in (0, 2):
        bundle["anchors"][index]["row_count"] += 1
    assert main([written(bundle)]) == EXIT_FAILED
    lines = capsys.readouterr().out.splitlines()
    assert sum("root differs" in line for line in lines) == 2
    assert lines[-1].strip() == "4 checked, 2 mismatched, 0 skipped"


def test_an_anchor_naming_a_missing_day_says_so(
    builder: ModuleType, written: Writer, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = builder.build_bundle([6, 0, 7])
    bundle["anchors"].append(
        {
            "anchor_date": "2026-08-02",
            "root_hash": "4" * 64,
            "tip_hash": "5" * 64,
            "row_count": 3,
            "from_seq": 2,
            "to_seq": 4,
        }
    )
    assert main([written(bundle)]) == EXIT_FAILED
    assert "2026-08-02 has no rows in the bundle (anchor claims 3)" in (
        capsys.readouterr().out
    )


def test_a_partial_export_says_it_is_not_anchored_to_genesis(
    bundle: dict[str, Any],
    builder: ModuleType,
    written: Writer,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([written(builder.slice_bundle(bundle, 7, 18))]) == EXIT_OK
    lines = capsys.readouterr().out.splitlines()
    assert lines[1] == "chain    OK          rows 7..18 (12 checked)"
    assert (
        lines[2] == "                     anchored to declared prev_hash (not genesis)"
    )


def test_a_broken_partial_export_still_shows_the_genesis_note(
    bundle: dict[str, Any],
    builder: ModuleType,
    written: Writer,
    capsys: pytest.CaptureFixture[str],
) -> None:
    partial = builder.slice_bundle(bundle, 7, 18)
    partial["rows"][2]["latency_ms"] += 1
    assert main([written(partial)]) == EXIT_FAILED
    assert "anchored to declared prev_hash (not genesis)" in capsys.readouterr().out


def test_a_bundle_without_anchors_reports_none(
    bundle: dict[str, Any], written: Writer, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle["anchors"] = []
    assert main([written(bundle)]) == EXIT_OK
    assert "anchors  NONE        0 verified, 0 skipped" in capsys.readouterr().out


def test_json_output_matches_the_documented_schema(
    bundle: dict[str, Any], written: Writer, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([written(bundle), "--json"]) == EXIT_OK
    report = json.loads(capsys.readouterr().out)
    assert set(report) == {
        "ok",
        "rows_checked",
        "first_break",
        "last_verified_seq",
        "anchors_checked",
        "anchor_mismatches",
        "anchors_skipped",
        "from_seq",
        "to_seq",
        "anchored_to_genesis",
    }
    assert report["ok"] is True
    assert report["first_break"] is None
    assert report["anchor_mismatches"] == []


def test_json_output_carries_the_break_detail(
    bundle: dict[str, Any], written: Writer, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle["rows"][11]["prompt_tokens"] += 1
    assert main([written(bundle), "--json"]) == EXIT_FAILED
    report = json.loads(capsys.readouterr().out)
    assert report["first_break"] == {
        "seq": 12,
        "id": None,
        "reason": "row_hash_mismatch",
    }
    assert report["last_verified_seq"] == 11


def test_json_output_carries_anchor_detail(
    bundle: dict[str, Any],
    builder: ModuleType,
    written: Writer,
    capsys: pytest.CaptureFixture[str],
) -> None:
    partial = builder.slice_bundle(bundle, 7, 18)
    partial["anchors"][1]["tip_hash"] = "8" * 64
    assert main([written(partial), "--json"]) == EXIT_FAILED
    report = json.loads(capsys.readouterr().out)
    assert report["anchor_mismatches"][0]["stored_row_count"] == 5
    assert report["anchors_skipped"][0]["reason"] == "incomplete_day"


def test_quiet_prints_nothing_on_success(
    bundle: dict[str, Any], written: Writer, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([written(bundle), "--quiet"]) == EXIT_OK
    assert capsys.readouterr().out == ""


def test_quiet_prints_nothing_on_failure(
    bundle: dict[str, Any], written: Writer, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle["rows"][0]["latency_ms"] += 1
    assert main([written(bundle), "--quiet", "--json"]) == EXIT_FAILED
    assert capsys.readouterr().out == ""


def test_a_bundle_can_be_read_from_stdin(
    bundle: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(bundle)))
    assert main(["-", "--quiet"]) == EXIT_OK


def test_a_missing_file_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(tmp_path / "absent.json")]) == EXIT_INPUT
    assert "cannot read" in capsys.readouterr().err


def test_a_non_utf8_file_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "binary.json"
    path.write_bytes(b"\xff\xfe\x00")
    assert main([str(path)]) == EXIT_INPUT
    assert "is not UTF-8 text" in capsys.readouterr().err


def test_a_schema_violation_is_an_input_error_not_a_failure(
    bundle: dict[str, Any], written: Writer, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle["rows"][0]["cost_usd"] = "0"
    assert main([written(bundle)]) == EXIT_INPUT
    assert "cost_usd" in capsys.readouterr().err
