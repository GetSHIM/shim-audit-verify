"""Tamper matrix.

One test per way a chain can be broken, plus the cases a verifier must *not*
call tampering: a reordered object, a partial export, a day that has no anchor
yet. False alarms destroy a verifier's usefulness as surely as false passes.
"""

from types import ModuleType
from typing import Any

import pytest

from shim_audit_verify.verify import verify_bundle


def _zero_cost_row(bundle: dict[str, Any]) -> dict[str, Any]:
    rows = [row for row in bundle["rows"] if row["cost_usd"] == "0E-8"]
    assert rows, "the fixture must exercise the 0E-8 cost form"
    return rows[0]


def test_an_untampered_bundle_verifies(bundle: dict[str, Any]) -> None:
    report = verify_bundle(bundle)
    assert report.ok
    assert report.first_break is None
    assert report.rows_checked == bundle["row_count"]
    assert report.last_verified_seq == bundle["rows"][-1]["seq"]
    assert report.anchors_checked == len(bundle["anchors"])
    assert report.anchors_skipped == ()
    assert report.anchored_to_genesis


def test_deleting_a_row_breaks_the_sequence(bundle: dict[str, Any]) -> None:
    del bundle["rows"][10]
    bundle["row_count"] -= 1
    report = verify_bundle(bundle)
    assert not report.ok
    assert report.first_break is not None
    assert report.first_break.reason == "seq_gap"
    assert report.first_break.seq == 12
    assert report.last_verified_seq == 10


def test_duplicating_a_row_breaks_the_sequence(bundle: dict[str, Any]) -> None:
    bundle["rows"].insert(5, dict(bundle["rows"][5]))
    bundle["row_count"] += 1
    report = verify_bundle(bundle)
    assert report.first_break is not None
    assert report.first_break.reason == "seq_gap"


def test_swapping_two_rows_breaks_the_sequence(bundle: dict[str, Any]) -> None:
    rows = bundle["rows"]
    rows[4], rows[5] = rows[5], rows[4]
    report = verify_bundle(bundle)
    assert report.first_break is not None
    assert report.first_break.reason == "seq_gap"
    assert report.first_break.seq == 6


def test_a_forged_genesis_in_the_envelope_is_caught(bundle: dict[str, Any]) -> None:
    bundle["genesis_hash"] = "0" * 64
    report = verify_bundle(bundle)
    assert report.first_break is not None
    assert report.first_break.reason == "genesis_mismatch"
    assert report.first_break.seq == 1
    assert report.last_verified_seq is None


def test_a_first_row_pointing_elsewhere_is_a_genesis_mismatch(
    bundle: dict[str, Any],
) -> None:
    bundle["rows"][0]["prev_hash"] = "1" * 64
    report = verify_bundle(bundle)
    assert report.first_break is not None
    assert report.first_break.reason == "genesis_mismatch"
    assert report.first_break.seq == 1


def test_a_relinked_middle_row_is_a_prev_hash_mismatch(bundle: dict[str, Any]) -> None:
    bundle["rows"][7]["prev_hash"] = "2" * 64
    report = verify_bundle(bundle)
    assert report.first_break is not None
    assert report.first_break.reason == "prev_hash_mismatch"
    assert report.first_break.seq == 8
    assert report.last_verified_seq == 7


def test_editing_a_counter_is_a_row_hash_mismatch(bundle: dict[str, Any]) -> None:
    bundle["rows"][12]["prompt_tokens"] += 1
    report = verify_bundle(bundle)
    assert report.first_break is not None
    assert report.first_break.reason == "row_hash_mismatch"
    assert report.first_break.seq == 13


def test_one_character_inside_extra_is_a_row_hash_mismatch(
    bundle: dict[str, Any],
) -> None:
    row = bundle["rows"][3]
    row["extra"]["tag"] = str(row["extra"]["tag"])[:-1] + "x"
    report = verify_bundle(bundle)
    assert report.first_break is not None
    assert report.first_break.reason == "row_hash_mismatch"


def test_renormalising_a_zero_cost_breaks_the_row(bundle: dict[str, Any]) -> None:
    # 0E-8 and 0.00000000 are the same number and different canonical bytes.
    # This is exactly the trap a reimplementation falls into.
    _zero_cost_row(bundle)["cost_usd"] = "0.00000000"
    report = verify_bundle(bundle)
    assert report.first_break is not None
    assert report.first_break.reason == "row_hash_mismatch"


def test_reordering_keys_changes_nothing(bundle: dict[str, Any]) -> None:
    row = bundle["rows"][2]
    bundle["rows"][2] = dict(reversed(list(row.items())))
    bundle["rows"][2]["extra"] = dict(reversed(list(row["extra"].items())))
    assert verify_bundle(bundle).ok


def test_a_row_id_does_not_participate_in_the_hash(bundle: dict[str, Any]) -> None:
    bundle["rows"][1]["id"] = "99999999-8888-4777-8666-555555555555"
    report = verify_bundle(bundle)
    assert report.ok
    bundle["rows"][1]["prev_hash"] = "3" * 64
    assert (
        verify_bundle(bundle).first_break.id == "99999999-8888-4777-8666-555555555555"
    )


@pytest.mark.parametrize(
    "field", ["root_hash", "tip_hash", "row_count", "from_seq", "to_seq"]
)
def test_editing_any_anchor_field_is_a_mismatch(
    bundle: dict[str, Any], field: str
) -> None:
    anchor = bundle["anchors"][1]
    anchor[field] = "9" * 64 if isinstance(anchor[field], str) else anchor[field] + 1
    report = verify_bundle(bundle)
    assert not report.ok
    assert report.first_break is None
    assert [mismatch.anchor_date for mismatch in report.anchor_mismatches] == [
        anchor["anchor_date"]
    ]


def test_an_anchor_for_an_empty_day_inside_the_range_is_a_mismatch(
    builder: ModuleType,
) -> None:
    # A chain with a quiet middle day: 2026-08-02 exists in the range but has no
    # rows, so an anchor claiming rows for it cannot be explained by a partial
    # export and must be reported.
    gapped = builder.build_bundle([6, 0, 7])
    gapped["anchors"].append(
        {
            "anchor_date": "2026-08-02",
            "root_hash": "4" * 64,
            "tip_hash": "5" * 64,
            "row_count": 3,
            "from_seq": 2,
            "to_seq": 4,
        }
    )
    report = verify_bundle(gapped)
    assert not report.ok
    mismatch = report.anchor_mismatches[0]
    assert mismatch.anchor_date == "2026-08-02"
    assert mismatch.recomputed_root is None
    assert mismatch.live_row_count == 0
    assert mismatch.stored_row_count == 3


def test_an_anchor_for_a_day_outside_the_export_is_skipped(
    bundle: dict[str, Any],
) -> None:
    bundle["anchors"].append(
        {
            "anchor_date": "2026-09-09",
            "root_hash": "4" * 64,
            "tip_hash": "5" * 64,
            "row_count": 3,
            "from_seq": 2,
            "to_seq": 4,
        }
    )
    report = verify_bundle(bundle)
    assert report.ok
    assert [skip.anchor_date for skip in report.anchors_skipped] == ["2026-09-09"]


def test_an_edited_interior_anchor_cannot_talk_its_way_into_a_skip(
    bundle: dict[str, Any],
) -> None:
    # Claiming a range outside the bundle used to buy a skip. Coverage is now
    # decided from the rows, so an interior anchor is always judged.
    bundle["anchors"][1].update(from_seq=1, to_seq=9999, row_count=999)
    report = verify_bundle(bundle)
    assert not report.ok
    assert report.anchors_skipped == ()
    assert (
        report.anchor_mismatches[0].anchor_date == bundle["anchors"][1]["anchor_date"]
    )


def test_a_day_without_an_anchor_is_not_an_error(bundle: dict[str, Any]) -> None:
    bundle["anchors"] = bundle["anchors"][:2]
    report = verify_bundle(bundle)
    assert report.ok
    assert report.anchors_checked == 2


def test_a_partial_export_skips_the_days_it_only_half_covers(
    bundle: dict[str, Any], builder: ModuleType
) -> None:
    partial = builder.slice_bundle(bundle, 3, 9)
    report = verify_bundle(partial)
    assert report.ok
    assert not report.anchored_to_genesis
    assert report.anchors_checked == 0
    assert {skip.reason for skip in report.anchors_skipped} == {"incomplete_day"}


def test_a_partial_export_still_checks_the_days_it_fully_covers(
    bundle: dict[str, Any], builder: ModuleType
) -> None:
    # Days are 6, 5, 7 and 4 rows: seq 7..18 covers days two and three whole.
    partial = builder.slice_bundle(bundle, 7, 18)
    report = verify_bundle(partial)
    assert report.ok
    assert report.anchors_checked == 2
    assert len(report.anchors_skipped) == 2


def test_a_partial_export_with_a_broken_row_still_reports_the_break(
    bundle: dict[str, Any], builder: ModuleType
) -> None:
    partial = builder.slice_bundle(bundle, 7, 18)
    partial["rows"][4]["latency_ms"] += 1
    report = verify_bundle(partial)
    assert report.first_break is not None
    assert report.first_break.reason == "row_hash_mismatch"
    assert report.first_break.seq == 11


def test_a_partial_export_declaring_a_wrong_start_breaks_immediately(
    bundle: dict[str, Any], builder: ModuleType
) -> None:
    partial = builder.slice_bundle(bundle, 7, 18)
    partial["chain_start"]["from_seq"] = 8
    report = verify_bundle(partial)
    assert report.first_break is not None
    assert report.first_break.reason == "seq_gap"
    assert report.last_verified_seq is None


def test_rows_checked_counts_the_whole_bundle_even_after_a_break(
    bundle: dict[str, Any],
) -> None:
    bundle["rows"][1]["latency_ms"] += 1
    report = verify_bundle(bundle)
    assert report.rows_checked == bundle["row_count"]


def test_editing_the_envelope_still_verifies(bundle: dict[str, Any]) -> None:
    # Documented limitation, not an oversight: FORMAT.md 7.5 says the chain does
    # not cover generated_at, period, gateway_version or notes.
    bundle["notes"] = "edited after the fact"
    bundle["period"]["end"] = "2099-01-01T00:00:00+00:00"
    assert verify_bundle(bundle).ok
