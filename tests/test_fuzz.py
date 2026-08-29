"""Single-character mutation must never yield a false OK.

An "OK" is only allowed when nothing the verifier actually vouched for changed.
Two things it does not vouch for: the envelope, which the chain does not cover
(FORMAT.md 7.5), and any anchor it reported as skipped. Both exclusions are
computed from the report itself rather than waved through.
"""

import json
import random
import string
from typing import Any

from shim_audit_verify.bundle import CANONICAL_KEYS, BundleFormatError, parse_bundle
from shim_audit_verify.report import VerificationReport
from shim_audit_verify.verify import verify_bundle, verify_validated

_ALPHABET = string.digits + string.ascii_letters + string.punctuation
_EVIDENCE_KEYS = (*CANONICAL_KEYS, "prev_hash", "row_hash")


def _mutate(text: str, rng: random.Random) -> str:
    index = rng.randrange(len(text))
    replacement = rng.choice(_ALPHABET)
    while replacement == text[index]:
        replacement = rng.choice(_ALPHABET)
    return text[:index] + replacement + text[index + 1 :]


def _covered(
    payload: dict[str, Any], other: dict[str, Any], report: VerificationReport
) -> tuple[list[dict[str, Any]], list[Any]]:
    """Everything the verifier vouched for, with skipped anchors dropped.

    An anchor is dropped when either side of the comparison names a skipped
    date, so renaming an anchor into a skip cannot hide the edit either.
    """
    skipped = {skip.anchor_date for skip in report.anchors_skipped}
    anchors = [
        anchor
        for anchor, mirror in zip(payload["anchors"], other["anchors"], strict=True)
        if anchor["anchor_date"] not in skipped and mirror["anchor_date"] not in skipped
    ]
    rows = [{key: row[key] for key in _EVIDENCE_KEYS} for row in payload["rows"]]
    return rows, anchors


def test_no_single_character_mutation_verifies_altered_evidence(
    bundle: dict[str, Any],
) -> None:
    text = json.dumps(bundle)
    rng = random.Random(20260829)
    rejected = broken = untouched = 0

    for _ in range(4000):
        mutated = _mutate(text, rng)
        try:
            parsed = parse_bundle(mutated)
        except BundleFormatError:
            rejected += 1
            continue
        report = verify_validated(parsed)
        if not report.ok:
            broken += 1
            continue
        payload = json.loads(mutated)
        assert _covered(payload, bundle, report) == _covered(bundle, payload, report)
        untouched += 1

    # Each outcome must actually occur, or the test is passing vacuously.
    assert rejected and broken and untouched


def test_the_baseline_bundle_the_fuzzer_starts_from_is_valid(
    bundle: dict[str, Any],
) -> None:
    assert verify_bundle(bundle).ok
