"""Format-error matrix.

Everything here must raise ``BundleFormatError``. A schema problem is "this file
is not a bundle"; it is never allowed to masquerade as "this bundle was
altered", which is why the CLI gives it a separate exit code.
"""

import re
from collections.abc import Callable
from typing import Any

import pytest

from shim_audit_verify.bundle import BundleFormatError, parse_bundle, validate_bundle

Mutation = Callable[[dict[str, Any]], None]


def _row(bundle: dict[str, Any]) -> dict[str, Any]:
    return bundle["rows"][2]


def _anchor(bundle: dict[str, Any]) -> dict[str, Any]:
    return bundle["anchors"][1]


MUTATIONS: list[tuple[str, Mutation, str]] = [
    (
        "envelope-unknown-key",
        lambda b: b.update(surprise=1),
        "unknown key(s): surprise",
    ),
    ("envelope-missing-key", lambda b: b.pop("notes"), "missing key(s): notes"),
    ("wrong-format-name", lambda b: b.update(format="other"), "bundle.format"),
    ("unknown-version", lambda b: b.update(format_version=2), "unsupported version 2"),
    (
        "version-not-integer",
        lambda b: b.update(format_version="1"),
        "expected an integer",
    ),
    (
        "generated-at-not-utc",
        lambda b: b.update(generated_at="2026-08-29T09:00:00Z"),
        "ending in +00:00",
    ),
    (
        "generated-at-not-iso",
        lambda b: b.update(generated_at="not-a-date+00:00"),
        "ISO 8601",
    ),
    (
        "gateway-version-not-text",
        lambda b: b.update(gateway_version=14),
        "expected a string",
    ),
    (
        "organization-not-uuid",
        lambda b: b.update(organization_id="nope"),
        "expected a UUID",
    ),
    ("genesis-not-hex", lambda b: b.update(genesis_hash="zz" * 32), "hex characters"),
    (
        "genesis-uppercase-hex",
        lambda b: b.update(genesis_hash="A" * 64),
        "hex characters",
    ),
    ("notes-not-text", lambda b: b.update(notes=None), "expected a string"),
    (
        "chain-start-not-object",
        lambda b: b.update(chain_start=[]),
        "expected an object",
    ),
    (
        "chain-start-unknown-key",
        lambda b: b["chain_start"].update(extra=1),
        "unknown key(s): extra",
    ),
    (
        "chain-start-seq-zero",
        lambda b: b["chain_start"].update(from_seq=0),
        "positive integer",
    ),
    (
        "chain-start-prev-not-hex",
        lambda b: b["chain_start"].update(prev_hash="ff"),
        "hex characters",
    ),
    ("period-not-object", lambda b: b.update(period="august"), "expected an object"),
    ("period-missing-end", lambda b: b["period"].pop("end"), "missing key(s): end"),
    (
        "period-start-not-utc",
        lambda b: b["period"].update(start="2026-08-01"),
        "ending in +00:00",
    ),
    ("rows-not-array", lambda b: b.update(rows={}), "expected an array"),
    ("rows-empty", lambda b: b.update(rows=[], row_count=0), "at least one row"),
    ("row-count-mismatch", lambda b: b.update(row_count=999), "does not match"),
    ("row-count-negative", lambda b: b.update(row_count=-1), "non-negative integer"),
    ("row-not-object", lambda b: b["rows"].__setitem__(0, "row"), "expected an object"),
    ("row-unknown-key", lambda b: _row(b).update(shadow=1), "unknown key(s): shadow"),
    ("row-missing-key", lambda b: _row(b).pop("model"), "missing key(s): model"),
    ("row-seq-zero", lambda b: _row(b).update(seq=0), "positive integer"),
    ("row-seq-boolean", lambda b: _row(b).update(seq=True), "expected an integer"),
    (
        "row-org-not-uuid",
        lambda b: _row(b).update(organization_id="x"),
        "expected a UUID",
    ),
    (
        "row-created-at-not-utc",
        lambda b: _row(b).update(created_at="2026-08-01T00:00:00+03:00"),
        "ending in +00:00",
    ),
    (
        "row-event-type-null",
        lambda b: _row(b).update(event_type=None),
        "expected a string",
    ),
    (
        "row-api-key-not-uuid",
        lambda b: _row(b).update(api_key_id="k1"),
        "expected a UUID",
    ),
    ("row-actor-not-text", lambda b: _row(b).update(actor=7), "expected a string"),
    (
        "row-tokens-negative",
        lambda b: _row(b).update(prompt_tokens=-1),
        "non-negative integer",
    ),
    (
        "row-latency-boolean",
        lambda b: _row(b).update(latency_ms=False),
        "expected an integer",
    ),
    (
        "row-pii-detected-not-boolean",
        lambda b: _row(b).update(pii_detected="yes"),
        "expected a boolean",
    ),
    (
        "row-cache-hit-not-boolean",
        lambda b: _row(b).update(is_cache_hit=1),
        "expected a boolean",
    ),
    (
        "row-pii-entities-not-object",
        lambda b: _row(b).update(pii_entities=[]),
        "expected an object",
    ),
    (
        "row-pii-entity-count-negative",
        lambda b: _row(b).update(pii_entities={"EMAIL_ADDRESS": -2}),
        "non-negative integer",
    ),
    (
        "row-verdicts-not-array",
        lambda b: _row(b).update(policy_verdicts={}),
        "expected an array",
    ),
    (
        "row-verdict-not-object",
        lambda b: _row(b).update(policy_verdicts=["deny"]),
        "expected an object",
    ),
    (
        "row-cost-plain-zero",
        lambda b: _row(b).update(cost_usd="0"),
        "a str(Decimal) cost",
    ),
    (
        "row-cost-two-decimals",
        lambda b: _row(b).update(cost_usd="1.25"),
        "a str(Decimal) cost",
    ),
    (
        "row-cost-negative",
        lambda b: _row(b).update(cost_usd="-1.00000000"),
        "a str(Decimal) cost",
    ),
    (
        "row-cost-not-text",
        lambda b: _row(b).update(cost_usd=0.001),
        "expected a string",
    ),
    ("row-extra-not-object", lambda b: _row(b).update(extra=[]), "expected an object"),
    ("row-prev-hash-short", lambda b: _row(b).update(prev_hash="ab"), "hex characters"),
    ("row-hash-not-hex", lambda b: _row(b).update(row_hash="g" * 64), "hex characters"),
    ("row-id-not-uuid", lambda b: _row(b).update(id="not-a-uuid"), "expected a UUID"),
    ("anchors-not-array", lambda b: b.update(anchors={}), "expected an array"),
    (
        "anchor-not-object",
        lambda b: b["anchors"].__setitem__(0, 1),
        "expected an object",
    ),
    (
        "anchor-unknown-key",
        lambda b: _anchor(b).update(external_ref=None),
        "unknown key(s): external_ref",
    ),
    (
        "anchor-missing-key",
        lambda b: _anchor(b).pop("tip_hash"),
        "missing key(s): tip_hash",
    ),
    (
        "anchor-date-not-a-date",
        lambda b: _anchor(b).update(anchor_date="2026-8-1"),
        "YYYY-MM-DD",
    ),
    (
        "anchor-root-not-hex",
        lambda b: _anchor(b).update(root_hash="0" * 63),
        "hex characters",
    ),
    (
        "anchor-tip-not-hex",
        lambda b: _anchor(b).update(tip_hash=None),
        "expected a string",
    ),
    (
        "anchor-row-count-negative",
        lambda b: _anchor(b).update(row_count=-3),
        "non-negative integer",
    ),
    (
        "anchor-from-seq-zero",
        lambda b: _anchor(b).update(from_seq=0),
        "positive integer",
    ),
    (
        "anchor-range-inverted",
        lambda b: _anchor(b).update(from_seq=90, to_seq=2),
        "to_seq is before from_seq",
    ),
]


@pytest.mark.parametrize(
    ("mutate", "fragment"),
    [(mutation, fragment) for _, mutation, fragment in MUTATIONS],
    ids=[name for name, _, _ in MUTATIONS],
)
def test_schema_violation_is_a_format_error(
    bundle: dict[str, Any], mutate: Mutation, fragment: str
) -> None:
    mutate(bundle)
    with pytest.raises(BundleFormatError, match=re.escape(fragment)):
        validate_bundle(bundle)


def test_a_valid_bundle_validates(bundle: dict[str, Any]) -> None:
    validated = validate_bundle(bundle)
    assert validated.format_version == 1
    assert len(validated.rows) == bundle["row_count"]
    assert validated.rows[0].seq == 1


def test_an_optional_row_id_is_accepted_and_excluded_from_the_hash(
    bundle: dict[str, Any],
) -> None:
    identifier = "99999999-8888-4777-8666-555555555555"
    bundle["rows"][0]["id"] = identifier
    validated = validate_bundle(bundle)
    assert validated.rows[0].id == identifier
    assert "id" not in validated.rows[0].canonical


def test_a_row_without_an_id_reports_none(bundle: dict[str, Any]) -> None:
    assert validate_bundle(bundle).rows[0].id is None


def test_bundle_must_be_an_object() -> None:
    with pytest.raises(BundleFormatError, match="expected an object"):
        validate_bundle(["not", "a", "bundle"])


def test_invalid_json_is_a_format_error() -> None:
    with pytest.raises(BundleFormatError, match="invalid JSON"):
        parse_bundle("{oops")


def test_duplicate_json_keys_are_refused() -> None:
    with pytest.raises(BundleFormatError, match="duplicate JSON key 'format'"):
        parse_bundle('{"format": "a", "format": "b"}')


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_json_constants_are_refused(literal: str) -> None:
    with pytest.raises(BundleFormatError, match="is not valid in a bundle"):
        parse_bundle('{"a": ' + literal + "}")


def test_parse_bundle_accepts_a_serialized_valid_bundle(bundle: dict[str, Any]) -> None:
    import json

    assert parse_bundle(json.dumps(bundle)).rows[0].seq == 1
