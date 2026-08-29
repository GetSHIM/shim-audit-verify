"""Parsing and strict schema validation for ``shim.audit.bundle`` files.

Strictness is the point. An unknown key could be an assurance a verifier does
not actually check, and a silently accepted duplicate key lets a file say two
different things at once, so both are refused rather than ignored.

Everything raised here is a *format* error, never a verification failure. The
two must stay distinct: one means "this file is not a bundle", the other means
"this bundle has been altered".
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn

FORMAT_NAME = "shim.audit.bundle"
SUPPORTED_VERSIONS = frozenset({1})

CANONICAL_KEYS: tuple[str, ...] = (
    "seq",
    "organization_id",
    "created_at",
    "event_type",
    "request_id",
    "api_key_id",
    "actor",
    "model",
    "provider",
    "gateway_version",
    "endpoint",
    "input_hash",
    "output_hash",
    "prompt_tokens",
    "completion_tokens",
    "pii_detected",
    "pii_entities",
    "policy_verdicts",
    "is_cache_hit",
    "latency_ms",
    "cost_usd",
    "extra",
)
_NULLABLE_TEXT_KEYS = (
    "request_id",
    "actor",
    "model",
    "provider",
    "gateway_version",
    "endpoint",
    "input_hash",
    "output_hash",
)
_COUNTER_KEYS = ("prompt_tokens", "completion_tokens", "latency_ms")

_ENVELOPE_KEYS = frozenset(
    {
        "format",
        "format_version",
        "generated_at",
        "gateway_version",
        "organization_id",
        "genesis_hash",
        "chain_start",
        "period",
        "row_count",
        "rows",
        "anchors",
        "notes",
    }
)
_ROW_KEYS = frozenset(CANONICAL_KEYS) | {"prev_hash", "row_hash"}
_ROW_OPTIONAL_KEYS = frozenset({"id"})
_ANCHOR_KEYS = frozenset(
    {"anchor_date", "root_hash", "tip_hash", "row_count", "from_seq", "to_seq"}
)

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_UUID = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
# str(Decimal) switches to scientific notation once the coefficient has
# fewer than three digits, so a sub-microcent cost renders as "1E-8" or
# "1.2E-7". All four forms are hashed exactly as written; see FORMAT.md 2.1.
_COST = re.compile(r"\A(0E-8|[1-9](\.[0-9]+)?E-[0-9]+|[0-9]+\.[0-9]{8})\Z")
_DATE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_HEX_WHAT = "64 lowercase hex characters"
_COST_WHAT = "a str(Decimal) cost: 0E-8, 1E-8, 1.2E-7 or 0.12500000"


@dataclass(frozen=True, slots=True)
class Row:
    """One validated audit row, with its canonical projection built once."""

    seq: int
    prev_hash: str
    row_hash: str
    created_at: str
    id: str | None
    canonical: dict[str, object]


@dataclass(frozen=True, slots=True)
class Anchor:
    """One validated daily anchor."""

    anchor_date: str
    root_hash: str
    tip_hash: str
    row_count: int
    from_seq: int
    to_seq: int


@dataclass(frozen=True, slots=True)
class Bundle:
    """A validated bundle. Constructing one is the only way past the schema."""

    format_version: int
    generated_at: str
    gateway_version: str
    organization_id: str
    genesis_hash: str
    from_seq: int
    prev_hash: str
    rows: tuple[Row, ...]
    anchors: tuple[Anchor, ...]


class BundleFormatError(ValueError):
    """The input is not a well-formed bundle."""


def _fail(path: str, message: str) -> NoReturn:
    raise BundleFormatError(f"{path}: {message}")


def _reject_constant(name: str) -> NoReturn:
    raise BundleFormatError(f"JSON constant {name} is not valid in a bundle")


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen: dict[str, object] = {}
    for key, value in pairs:
        if key in seen:
            raise BundleFormatError(f"duplicate JSON key {key!r}")
        seen[key] = value
    return seen


def parse_bundle(text: str) -> Bundle:
    """Parse bundle JSON, refusing duplicate keys and non-finite constants."""
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise BundleFormatError(f"invalid JSON: {exc}") from None
    return validate_bundle(parsed)


def _mapping(value: object, path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(path, "expected an object")
    return value


def _sequence(value: object, path: str) -> list[object]:
    if not isinstance(value, list):
        _fail(path, "expected an array")
    return value


def _text(value: object, path: str) -> str:
    if not isinstance(value, str):
        _fail(path, "expected a string")
    return value


def _integer(value: object, path: str) -> int:
    # bool is a subclass of int; a boolean where a count belongs is a type error.
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(path, "expected an integer")
    return value


def _boolean(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        _fail(path, "expected a boolean")
    return value


def _nonnegative(value: object, path: str) -> int:
    parsed = _integer(value, path)
    if parsed < 0:
        _fail(path, "expected a non-negative integer")
    return parsed


def _positive(value: object, path: str) -> int:
    parsed = _integer(value, path)
    if parsed < 1:
        _fail(path, "expected a positive integer")
    return parsed


def _pattern(value: object, path: str, pattern: re.Pattern[str], what: str) -> str:
    parsed = _text(value, path)
    if not pattern.match(parsed):
        _fail(path, f"expected {what}")
    return parsed


def _timestamp(value: object, path: str) -> str:
    parsed = _text(value, path)
    if not parsed.endswith("+00:00"):
        _fail(path, "expected a UTC timestamp ending in +00:00")
    try:
        datetime.fromisoformat(parsed)
    except ValueError:
        _fail(path, "expected an ISO 8601 timestamp")
    return parsed


def _nullable_text(value: object, path: str) -> str | None:
    return None if value is None else _text(value, path)


def _exact_keys(
    mapping: Mapping[str, object],
    path: str,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    present = frozenset(mapping)
    missing = sorted(required - present)
    if missing:
        _fail(path, f"missing key(s): {', '.join(missing)}")
    unknown = sorted(present - required - optional)
    if unknown:
        _fail(path, f"unknown key(s): {', '.join(unknown)}")


def _validate_row(value: object, path: str) -> Row:
    row = _mapping(value, path)
    _exact_keys(row, path, _ROW_KEYS, _ROW_OPTIONAL_KEYS)
    seq = _positive(row["seq"], f"{path}.seq")
    _pattern(row["organization_id"], f"{path}.organization_id", _UUID, "a UUID")
    created_at = _timestamp(row["created_at"], f"{path}.created_at")
    _text(row["event_type"], f"{path}.event_type")
    if row["api_key_id"] is not None:
        _pattern(row["api_key_id"], f"{path}.api_key_id", _UUID, "a UUID")
    for key in _NULLABLE_TEXT_KEYS:
        _nullable_text(row[key], f"{path}.{key}")
    for key in _COUNTER_KEYS:
        _nonnegative(row[key], f"{path}.{key}")
    _boolean(row["pii_detected"], f"{path}.pii_detected")
    _boolean(row["is_cache_hit"], f"{path}.is_cache_hit")
    for name, count in _mapping(row["pii_entities"], f"{path}.pii_entities").items():
        _nonnegative(count, f"{path}.pii_entities.{name}")
    verdicts = _sequence(row["policy_verdicts"], f"{path}.policy_verdicts")
    for index, verdict in enumerate(verdicts):
        _mapping(verdict, f"{path}.policy_verdicts[{index}]")
    _pattern(row["cost_usd"], f"{path}.cost_usd", _COST, _COST_WHAT)
    _mapping(row["extra"], f"{path}.extra")
    return Row(
        seq=seq,
        prev_hash=_pattern(row["prev_hash"], f"{path}.prev_hash", _HEX64, _HEX_WHAT),
        row_hash=_pattern(row["row_hash"], f"{path}.row_hash", _HEX64, _HEX_WHAT),
        created_at=created_at,
        id=(
            _pattern(row["id"], f"{path}.id", _UUID, "a UUID") if "id" in row else None
        ),
        canonical={key: row[key] for key in CANONICAL_KEYS},
    )


def _validate_anchor(value: object, path: str) -> Anchor:
    anchor = _mapping(value, path)
    _exact_keys(anchor, path, _ANCHOR_KEYS)
    from_seq = _positive(anchor["from_seq"], f"{path}.from_seq")
    to_seq = _positive(anchor["to_seq"], f"{path}.to_seq")
    if to_seq < from_seq:
        _fail(path, "to_seq is before from_seq")
    return Anchor(
        anchor_date=_pattern(
            anchor["anchor_date"], f"{path}.anchor_date", _DATE, "a YYYY-MM-DD date"
        ),
        root_hash=_pattern(anchor["root_hash"], f"{path}.root_hash", _HEX64, _HEX_WHAT),
        tip_hash=_pattern(anchor["tip_hash"], f"{path}.tip_hash", _HEX64, _HEX_WHAT),
        row_count=_nonnegative(anchor["row_count"], f"{path}.row_count"),
        from_seq=from_seq,
        to_seq=to_seq,
    )


def validate_bundle(value: object) -> Bundle:
    """Return a validated ``Bundle``, or raise ``BundleFormatError``."""
    bundle = _mapping(value, "bundle")
    _exact_keys(bundle, "bundle", _ENVELOPE_KEYS)
    if _text(bundle["format"], "bundle.format") != FORMAT_NAME:
        _fail("bundle.format", f"expected {FORMAT_NAME!r}")
    version = _integer(bundle["format_version"], "bundle.format_version")
    if version not in SUPPORTED_VERSIONS:
        _fail("bundle.format_version", f"unsupported version {version}")
    _text(bundle["notes"], "bundle.notes")

    period = _mapping(bundle["period"], "bundle.period")
    _exact_keys(period, "bundle.period", frozenset({"start", "end"}))
    _timestamp(period["start"], "bundle.period.start")
    _timestamp(period["end"], "bundle.period.end")

    chain_start = _mapping(bundle["chain_start"], "bundle.chain_start")
    _exact_keys(chain_start, "bundle.chain_start", frozenset({"from_seq", "prev_hash"}))

    raw_rows = _sequence(bundle["rows"], "bundle.rows")
    if not raw_rows:
        _fail("bundle.rows", "a bundle must contain at least one row")
    rows = tuple(
        _validate_row(row, f"bundle.rows[{index}]")
        for index, row in enumerate(raw_rows)
    )
    if _nonnegative(bundle["row_count"], "bundle.row_count") != len(rows):
        _fail("bundle.row_count", f"does not match {len(rows)} rows")

    raw_anchors = _sequence(bundle["anchors"], "bundle.anchors")
    anchors = tuple(
        _validate_anchor(anchor, f"bundle.anchors[{index}]")
        for index, anchor in enumerate(raw_anchors)
    )
    return Bundle(
        format_version=version,
        generated_at=_timestamp(bundle["generated_at"], "bundle.generated_at"),
        gateway_version=_text(bundle["gateway_version"], "bundle.gateway_version"),
        organization_id=_pattern(
            bundle["organization_id"], "bundle.organization_id", _UUID, "a UUID"
        ),
        genesis_hash=_pattern(
            bundle["genesis_hash"], "bundle.genesis_hash", _HEX64, _HEX_WHAT
        ),
        from_seq=_positive(chain_start["from_seq"], "bundle.chain_start.from_seq"),
        prev_hash=_pattern(
            chain_start["prev_hash"], "bundle.chain_start.prev_hash", _HEX64, _HEX_WHAT
        ),
        rows=rows,
        anchors=anchors,
    )
