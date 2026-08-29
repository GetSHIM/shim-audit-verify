"""Frozen result types.

These are public API under semver. Field names deliberately mirror the Shim
server's ``VerifyResult`` schema so one consumer schema parses both a bundle
verification and a server-side verification, including the nested
``live_row_count`` name that reads oddly for a static file.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ChainBreak:
    """The first place the chain stopped verifying."""

    seq: int
    id: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class AnchorMismatch:
    """A daily anchor that does not match the rows the bundle carries."""

    anchor_date: str
    stored_root: str
    recomputed_root: str | None
    stored_row_count: int
    live_row_count: int


@dataclass(frozen=True, slots=True)
class AnchorSkip:
    """A daily anchor the bundle does not fully cover, so it was not judged."""

    anchor_date: str
    reason: str


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """The complete outcome of verifying one bundle."""

    ok: bool
    rows_checked: int
    first_break: ChainBreak | None
    last_verified_seq: int | None
    anchors_checked: int
    anchor_mismatches: tuple[AnchorMismatch, ...]
    anchors_skipped: tuple[AnchorSkip, ...]
    from_seq: int
    to_seq: int
    anchored_to_genesis: bool
