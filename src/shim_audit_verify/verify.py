"""Chain and anchor verification for a ``shim.audit.bundle``.

The chain walk mirrors the shim server's own verifier step for step, including
stopping at the first break, so the two cannot drift apart quietly.
"""

from collections.abc import Mapping, Sequence

from shim_audit_verify.bundle import Anchor, Bundle, Row, validate_bundle
from shim_audit_verify.hashing import compute_row_hash, merkle_root
from shim_audit_verify.report import (
    AnchorMismatch,
    AnchorSkip,
    ChainBreak,
    VerificationReport,
)


def _verify_chain(
    rows: Sequence[Row],
    *,
    from_seq: int,
    prev_hash: str,
) -> tuple[ChainBreak | None, int | None]:
    """Walk the chain, returning the first break and the last verified ``seq``."""
    expected_seq = from_seq
    expected_prev = prev_hash
    last_verified: int | None = None
    for row in rows:
        if row.seq != expected_seq:
            return ChainBreak(row.seq, row.id, "seq_gap"), last_verified
        if row.prev_hash != expected_prev:
            reason = "genesis_mismatch" if row.seq == 1 else "prev_hash_mismatch"
            return ChainBreak(row.seq, row.id, reason), last_verified
        if compute_row_hash(expected_prev, row.canonical) != row.row_hash:
            return ChainBreak(row.seq, row.id, "row_hash_mismatch"), last_verified
        expected_seq = row.seq + 1
        expected_prev = row.row_hash
        last_verified = row.seq
    return None, last_verified


def _verify_anchors(
    anchors: Sequence[Anchor],
    rows: Sequence[Row],
    *,
    full_chain: bool,
) -> tuple[tuple[AnchorMismatch, ...], tuple[AnchorSkip, ...]]:
    """Recompute every anchor the bundle fully covers; skip the ones it does not.

    Coverage is decided from the bundle's own rows, never from the anchor's
    fields. An anchor carries no signature and is not part of the hash chain, so
    letting it declare its own seq range would let an edited anchor talk its way
    out of being checked.
    """
    by_date: dict[str, list[Row]] = {}
    for row in rows:
        # created_at is a validated UTC timestamp, so its date is its first 10 chars.
        by_date.setdefault(row.created_at[:10], []).append(row)
    first_date = rows[0].created_at[:10]
    last_date = rows[-1].created_at[:10]

    mismatches: list[AnchorMismatch] = []
    skipped: list[AnchorSkip] = []
    for anchor in anchors:
        day = by_date.get(anchor.anchor_date, [])
        outside = anchor.anchor_date < first_date or anchor.anchor_date > last_date
        # A day at either edge of the export may legitimately be half-present:
        # rows before the first or after the last are simply not in this file.
        # The first day of a full chain is not an edge, because nothing precedes
        # seq 1.
        at_edge = anchor.anchor_date == last_date or (
            anchor.anchor_date == first_date and not full_chain
        )
        if outside or (at_edge and len(day) != anchor.row_count):
            skipped.append(AnchorSkip(anchor.anchor_date, "incomplete_day"))
            continue
        if not day:
            mismatches.append(
                AnchorMismatch(
                    anchor.anchor_date, anchor.root_hash, None, anchor.row_count, 0
                )
            )
            continue
        recomputed = merkle_root([row.row_hash for row in day])
        matches = (
            recomputed == anchor.root_hash
            and day[-1].row_hash == anchor.tip_hash
            and len(day) == anchor.row_count
            and day[0].seq == anchor.from_seq
            and day[-1].seq == anchor.to_seq
        )
        if not matches:
            mismatches.append(
                AnchorMismatch(
                    anchor.anchor_date,
                    anchor.root_hash,
                    recomputed,
                    anchor.row_count,
                    len(day),
                )
            )
    return tuple(mismatches), tuple(skipped)


def verify_validated(bundle: Bundle) -> VerificationReport:
    """Verify an already validated bundle."""
    rows = bundle.rows
    anchored_to_genesis = bundle.from_seq == 1
    if anchored_to_genesis and bundle.prev_hash != bundle.genesis_hash:
        # The envelope contradicts itself before a single row is read.
        first_break: ChainBreak | None = ChainBreak(
            rows[0].seq, rows[0].id, "genesis_mismatch"
        )
        last_verified: int | None = None
    else:
        first_break, last_verified = _verify_chain(
            rows, from_seq=bundle.from_seq, prev_hash=bundle.prev_hash
        )

    mismatches, skipped = _verify_anchors(
        bundle.anchors, rows, full_chain=anchored_to_genesis
    )
    return VerificationReport(
        ok=first_break is None and not mismatches,
        rows_checked=len(rows),
        first_break=first_break,
        last_verified_seq=last_verified,
        anchors_checked=len(bundle.anchors) - len(skipped),
        anchor_mismatches=mismatches,
        anchors_skipped=skipped,
        from_seq=rows[0].seq,
        to_seq=rows[-1].seq,
        anchored_to_genesis=anchored_to_genesis,
    )


def verify_bundle(bundle: Mapping[str, object]) -> VerificationReport:
    """Validate and verify a bundle. Raises ``BundleFormatError`` on a bad input."""
    return verify_validated(validate_bundle(bundle))
