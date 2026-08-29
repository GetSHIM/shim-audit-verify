"""Command line entry point.

Exit codes are part of the contract: ``0`` verified, ``1`` verification failed,
``2`` the input is not a bundle. Conflating the last two would let a malformed
file read as tampering, or worse, tampering read as a typo.
"""

import argparse
import dataclasses
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from shim_audit_verify.bundle import (
    FORMAT_NAME,
    Bundle,
    BundleFormatError,
    parse_bundle,
)
from shim_audit_verify.report import VerificationReport
from shim_audit_verify.verify import verify_validated

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_INPUT = 2

_LABEL = 9
_STATUS = 12
_INDENT = " " * (_LABEL + _STATUS)


def _short(value: str) -> str:
    return f"{value[:4]}…"


def _read(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    try:
        return Path(source).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise BundleFormatError(f"{source} is not UTF-8 text") from None
    except OSError as exc:
        raise BundleFormatError(f"cannot read {source}: {exc.strerror}") from None


def _chain_lines(report: VerificationReport) -> list[str]:
    anchor_note = (
        "anchored to genesis"
        if report.anchored_to_genesis
        else "anchored to declared prev_hash (not genesis)"
    )
    if report.first_break is None:
        detail = (
            f"rows {report.from_seq}..{report.to_seq} ({report.rows_checked} checked)"
        )
        if report.anchored_to_genesis:
            return [f"{'chain':<{_LABEL}}{'OK':<{_STATUS}}{detail}   {anchor_note}"]
        return [
            f"{'chain':<{_LABEL}}{'OK':<{_STATUS}}{detail}",
            f"{_INDENT}{anchor_note}",
        ]
    verified = (
        "no rows verified"
        if report.last_verified_seq is None
        else f"last verified seq {report.last_verified_seq}"
    )
    lines = [
        f"{'chain':<{_LABEL}}{'BROKEN':<{_STATUS}}"
        f"first break at seq {report.first_break.seq}: {report.first_break.reason}",
        f"{_INDENT}{verified}",
    ]
    if not report.anchored_to_genesis:
        lines.append(f"{_INDENT}{anchor_note}")
    return lines


def _anchor_lines(report: VerificationReport) -> list[str]:
    skipped = len(report.anchors_skipped)
    if not report.anchor_mismatches:
        status = "NONE" if report.anchors_checked == 0 else "OK"
        counts = f"{report.anchors_checked} verified, {skipped} skipped"
        return [f"{'anchors':<{_LABEL}}{status:<{_STATUS}}{counts}"]
    # "verified" would be a lie on this path: some of those anchors did not verify.
    counts = (
        f"{report.anchors_checked} checked, "
        f"{len(report.anchor_mismatches)} mismatched, {skipped} skipped"
    )
    details = [
        (
            f"{mismatch.anchor_date} has no rows in the bundle "
            f"(anchor claims {mismatch.stored_row_count})"
            if mismatch.recomputed_root is None
            else f"{mismatch.anchor_date} root differs "
            f"(stored {_short(mismatch.stored_root)}, "
            f"recomputed {_short(mismatch.recomputed_root)})"
        )
        for mismatch in report.anchor_mismatches
    ]
    head = f"{'anchors':<{_LABEL}}{'MISMATCH':<{_STATUS}}{details[0]}"
    return [
        head,
        *(f"{_INDENT}{detail}" for detail in details[1:]),
        f"{_INDENT}{counts}",
    ]


def _render(bundle: Bundle, report: VerificationReport) -> str:
    header = (
        f"{'bundle':<{_LABEL}}{FORMAT_NAME} v{bundle.format_version}   "
        f"org {_short(bundle.organization_id)}   gateway {bundle.gateway_version}"
    )
    return "\n".join([header, *_chain_lines(report), *_anchor_lines(report)])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shim-audit-verify",
        description=(
            "Verify a shim.audit.bundle evidence file. Reads nothing but the file "
            "given; never touches the network."
        ),
    )
    parser.add_argument("bundle", help="path to the bundle, or - for stdin")
    parser.add_argument(
        "--json", action="store_true", help="emit the machine-readable report"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="print nothing; use the exit code"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Return the process exit code."""
    arguments = _parser().parse_args(argv)
    try:
        bundle = parse_bundle(_read(arguments.bundle))
    except BundleFormatError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    report = verify_validated(bundle)
    if not arguments.quiet:
        if arguments.json:
            print(json.dumps(dataclasses.asdict(report), indent=2, sort_keys=True))
        else:
            print(_render(bundle, report))
    return EXIT_OK if report.ok else EXIT_FAILED
