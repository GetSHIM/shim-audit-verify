"""Independent verifier for Shim audit evidence bundles.

The hashing primitives are exported deliberately: anyone reimplementing the
format in another language should have this as their reference.
"""

from shim_audit_verify.bundle import (
    CANONICAL_KEYS,
    FORMAT_NAME,
    SUPPORTED_VERSIONS,
    Anchor,
    Bundle,
    BundleFormatError,
    Row,
    parse_bundle,
    validate_bundle,
)
from shim_audit_verify.hashing import (
    canonical_row,
    chain_hash,
    compute_row_hash,
    genesis_hash,
    merkle_root,
)
from shim_audit_verify.report import (
    AnchorMismatch,
    AnchorSkip,
    ChainBreak,
    VerificationReport,
)
from shim_audit_verify.verify import verify_bundle, verify_validated

__version__ = "0.1.0"

__all__ = [
    "CANONICAL_KEYS",
    "FORMAT_NAME",
    "SUPPORTED_VERSIONS",
    "Anchor",
    "AnchorMismatch",
    "AnchorSkip",
    "Bundle",
    "BundleFormatError",
    "ChainBreak",
    "Row",
    "VerificationReport",
    "__version__",
    "canonical_row",
    "chain_hash",
    "compute_row_hash",
    "genesis_hash",
    "merkle_root",
    "parse_bundle",
    "validate_bundle",
    "verify_bundle",
    "verify_validated",
]
