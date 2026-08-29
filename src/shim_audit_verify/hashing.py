"""SHA-256 primitives for the shim.audit.bundle format.

Imports nothing but ``hashlib`` and ``json``: an auditor reads this one short
file and has the whole cryptographic surface. Any import here widens it.
"""

import hashlib
import json

SEPARATOR = b"\x1f"
GENESIS_LABEL = b"audit-genesis"


def canonical_row(fields: dict[str, object]) -> bytes:
    """Return the exact bytes a row is hashed over.

    ``sort_keys`` is why field order inside a bundle is irrelevant, and
    ``ensure_ascii=False`` is why Turkish text hashes as UTF-8 rather than as
    ``\\uXXXX`` escapes. Both are load-bearing, not style.
    """
    return json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def chain_hash(previous_hash: str, canonical: bytes) -> str:
    """Link canonical bytes to their predecessor's hash."""
    digest = hashlib.sha256()
    digest.update(previous_hash.encode("utf-8"))
    digest.update(SEPARATOR)
    digest.update(canonical)
    return digest.hexdigest()


def compute_row_hash(previous_hash: str, fields: dict[str, object]) -> str:
    """Return the ``row_hash`` of one canonical field object."""
    return chain_hash(previous_hash, canonical_row(fields))


def genesis_hash(salt: str, organization_id: str) -> str:
    """Derive a chain root. Verifiers cannot check this: the salt is never published."""
    digest = hashlib.sha256()
    digest.update(salt.encode("utf-8"))
    digest.update(SEPARATOR + GENESIS_LABEL + SEPARATOR)
    digest.update(organization_id.encode("utf-8"))
    return digest.hexdigest()


def merkle_root(leaves: list[str]) -> str:
    """Return the order-sensitive root over hex leaves, duplicating odd tails."""
    if not leaves:
        raise ValueError("at least one leaf is required")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(f"{left}{right}".encode()).hexdigest()
            for left, right in zip(level[::2], level[1::2], strict=True)
        ]
    return level[0]
