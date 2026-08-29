"""Build synthetic audit chains for tests and for the published examples.

This re-implements nothing. It drives the same primitives the verifier exposes,
which is exactly how a producer is meant to use them, and it never touches a
database so no real tenant data can leak into a published example.
"""

import random
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any

from shim_audit_verify.hashing import compute_row_hash, genesis_hash, merkle_root

# Synthetic throughout: a made-up tenant id, a published salt, and addresses on
# the reserved .test TLD. No production salt or real traffic ever appears here.
ORG = "3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
EXAMPLE_SALT = "shim-audit-verify-example-salt"
GATEWAY_VERSION = "shim-gateway/1.4.2"

_MODELS = (
    ("claude-sonnet-4", "anthropic"),
    ("gpt-4o", "openai"),
    ("gemini-2.5-pro", "google"),
    ("llama-3.3-70b", "ollama"),
)
_ACTORS = ("ayse@example.test", "mert@example.test", "svc-batch@example.test")
_ENDPOINTS = ("/v1/chat/completions", "/v1/messages", "/v1/embeddings")
_PII = ("EMAIL_ADDRESS", "PHONE_NUMBER", "TR_TCKN", "CREDIT_CARD", "IBAN_CODE")
_TAGS = ("takım-a", "müşteri-görüşmesi", "batch-özet", "support")
_CENT = Decimal("0.00000001")


def _cost(rng: random.Random) -> str:
    """Return a cost string, deliberately spanning every str(Decimal) form.

    Sub-microcent costs render in scientific notation ("1E-8", "1.2E-7") rather
    than as a plain fixed-point string. Cheap cached calls really do cost that
    little, so a sample that never produced one would let a reimplementation
    look correct while getting the common case wrong.
    """
    draw = rng.random()
    if draw < 0.18:
        units = 0
    elif draw < 0.30:
        units = rng.randrange(1, 100)
    else:
        units = rng.randrange(100, 400_000)
    return str((Decimal(units) / Decimal(10**8)).quantize(_CENT))


def _fields(
    seq: int, created_at: datetime, rng: random.Random, org: str
) -> dict[str, Any]:
    model, provider = rng.choice(_MODELS)
    cache_hit = rng.random() < 0.2
    # Console requests authenticate with a session, not an API key, so a null
    # api_key_id is ordinary rather than exotic.
    from_console = rng.random() < 0.15
    pii_count = 0 if rng.random() < 0.75 else rng.randrange(1, 3)
    entities = {name: rng.randrange(1, 4) for name in rng.sample(_PII, pii_count)}
    verdicts: list[dict[str, Any]] = []
    if entities:
        verdicts.append({"code": "pii.redact", "outcome": "applied"})
    if rng.random() < 0.1:
        verdicts.append({"code": "budget.cap", "outcome": "allow", "headroom_pct": 12})
    return {
        "seq": seq,
        "organization_id": org,
        "created_at": created_at.isoformat(),
        "event_type": "ai_request",
        "request_id": f"req-{seq:05d}",
        "api_key_id": None if from_console else "11111111-2222-4333-8444-555555555555",
        "actor": rng.choice(_ACTORS),
        "model": model,
        "provider": provider,
        "gateway_version": GATEWAY_VERSION,
        "endpoint": "/console/playground" if from_console else rng.choice(_ENDPOINTS),
        "input_hash": f"{rng.getrandbits(256):064x}",
        "output_hash": None if cache_hit else f"{rng.getrandbits(256):064x}",
        "prompt_tokens": rng.randrange(20, 4000),
        "completion_tokens": 0 if cache_hit else rng.randrange(10, 2000),
        "pii_detected": bool(entities),
        "pii_entities": dict(sorted(entities.items())),
        "policy_verdicts": verdicts,
        "is_cache_hit": cache_hit,
        "latency_ms": rng.randrange(4, 60) if cache_hit else rng.randrange(300, 4000),
        "cost_usd": "0E-8" if cache_hit else _cost(rng),
        "extra": {
            "tag": rng.choice(_TAGS),
            "route": {"attempt": 1, "region": "europe-west3"},
            "similarity": round(rng.uniform(0.80, 0.99), 4) if cache_hit else None,
        },
    }


def build_rows(
    rows_per_day: list[int],
    *,
    org: str = ORG,
    salt: str = EXAMPLE_SALT,
    start_date: date = date(2026, 8, 1),
    seed: int = 20260829,
) -> list[dict[str, Any]]:
    """Return a linked chain starting at seq 1, spread across consecutive days."""
    rng = random.Random(seed)
    previous = genesis_hash(salt, org)
    rows: list[dict[str, Any]] = []
    seq = 1
    for offset, count in enumerate(rows_per_day):
        moment = datetime.combine(
            start_date + timedelta(days=offset),
            datetime.min.time(),
            tzinfo=UTC,
        ) + timedelta(hours=8)
        for _ in range(count):
            moment += timedelta(
                seconds=rng.randrange(30, 900), microseconds=rng.randrange(0, 999999)
            )
            fields = _fields(seq, moment, rng, org)
            row_hash = compute_row_hash(previous, fields)
            rows.append({**fields, "prev_hash": previous, "row_hash": row_hash})
            previous = row_hash
            seq += 1
    return rows


def build_anchors(
    rows: list[dict[str, Any]], *, days: int | None = None
) -> list[dict[str, Any]]:
    """Anchor the first ``days`` UTC days in ``rows``; all of them by default."""
    by_date: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_date.setdefault(str(row["created_at"])[:10], []).append(row)
    selected = sorted(by_date)[: len(by_date) if days is None else days]
    return [
        {
            "anchor_date": anchor_date,
            "root_hash": merkle_root([row["row_hash"] for row in by_date[anchor_date]]),
            "tip_hash": by_date[anchor_date][-1]["row_hash"],
            "row_count": len(by_date[anchor_date]),
            "from_seq": by_date[anchor_date][0]["seq"],
            "to_seq": by_date[anchor_date][-1]["seq"],
        }
        for anchor_date in selected
    ]


def build_bundle(
    rows_per_day: list[int],
    *,
    org: str = ORG,
    salt: str = EXAMPLE_SALT,
    start_date: date = date(2026, 8, 1),
    seed: int = 20260829,
    anchor_days: int | None = None,
    generated_at: str = "2026-08-29T09:00:00+00:00",
) -> dict[str, Any]:
    """Return a complete, valid bundle covering the whole chain from seq 1."""
    rows = build_rows(
        rows_per_day, org=org, salt=salt, start_date=start_date, seed=seed
    )
    return {
        "format": "shim.audit.bundle",
        "format_version": 1,
        "generated_at": generated_at,
        "gateway_version": GATEWAY_VERSION,
        "organization_id": org,
        "genesis_hash": genesis_hash(salt, org),
        "chain_start": {"from_seq": 1, "prev_hash": genesis_hash(salt, org)},
        "period": {
            "start": str(rows[0]["created_at"]),
            "end": str(rows[-1]["created_at"]),
        },
        "row_count": len(rows),
        "rows": rows,
        "anchors": build_anchors(rows, days=anchor_days),
        "notes": "Metadata only. No prompt or response bodies are recorded.",
    }


def slice_bundle(bundle: dict[str, Any], first: int, last: int) -> dict[str, Any]:
    """Return a partial export of ``bundle`` covering seq ``first``..``last``."""
    rows = [row for row in bundle["rows"] if first <= int(str(row["seq"])) <= last]
    return {
        **bundle,
        "chain_start": {"from_seq": first, "prev_hash": rows[0]["prev_hash"]},
        "period": {
            "start": str(rows[0]["created_at"]),
            "end": str(rows[-1]["created_at"]),
        },
        "row_count": len(rows),
        "rows": rows,
    }
