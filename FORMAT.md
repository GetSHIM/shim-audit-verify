# `shim.audit.bundle` v1

This document is the byte-level contract for a shim audit evidence bundle. It is
written so that a third party can reimplement the verifier in any language and
get identical results. Where this document and any implementation disagree, this
document is the specification and the implementation is the bug.

Read [Known limitations](#7-known-limitations) before drawing conclusions from a
`chain OK` result. It states plainly what the chain does not prove.

## 1. Envelope

A bundle is a single UTF-8 encoded JSON object.

```json
{
  "format": "shim.audit.bundle",
  "format_version": 1,
  "generated_at": "2026-08-29T09:00:00+00:00",
  "gateway_version": "shim-gateway/1.4.2",
  "organization_id": "3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
  "genesis_hash": "8a1c…",
  "chain_start": { "from_seq": 1, "prev_hash": "8a1c…" },
  "period": { "start": "2026-08-01T00:00:00+00:00", "end": "2026-08-28T23:59:59+00:00" },
  "row_count": 842,
  "rows": [],
  "anchors": [],
  "notes": "Metadata only. No prompt or response bodies are recorded."
}
```

| Key | Type | Rule |
|---|---|---|
| `format` | string | Exactly `shim.audit.bundle`. |
| `format_version` | number | Exactly `1` for this document. |
| `generated_at` | string | RFC 3339 UTC timestamp, ends with `+00:00`. |
| `gateway_version` | string | Version of the gateway that produced the bundle. |
| `organization_id` | string | Lowercase canonical UUID of the tenant. |
| `genesis_hash` | string | 64 lowercase hex characters. See [§4.3](#43-genesis). |
| `chain_start` | object | `{ "from_seq": number, "prev_hash": string }`. See [§3](#3-chain_start). |
| `period` | object | `{ "start": string, "end": string }`, both UTC, both end with `+00:00`. |
| `row_count` | number | Must equal `len(rows)`. |
| `rows` | array | Non-empty, ascending `seq` order. See [§2](#2-rows). |
| `anchors` | array | Daily anchors. See [§5](#5-anchors). |
| `notes` | string | Free text. Carries no cryptographic meaning. |

Every key is required. A bundle carrying keys not listed here is rejected as a
format error, because an unknown key may be an assurance a verifier does not
actually check.

`rows` must contain at least one row. Verifying an empty bundle would produce a
vacuous `OK` that proves nothing, so it is refused as a format error instead. A
period with no activity has no evidence to export.

## 2. `rows[]`

Each row object contains exactly 24 keys: the 22 canonical fields below, plus
`prev_hash` and `row_hash`. An `id` key (the row UUID) may additionally be
present; it is not part of the hash.

`prev_hash` and `row_hash` are **not** inside the canonical object. They sit
beside it on the row. A verifier hashing the row object as written will get the
wrong answer; it must first project the 22 canonical keys.

The canonical fields, and the exact JSON value each carries:

| Field | Type | Rule |
|---|---|---|
| `seq` | number | Integer, starts at 1, increases by exactly 1 with no gaps. |
| `organization_id` | string | Lowercase canonical UUID. |
| `created_at` | string | UTC timestamp, ends with `+00:00`. Microseconds present or absent, exactly as recorded. |
| `event_type` | string | For example `ai_request`. |
| `request_id` | string \| null | |
| `api_key_id` | string \| null | Lowercase canonical UUID or null. |
| `actor` | string \| null | See [§7.4](#74-actor-is-an-identity). |
| `model` | string \| null | |
| `provider` | string \| null | |
| `gateway_version` | string \| null | |
| `endpoint` | string \| null | |
| `input_hash` | string \| null | Digest of the request. Never the request itself. |
| `output_hash` | string \| null | Digest of the response. Never the response itself. |
| `prompt_tokens` | number | Integer `>= 0`. |
| `completion_tokens` | number | Integer `>= 0`. |
| `pii_detected` | boolean | |
| `pii_entities` | object | Entity name to non-negative integer count. |
| `policy_verdicts` | array | Array of objects. |
| `is_cache_hit` | boolean | |
| `latency_ms` | number | Integer `>= 0`. |
| `cost_usd` | string | See [§2.1](#21-cost_usd-is-a-string-and-zero-is-not-what-you-expect). |
| `extra` | object | Free-form metadata. See [§2.2](#22-numbers-inside-extra). |

The values in a bundle are written exactly as the producer hashed them. A
verifier performs **no** type coercion: it projects the 22 keys and serializes
them. Any normalisation a verifier adds is a bug that will make valid bundles
fail.

### 2.1 `cost_usd` is a string, and its shape will surprise you

`cost_usd` is held server-side as a fixed-point decimal with 8 fractional digits
and enters the hash as the exact output of Python's `str(Decimal)` after
quantising to those 8 places. That function does **not** always produce a plain
fixed-point string: once the coefficient has fewer than three significant
digits, it switches to scientific notation.

All four forms are real, and all four appear in production:

| Value | Rendered as | When |
|---|---|---|
| `0` | `0E-8` | Cache hits and models with no price attached. Very common. |
| `0.00000001` | `1E-8` | One to nine hundred-millionths of a dollar. |
| `0.00000012` | `1.2E-7` | Ten to nine hundred and ninety millionths, two significant digits. |
| `0.12500000` | `0.12500000` | Anything from `0.00000100` upward. |

None of this is a producer bug, and none of it can be normalised away. The hash
was taken over whichever string `str(Decimal)` produced, and a PostgreSQL
`numeric(18,8)` round trip returns the identical value, so the chain is
self-consistent. Rewriting `0E-8` as `0.00000000`, or `1E-8` as `0.00000001`,
changes the canonical bytes and breaks the row hash.

This is the single hardest thing to guess when reimplementing this format, which
is why four golden vectors in `tests/vectors/rows/` pin it: one per form.

A verifier should accept the family rather than an exact enumeration, and let the
hash do the real work:

```
^(0E-8|[1-9](\.[0-9]+)?E-[0-9]+|[0-9]+\.[0-9]{8})$
```

A `cost_usd` that fails this is a producer that is not following this
specification, and is reported as an input error rather than as tampering.

### 2.2 Numbers inside `extra`

`extra` and `policy_verdicts` are free-form JSON objects and may contain
integers, floats, strings, booleans, nulls, arrays and nested objects.

Floats are serialized by `json.dumps`, which emits exponent notation for
magnitudes at or above `1e16`. A producer must never place such a value in a
canonical field: PostgreSQL `jsonb` normalises `1e+16` to `10000000000000000`,
which changes the canonical bytes on the way back out and would break the row
hash. The shim exporter rejects non-finite floats and floats with
`abs(value) >= 1e16` rather than emitting a bundle that cannot be verified.
Ordinary floats such as `0.85` round-trip unchanged and are fine.

## 3. `chain_start`

```json
{ "from_seq": 1, "prev_hash": "8a1c…" }
```

`from_seq` is the `seq` of the first row in `rows`. `prev_hash` is the hash the
first row links back to.

- **Full chain.** `from_seq` is `1` and `prev_hash` equals `genesis_hash`.
- **Partial export.** `from_seq` is `N > 1` and `prev_hash` is the `prev_hash` of
  row `N`, taken from the producer.

A partial bundle proves only that the exported window is internally consistent.
The link back to genesis is asserted by the producer, not proven by the bundle,
because the rows that would prove it are not in the file. A verifier must say so
in its output rather than reporting a bare `OK`.

## 4. Hash contract

### 4.1 Canonical serialization

```python
json.dumps(
    fields,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
    allow_nan=False,
).encode("utf-8")
```

`fields` is the object of exactly the 22 canonical keys from [§2](#2-rows).

- `sort_keys=True` applies recursively, so the order keys appear in inside a
  bundle file is irrelevant, at every nesting depth.
- `separators=(",", ":")` means no whitespace anywhere.
- `ensure_ascii=False` means non-ASCII text is hashed as UTF-8 bytes, not as
  `\uXXXX` escape sequences. `"ölçüm"` hashes as 7 bytes, not 18.
- `allow_nan=False` means `NaN` and `Infinity` are refused rather than emitted as
  the non-standard JSON literals Python would otherwise produce.

### 4.2 Row hash

```
row_hash = SHA256( ascii(prev_hash) || 0x1F || canonical_bytes )
```

`prev_hash` is the 64-character lowercase hex string, encoded as ASCII. A single
`0x1F` (unit separator) byte follows it, then the canonical bytes from §4.1. The
result is lowercase hex.

### 4.3 Genesis

```
genesis_hash = SHA256( salt || 0x1F || "audit-genesis" || 0x1F || organization_id )
```

The salt is a per-deployment secret. **It is never written into a bundle**, and
publishing it would let anyone recompute a chain from scratch. A bundle carries
only the derived `genesis_hash`.

Consequently a verifier cannot check that `genesis_hash` was derived correctly.
It can only check that row 1 links to the declared value. See
[§7.2](#72-genesis-derivation-is-not-verifiable).

### 4.4 Daily anchor

For one UTC calendar day, take the `row_hash` of every row of that day in
ascending `seq` order. These are the leaves.

```
parent = SHA256( ascii(left_hex) || ascii(right_hex) )
```

The two hex strings are concatenated with no separator, so the construction is
order-sensitive. If a level has an odd number of nodes, the last node is
duplicated to pair with itself. Repeat until one node remains: that is
`root_hash`.

`tip_hash` is the `row_hash` of the last row of that day.

## 5. `anchors[]`

```json
{
  "anchor_date": "2026-08-14",
  "root_hash": "…",
  "tip_hash": "…",
  "row_count": 61,
  "from_seq": 402,
  "to_seq": 462
}
```

All six keys are required. `anchor_date` is a `YYYY-MM-DD` UTC date.

Anchors are stored locally by the producer and copied into the bundle. They are
not published to any third party, so they add no independent timestamping. See
[§7.1](#71-anchors-are-local-only).

## 6. Verification algorithm

### 6.1 Chain

1. `seq` must start at `chain_start.from_seq` and increase by exactly 1 for each
   subsequent row. Otherwise: `seq_gap`.
2. The first row's `prev_hash` must equal `chain_start.prev_hash`. When
   `from_seq == 1` it must additionally equal `genesis_hash`. Otherwise:
   `genesis_mismatch`.
3. Every later row's `prev_hash` must equal the previous row's `row_hash`.
   Otherwise: `prev_hash_mismatch`.
4. Each row's `row_hash` is recomputed per §4.1 and §4.2 and must match the
   stored value. Otherwise: `row_hash_mismatch`.

Verification stops at the first break and reports it, matching the producer's
own behaviour.

### 6.2 Anchors

For each anchor, collect the bundle rows whose `created_at` falls on
`anchor_date` in UTC, in ascending `seq` order, and recompute `root_hash` and
`tip_hash` per §4.4. Compare `root_hash`, `tip_hash`, `row_count`, `from_seq`
and `to_seq`.

An anchor whose `[from_seq, to_seq]` range is not fully contained in the range of
rows present in the bundle is **skipped**, with reason `incomplete_day`, and is
not counted as a mismatch. A partial export legitimately contains part of a day;
reporting that as tampering would make the verifier useless.

A day present in `rows` with no matching anchor is not an error. Anchors are
written by a daily job, so the most recent day is often not yet anchored.

The two checks detect different edits, and a bundle can fail one while passing
the other. Anchor leaves are the **stored** `row_hash` values (§4.4), so editing
a row's content breaks §6.1 while leaving every root intact, and editing a
stored `row_hash` breaks §6.2 first. The example bundle in `examples/` shows the
first case: `chain BROKEN`, `anchors OK`. Read the chain result as the primary
finding; treat the anchors as a narrower second check, never as a second opinion
on the same question.

### 6.3 Format errors

A file that is not a valid bundle — malformed JSON, missing key, unknown key,
wrong type, unknown `format_version`, a `cost_usd` that does not match the
pattern in §2.1, a timestamp that does not end with `+00:00` — is an **input
error**, not a verification failure. The two must never be conflated: one means
"this file is not a bundle", the other means "this bundle has been altered".

## 7. Known limitations
These are properties of the design, not bugs, and they are listed here because a
verification tool that overstates what it proves is worse than none.

### 7.1 Anchors are local only

Anchors are computed and stored by the same system that writes the rows. They
are not published to any third party and carry no external timestamp. The chain
shows that rows have not been edited after the fact. It proves nothing against an
actor who controls both the database and the salt, because that actor can
recompute the entire chain. External anchor publication is on the roadmap; the
product does not do it today.

### 7.2 Genesis derivation is not verifiable

Per §4.3, the salt is a per-deployment secret and is never published. A verifier
sees that row 1 links to the declared `genesis_hash`; it cannot see that the
declared value was derived correctly.

### 7.3 The Merkle construction has no domain separation

Leaf and internal node inputs are not tagged differently, and an odd level
duplicates its last node. Both are the classic conditions for the second-preimage
weakness described for Certificate Transparency, where a crafted leaf set can be
made to produce a root belonging to a different tree shape.

It is not exploitable here in practice, because `row_count`, `from_seq` and
`to_seq` are stored alongside every anchor and are checked, which pins the tree
shape. It is stated anyway. Domain separation is a v2 candidate and would be a
breaking format change.

### 7.4 `actor` is an identity

The `actor` field can hold an email address, and it is inside the hash. It
therefore cannot be redacted from a bundle without breaking the chain. Anyone
sharing a bundle is sharing the actor identities in it. Bundles are intended for
auditors and regulators, not for publication.

### 7.5 The envelope is not hashed

The hash chain covers `rows` and, through them, `anchors`. It does not cover
`generated_at`, `period`, `gateway_version` or `notes`. Those envelope fields are
producer assertions about the export, not authenticated facts, and editing one
leaves a bundle that still verifies. Treat them as a label on the box, not as
part of the evidence.

Binding the envelope into the chain is a v2 candidate.

### 7.6 A bundle is metadata

No prompt or response body is ever recorded. `input_hash` and `output_hash` are
digests. A bundle answers "which request, which model, which PII class, which
policy outcome" — never "what was sent to the model".

### 7.7 This is not a declaration of conformity

The bundle is engineering evidence mapped to control requirements. Legal
sufficiency under the EU AI Act or KVKK requires independent review.

## 8. Versioning

`format_version` is an integer. A verifier must refuse a version it does not
know rather than attempt a best-effort read.

Adding a canonical field, removing one, or changing how any value is rendered
changes every hash and is a new `format_version`. Adding a non-canonical key
beside `prev_hash` and `row_hash` on a row, such as `id`, does not change hashes,
but still requires a version bump because verifiers reject unknown keys.

Signatures are deliberately absent from v1. No slot is reserved for them; adding
them will be a v2 change.
