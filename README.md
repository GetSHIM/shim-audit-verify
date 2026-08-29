<p align="center">
  <a href="https://getshim.tech">
    <img src="https://raw.githubusercontent.com/GetSHIM/shim-audit-verify/main/docs/assets/shim-logo.svg" alt="shim" width="280">
  </a>
</p>

<h1 align="center">shim Audit Verify</h1>

<p align="center">
  <strong>Check a shim audit bundle yourself, on your own machine.</strong><br>
  No account, no network, no dependencies. If a row was edited after the fact,
  this tells you which one.
</p>

<p align="center">
  <a href="https://getshim.tech">Website</a> ·
  <a href="https://github.com/GetSHIM/shim-audit-verify/blob/main/FORMAT.md">Format specification</a> ·
  <a href="https://github.com/GetSHIM/shim">shim</a> ·
  <a href="https://github.com/GetSHIM/shim-guard">shim Guard</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/shim-audit-verify/"><img src="https://img.shields.io/pypi/v/shim-audit-verify.svg?logo=pypi&amp;label=PyPI" alt="PyPI version"></a>
  <a href="https://github.com/GetSHIM/shim-audit-verify/actions/workflows/ci.yml"><img src="https://github.com/GetSHIM/shim-audit-verify/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/shim-audit-verify/"><img src="https://img.shields.io/pypi/pyversions/shim-audit-verify.svg?logo=python&amp;logoColor=white" alt="Python versions"></a>
  <a href="https://github.com/GetSHIM/shim-audit-verify/blob/main/LICENSE"><img src="https://img.shields.io/github/license/GetSHIM/shim-audit-verify.svg" alt="License"></a>
  <a href="https://github.com/GetSHIM/shim-audit-verify/stargazers"><img src="https://img.shields.io/github/stars/GetSHIM/shim-audit-verify.svg?style=flat&amp;logo=github" alt="GitHub stars"></a>
</p>

> [!IMPORTANT]
> A `chain OK` means the rows were not altered after they were written. It does
> **not** prove they are complete, correctly derived, or independently
> timestamped, because the daily anchors never leave the system that wrote them.
> Read [what it does not prove](#what-it-does-not-prove) before you rely on a
> result.

A shim gateway writes a metadata-only audit row for every AI request, and each
row's hash covers the previous row's hash. This tool takes an exported bundle of
those rows and recomputes the whole chain on your machine. If a row was edited,
deleted, inserted or reordered after the fact, it tells you which one.

## What it does not prove

Read this before you rely on a `chain OK`. The full list is in
[FORMAT.md](https://github.com/GetSHIM/shim-audit-verify/blob/main/FORMAT.md#7-known-limitations).

- **Anchors are local only.** The daily Merkle anchors are computed and stored by
  the same system that writes the rows, and are not published anywhere. The chain
  shows rows were not edited after the fact. It proves nothing against an actor
  who controls both the database and the chain salt, because that actor can
  recompute everything from scratch. External anchor publication is on the
  roadmap; the product does not do it today.
- **Genesis derivation is not verifiable.** The chain root is derived from a
  per-deployment secret salt that is never published. This tool sees that row 1
  links to the declared root; it cannot see that the root was derived correctly.
- **A bundle is metadata.** No prompt or response body is ever recorded. A bundle
  answers "which request, which model, which PII class, which policy outcome",
  never "what was sent to the model".
- **This is not a declaration of conformity.** It is engineering evidence. Legal
  sufficiency under the EU AI Act or KVKK requires independent review.

The term used throughout is *tamper-evident*, never "tamper-proof" or "immutable
ledger", because the first is what the design achieves and the other two are not.

## Quickstart

Nothing to install and no account. The tool reads the file you give it and
touches the network for nothing.

```console
$ curl -sO https://raw.githubusercontent.com/GetSHIM/shim-audit-verify/main/examples/shim-audit-sample.json
$ uvx shim-audit-verify shim-audit-sample.json
bundle   shim.audit.bundle v1   org 3f2b…   gateway shim-gateway/1.4.2
chain    OK          rows 1..305 (305 checked)   anchored to genesis
anchors  OK          5 verified, 0 skipped
```

`pipx run shim-audit-verify shim-audit-sample.json` works the same way, as does
`pip install shim-audit-verify` followed by `shim-audit-verify`.

## Tamper demo

The second published file is a byte-for-byte copy of the first with one field
changed: row 173's `prompt_tokens` is one higher. Nothing else differs, and no
hash in the file was touched.

```console
$ curl -sO https://raw.githubusercontent.com/GetSHIM/shim-audit-verify/main/examples/shim-audit-sample-tampered.json
$ uvx shim-audit-verify shim-audit-sample-tampered.json
bundle   shim.audit.bundle v1   org 3f2b…   gateway shim-gateway/1.4.2
chain    BROKEN      first break at seq 173: row_hash_mismatch
                     last verified seq 172
anchors  OK          5 verified, 0 skipped
$ echo $?
1
```

The anchors still verify, and that is correct: an anchor is a tree over the
stored row hashes, and this edit did not touch a row hash. The chain is what
catches an edited field. The two checks cover different things, which is why the
tool reports them separately.

Diff the two files yourself to confirm only that one field moved.

## Usage

```
shim-audit-verify BUNDLE.json [--json] [--quiet]
```

- `-` reads the bundle from standard input.
- `--json` emits the machine-readable report.
- `--quiet` prints nothing; use the exit code.

Exit codes are part of the contract:

| Code | Meaning |
|---|---|
| `0` | verified |
| `1` | verification failed: the bundle was altered |
| `2` | input error: the file is not a well-formed bundle |

`1` and `2` are deliberately distinct. A malformed file must never read as
tampering, and tampering must never read as a typo.

## Library

```python
from shim_audit_verify import verify_bundle, canonical_row, chain_hash, merkle_root

report = verify_bundle(bundle_dict)  # -> VerificationReport (frozen dataclass)
```

`canonical_row`, `chain_hash` and `merkle_root` are exported on purpose: they are
the reference for anyone reimplementing the format in another language.
[FORMAT.md](https://github.com/GetSHIM/shim-audit-verify/blob/main/FORMAT.md) is the byte-level specification, and
`tests/vectors/` holds golden vectors to check a reimplementation against. The
shim server runs those same vectors in its own test suite, so the producer cannot
change the format without breaking this repository's contract.

## Getting a bundle of your own

A shim tenant exports one from the gateway:

```console
$ curl -H "Authorization: Bearer $SHIM_TOKEN" \
    "$SHIM_URL/api/v1/compliance/audit/bundle?start=2026-08-01T00:00:00Z&end=2026-08-31T23:59:59Z" \
    -o bundle.json
$ uvx shim-audit-verify bundle.json
```

## Development

```console
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked ty check
uv run --locked coverage run -m pytest
uv run --locked coverage report
```

Coverage is enforced at 100% for lines and branches. See
[CONTRIBUTING.md](https://github.com/GetSHIM/shim-audit-verify/blob/main/CONTRIBUTING.md).

## Project documentation

- [Format specification](https://github.com/GetSHIM/shim-audit-verify/blob/main/FORMAT.md)
- [Known limitations](https://github.com/GetSHIM/shim-audit-verify/blob/main/FORMAT.md#7-known-limitations)
- [Changelog](https://github.com/GetSHIM/shim-audit-verify/blob/main/CHANGELOG.md)
- [Contributing](https://github.com/GetSHIM/shim-audit-verify/blob/main/CONTRIBUTING.md)
- [Security policy](https://github.com/GetSHIM/shim-audit-verify/blob/main/SECURITY.md)

## Related projects

- [shim](https://github.com/GetSHIM/shim) — the AI trust-boundary gateway that
  produces these bundles. This repository is deliberately separate: a verifier
  that shipped with the thing it verifies would be worth very little.
- [shim Guard](https://github.com/GetSHIM/shim-guard) — local pre-submit privacy
  protection for coding-agent CLIs.

## License

Apache-2.0. See [LICENSE](https://github.com/GetSHIM/shim-audit-verify/blob/main/LICENSE).
