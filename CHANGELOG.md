# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The public API under semver is: the `shim-audit-verify` command's arguments,
output contract and exit codes; the names exported from `shim_audit_verify`; and
the bundle format at a given `format_version`.

## [Unreleased]

## [0.1.0] - 2026-08-29

### Added

- `shim.audit.bundle` format version 1, specified byte for byte in `FORMAT.md`,
  including the known limitations of the design.
- `shim-audit-verify` command with `--json` and `--quiet`, and exit codes `0`
  verified, `1` verification failed, `2` input error.
- Library API: `verify_bundle`, `canonical_row`, `chain_hash`, `merkle_root`,
  `genesis_hash`, `compute_row_hash`, and the frozen report types.
- Golden vectors under `tests/vectors/`, shared with the Shim server's own test
  suite so producer and verifier cannot diverge silently.
- Published example bundles under `examples/`, one intact and one with a single
  altered field.

[Unreleased]: https://github.com/GetSHIM/shim-audit-verify/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/GetSHIM/shim-audit-verify/releases/tag/v0.1.0
