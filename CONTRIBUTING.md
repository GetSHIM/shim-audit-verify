# Contributing

This repository exists so that a stranger can check a claim we make about our
own product. That gives it two unusual rules.

**The format is not ours to change here.** `FORMAT.md` documents what the shim
gateway already produces. If a change to this repository would make a bundle
produced by a released gateway stop verifying, the change is wrong, even if it
is tidier. Format changes start on the producer side and arrive here with a
`format_version` bump and new golden vectors.

**No runtime dependencies. Ever.** The auditability of this verifier comes from
being readable end to end. `hashing.py` imports nothing but `hashlib` and `json`,
and it stays that way: every import is something an auditor has to read too. A
pull request adding a runtime dependency will be declined without discussion of
its merits.

Before a pull request:

```console
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked ty check
uv run --locked coverage run -m pytest
uv run --locked coverage report
uv run --locked python scripts/generate_vectors.py --check
uv run --locked python scripts/generate_examples.py --check
uv build --no-build-isolation
git diff --check
```

Coverage is enforced at 100% for lines and branches. The modules are small; there
is no excuse. If a line cannot be reached, delete it rather than exempt it.

Other expectations:

- Use synthetic values everywhere. Never commit a real bundle, a real tenant id,
  a production salt or anything derived from real traffic. `tests/test_examples.py`
  enforces part of this, but it cannot catch everything.
- New behaviour needs a test that fails without it. Bug fixes need the failing
  case first.
- Docstrings say *why*, not *what*. The code already says what.
- Keep the language honest: *tamper-evident*, never "tamper-proof" or "immutable".
  If a change makes a stronger claim than the design supports, the claim is the
  bug.
- A change to what the verifier proves must update
  [FORMAT.md](FORMAT.md#7-known-limitations) and the README's "What it does not
  prove" section in the same pull request.

Golden vectors and examples are generated, never hand-edited. Run the two
generator scripts and commit their output.
