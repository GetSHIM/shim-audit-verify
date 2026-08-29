# Security policy

## Supported versions

Only the latest released `shim-audit-verify` version receives security fixes.

## Reporting a vulnerability

Report suspected vulnerabilities through a private
[GitHub Security Advisory](https://github.com/GetSHIM/shim-audit-verify/security/advisories/new)
for this repository. Do not put exploit details in a public issue.

Include the affected version, environment, reproduction steps, impact and any
relevant redacted logs. Please do not send real secrets, personal data or a real
customer's bundle; a synthetic reproduction is always sufficient here.

Our commitments, as numbers rather than adjectives:

| Stage | Target |
|---|---|
| Acknowledgement of your report | 3 business days |
| Initial assessment and severity | 10 business days |
| Fix or documented mitigation for a confirmed high-severity issue | 30 days |
| Coordinated public disclosure | 90 days from the report, or on fix release, whichever is first |

We will keep you updated if a target slips, and we credit reporters in the
advisory unless you ask us not to.

## Scope

In scope:

- A crafted bundle that makes the verifier report `chain OK` while the rows it
  checked were altered. This is the failure that matters most; treat it as
  critical.
- A crafted bundle that makes the verifier report a break in an untampered
  bundle, or crash with an unhandled exception rather than exit code `2`.
- Any network access, filesystem write, subprocess execution or environment read
  by the installed package. It must do none of these.
- A dependency appearing in the published distribution. It has none, and must
  keep having none.
- Supply-chain issues in the release workflow, attestations or published
  artifacts.

Out of scope:

- The limitations documented in [FORMAT.md](FORMAT.md#7-known-limitations). Local
  anchoring, unverifiable genesis derivation, absent Merkle domain separation and
  the unhashed envelope are known and stated design properties, not
  vulnerabilities. A concrete exploit that goes beyond what those sections claim
  is in scope.
- The shim gateway itself. Report those through
  https://getshim.tech/security.

## EU Cyber Resilience Act

Shim Technologies publishes this package as free and open-source software under
Apache-2.0. Shim develops and monetises the commercial Shim gateway, so for this
package Shim acts as an **open-source software steward** within the meaning of
Regulation (EU) 2023/1781 (the Cyber Resilience Act) rather than as a
manufacturer, and this document is its coordinated vulnerability disclosure
policy.

Practically, that means: the reporting channel above is monitored, the targets
above are the ones we hold ourselves to, actively exploited vulnerabilities and
severe incidents will be reported to the relevant CSIRT and ENISA once those
obligations apply, and each release ships an SBOM plus a build attestation so
downstream users can carry out their own due diligence.

Where this package is embedded in a commercial product, the manufacturer of that
product carries the CRA manufacturer obligations, not Shim.
