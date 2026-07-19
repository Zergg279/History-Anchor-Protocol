# Build and verification report — v1.0.0

Date: 19 July 2026  
Release posture: first public reference implementation, finalised under the pseudonym Horus

## Results completed in this environment

- Python source lines in `hap/`: **5,939**.
- Direct runtime dependencies: **4** (`cryptography`, `fastapi`, `uvicorn`, `httpx`).
- Automated suite: **212 passed, 1 skipped**.
- Skipped test: real Bitcoin Core regtest lifecycle; `bitcoind` is not installed in this environment.
- Branch-aware coverage across the complete shipped `hap` package: **92%**.
- CI coverage floor: **90%**; a regression below this level fails the build.
- Resource warnings: **zero**; `ResourceWarning` and unraisable pytest warnings are treated as errors.
- Two-process HTTP lifecycle: **passed** (`relay → peer sync → coordinator → deterministic batch → proof verification`).
- Deterministic conformance vectors: **passed** as part of the suite.
- Ruff lint and formatting: **passed**.
- Bandit scan at medium/high severity: **passed with no findings**.
- Python byte-compilation and shell syntax checks: **passed**.
- Wheel reproducibility: **two independent fixed-epoch builds were byte-identical**.
- Release reproducibility: **two independent packaging runs produced byte-identical ZIP, wheel, and Git bundle assets**.
- Portable Git bundle: **plain clone selects `main`; cloned `HEAD` and annotated `v1.0.0` resolve to the release commit**.
- Exact installed wheel: **CLI identity, funding metadata, signed-record submission, direct batching, and portable package construction passed outside the source tree**.

## Coverage highlights

- canonical codec, configuration, authentication, package validation, archive validation: **100%**;
- Bitcoin RPC and transaction handling: **99%**;
- peer synchronisation: **99%**;
- CLI: **98%**;
- signed records and batches: **98%**;
- relay policy and encrypted wallets: **97%**;
- anchors: **96%**;
- proof validation: **95%**;
- Bitcoin commitment discovery and recovery: **94%**;
- HTTP API: **92%**.

Coverage is a defect-detection aid, not proof of correctness. The remaining confidence work is predominantly environmental: real Bitcoin Core, signet, concurrency, interrupted writes, hostile network operation, and independent implementations.

## Hardening defects found and corrected

The expanded tests found a real peer-resolution integrity defect. A peer could return a structurally valid package for a different Bitcoin commitment; the candidate was rejected, but the rejected object could remain assigned and be processed after the peer loop. The resolver now assigns a package only after its batch identifier exactly matches the commitment being resolved. A regression test permanently exercises this attack path.

SQLite ownership was also hardened. Storage close operations are idempotent, storage and service objects support context-manager use, and a best-effort cleanup guard protects short-lived tooling. The suite now fails on leaked SQLite `ResourceWarning`s.

## Trust-boundary tests included

The suite covers, among other cases:

- canonical signed-record and identifier validation;
- deterministic Merkle batches and Bitcoin commitment encoding;
- `txid:vout` anchor identity and active-chain reorganisation handling;
- malformed Bitcoin RPC responses and transaction construction failures;
- hostile, oversized, malformed, stalled, and wrong-commitment peers;
- recovery without trusting imported confirmation status;
- corrupted snapshots and archive relationship failures;
- content-addressed evidence verification and survival archives;
- base-protocol acceptance remaining pseudonymous and permissionless;
- responsible-profile person-impact, cooling, challenge, context, and trust-store rules;
- provenance separation between protocol facts, signed declarations, and analytical overlays;
- funding metadata remaining outside protocol validity, governance, ranking, and node operation;
- the complete user-facing command-line surface, including error and cleanup paths.

## Checks still requiring an external environment

- Run `scripts/regtest_e2e.sh` against a real Bitcoin Core regtest node.
- Broadcast and independently verify a real signet commitment.
- Exercise concurrent writers, forced process termination, disk-full and power-loss recovery.
- Commission Docker, TLS, firewall, backup, destruction, and restore on a target host.
- Run a networked dependency vulnerability audit.
- Obtain independent security, privacy, and legal review.
- Obtain a second independently written validator and compare conformance results.

## Release conclusion

The exact source is suitable for public open-source publication, independent inspection, reproduction, and real regtest/signet commissioning. It is a hardened first reference implementation, not a claim that software cannot fail, that arbitrary historical claims are true, or that unrestricted anonymous public hosting is safe without external commissioning and review.
