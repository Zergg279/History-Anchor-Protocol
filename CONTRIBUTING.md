# Contributing

HAP is an open protocol. Contributions may include code, tests, protocol review, threat modelling, documentation, independent implementations, archive research, and Bitcoin integration review.

## Principles

- Keep consensus-critical rules small and deterministic.
- Separate protocol validity from relay, archive, display, and truth-classification policy.
- Do not introduce a required token, founder key, official server, or hidden dependency.
- Preserve compatibility with already anchored records.
- Add tests for every consensus-critical change.
- Never submit private keys, RPC credentials, personal evidence, or exploit details with real user impact to a public issue.
- Funding, employment, sponsorship, or donation size never buys merge priority, validity status, truth status, or protocol governance.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps -e .
ruff format --check hap tests scripts
ruff check hap tests scripts
bandit -q -r hap -ll
python -m pytest -q
python -m compileall -q hap
```

Protocol changes should be proposed as versioned documents with migration and compatibility analysis. Independent reimplementations are encouraged.
