# Development Guide

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Testing

```bash
pytest -v              # Unit tests (uses requests-mock, no live instance needed)
tox                    # Full matrix: Python 3.10-3.14, lint, typecheck
tox -e lint            # Ruff only
tox -e typecheck       # Mypy only
```

## Release Process

1. Bump version in `pyproject.toml`
2. Commit and push to `main`
3. Create a GitHub Release with a `v*` tag:
   ```bash
   gh release create v0.x.0 --title "v0.x.0" --notes "Release notes here"
   ```
4. The `publish.yml` workflow automatically builds and uploads to PyPI

**Requires** `PYPI_API_TOKEN` secret in repository settings.

## Technical Notes

- Supports API v1 (flat responses) and v2 (nested wrapped responses)
- Parses both `{"data": [...]}` and `{"data": {"zones": [...]}}` / `{"data": {"records": [...]}}`
- Record creation is idempotent (checks for existing records)
- Cleanup silently handles missing zones/records
