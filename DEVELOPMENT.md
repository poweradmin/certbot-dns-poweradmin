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

Releases are automated via [release-please](https://github.com/googleapis/release-please).

1. Land changes on `main` using [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore(deps):`, etc.)
2. The `release.yml` workflow runs release-please, which opens (or updates) a **Release PR** with the bumped version in `pyproject.toml` and a generated `CHANGELOG.md` entry
3. Review and merge the Release PR — release-please tags the commit and publishes a GitHub Release
4. The `publish.yml` workflow then builds and uploads the package to PyPI

**Requires** `PYPI_API_TOKEN` secret in repository settings.

### Manual TestPyPI publish

Trigger the `Publish to TestPyPI` workflow via the Actions tab (`workflow_dispatch`). Requires `TEST_PYPI_API_TOKEN`.

## Technical Notes

- Supports API v1 (flat responses) and v2 (nested wrapped responses)
- Parses both `{"data": [...]}` and `{"data": {"zones": [...]}}` / `{"data": {"records": [...]}}`
- Record creation is idempotent (checks for existing records)
- Cleanup silently handles missing zones/records
