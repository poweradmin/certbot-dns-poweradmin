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

1. Land changes on `main` using [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `deps:`, etc.)
2. The `release.yml` workflow runs release-please, which opens (or updates) a **Release PR** bumping the version in `pyproject.toml` and `.release-please-manifest.json`, with a generated `CHANGELOG.md` entry
3. Review and merge the Release PR. release-please tags the commit and publishes a GitHub Release
4. In the same run, `release.yml` calls the reusable `build.yml` (tests, audit, build) and then uploads the dists to PyPI from its own `publish` job. Nothing triggers on the release event, so each release publishes once

**Requires:**
- `RELEASE_APP_CLIENT_ID` variable and `RELEASE_APP_PRIVATE_KEY` secret for the GitHub App that release-please runs as (so Release PR checks start on their own)
- PyPI [trusted publishers](https://docs.pypi.org/trusted-publishers/) for this repository with environment `pypi`: one for workflow `release.yml` (automatic releases) and one for `publish.yml` (manual runs). The upload runs in a top-level job of each, never inside the reusable `build.yml`, which PyPI cannot use as a publisher. No API token is stored

### Manual publish

- **PyPI:** run `Publish to PyPI` from the Actions tab with an existing tag (e.g. `v0.3.1`)
- **TestPyPI:** run `Publish to TestPyPI`. Requires a TestPyPI trusted publisher for workflow `test-publish.yml` with environment `testpypi`

## Technical Notes

- Uses API v2 (nested wrapped responses); flat responses are still parsed
- Parses both `{"data": [...]}` and `{"data": {"zones": [...]}}` / `{"data": {"records": [...]}}`
- Record creation is idempotent (checks for existing records)
- Cleanup silently handles missing zones/records
