## What and why

<!-- One or two paragraphs. What changes, and why this way. -->

Closes #

## How it was tested

<!-- Commands run and their result. For a bug fix, name the test that failed before the fix. -->

## Checklist

- [ ] Tests added or updated, and `uv run pytest` passes
- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy` pass
- [ ] Docs updated where behaviour changed
- [ ] CHANGELOG.md has an entry under Unreleased
- [ ] No fetched content is executed or imported on the host; no `shell=True`; fixtures are synthetic
