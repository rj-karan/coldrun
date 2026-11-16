# Rules

Semgrep rules (`semgrep/`) cover Python semantics; YARA rules (`yara/`) cover
text-level patterns in any language. Every rule has an id, a severity in its
metadata and a one-line explanation, and one `match` and one `nomatch`
fixture under `tests/fixtures/vet/`. They live inside the package so wheels
ship them; the top-level `rules` symlink keeps the spec's path.
