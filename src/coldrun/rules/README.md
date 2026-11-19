# Rules

Semgrep rules (`semgrep/`) cover Python semantics; YARA rules (`yara/`) cover
text-level patterns in any language. Every rule has an id, a severity in its
metadata and a one-line explanation, and one `match` and one `nomatch`
fixture under `tests/fixtures/vet/`. They live inside the package so wheels
ship them. There is deliberately no top-level `rules` link: it made the build drop these
files from every release up to 1.0.0 (#110). CI checks the built wheel refuses a sample.
