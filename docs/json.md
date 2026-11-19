# JSON report

`--json` on `run`, `scan` and `deps` prints one JSON document on stdout. The
human report, and the script's own output, go to stderr, so stdout stays
parseable.

```sh
coldrun scan ./tool.py --json | jq '.verdict, [.findings[].rule_id]'
```

Fields are `null` until the pipeline step that fills them has run, so a failed
run shows how far it got. `schema_version` is 1: new fields may appear without
a bump, and a field that changes meaning or disappears bumps it.

## Schema

```json
--8<-- "report.schema.json"
```
