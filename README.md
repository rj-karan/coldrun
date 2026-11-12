# coldrun

[![CI](https://github.com/rj-karan/coldrun/actions/workflows/ci.yml/badge.svg)](https://github.com/rj-karan/coldrun/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/rj-karan/coldrun/graph/badge.svg)](https://codecov.io/gh/rj-karan/coldrun)
[![PyPI](https://img.shields.io/pypi/v/coldrun?label=pypi)](https://pypi.org/project/coldrun/)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

Fetch, vet and sandbox any downloaded script in one command.

```
coldrun run https://github.com/someone/tool/blob/main/script.py -- --target 10.10.11.5
```

coldrun takes a script from a file, URL, GitHub repo, gist or exploit-db ID,
works out what it needs, checks it for behaviour aimed at your machine, and runs
it inside a sandbox with no network and no access to your home directory.

The project is under construction. The full specification is in
[docs/SPEC.md](docs/SPEC.md).

## Licence

MIT. See [LICENSE](LICENSE).
