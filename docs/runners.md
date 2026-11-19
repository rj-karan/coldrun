# Runners

A runner knows one language: how to recognise it, find its dependencies,
install them and run the script.

| Runner | Dependencies from | Installed with |
|---|---|---|
| Python 3 | PEP 723 block, `requirements.txt` beside the script, else imports parsed with `ast` | uv, cached under `~/.cache/coldrun/envs` |
| Python 2 | Same sources, imports read line by line | The image's pip in a pinned Python 2.7 image on Podman |
| Bash / sh | Commands the script invokes | Nothing; missing tools are reported with the `pacman` or `apt` line |
| Node | `package.json` beside the script, else `require` and `import` statements | The system `npm` with `--ignore-scripts` |
| Go | `go.mod` beside the script, else third-party imports | The system `go get` through `proxy.golang.org`; built offline |
| Ruby | `Gemfile` beside the script, else `require` lines outside the standard library | The system `gem install` from rubygems.org |

Node, Go and Ruby use the toolchain in `/usr/bin`. A version from mise, nvm or
asdf lives in your home directory, which the sandbox hides; the error says so.

## Writing a runner

A runner is a class with five methods, discovered through the
`coldrun.runners` entry-point group, so a separate package can ship one.

```python
from pathlib import Path

from coldrun.runners.base import GUEST_DEPS_DIR, DepSet, detect_by
from coldrun.vet.findings import Finding


class LuaRunner:
    name = "lua"

    def detect(self, path: Path) -> float:
        return detect_by(path, frozenset({"lua"}), {".lua": 0.8})

    def resolve_deps(self, path: Path) -> DepSet:
        return DepSet("luarocks", (), ("/usr/bin/lua",), "lua", "inferred")

    def install_cmd(self, deps: DepSet) -> list[str]:
        return []  # runs inside the sandbox, as an argument list

    def run_cmd(self, path: Path, args: list[str]) -> list[str]:
        return ["/usr/bin/lua", str(path), *args]

    def vet(self, path: Path, deps: DepSet) -> list[Finding]:
        return []
```

```toml
[project.entry-points."coldrun.runners"]
lua = "my_package.lua:LuaRunner"
```

Rules every runner follows:

- **Parse, never execute.** `detect` and `resolve_deps` read bytes, regexes or
  an AST. The host never imports, sources or runs the script.
- **Argument lists only.** Commands are lists, never shell strings, and run
  inside the sandbox.
- **Install into `GUEST_DEPS_DIR`.** That directory is the cached environment,
  writable during the install and read-only when the script runs.
- **Set `image`** on the class to run in a container image on Podman instead
  of the host toolchain.
- **Pass the contract suite.** Subclass `RunnerContract` from
  `tests/unit/runners/contract.py` with your fixtures, and pytest checks the
  rest.
