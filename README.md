# muzzle

Fetch, vet and sandbox any downloaded script in one command.

```
muzzle run https://github.com/someone/tool/blob/main/script.py -- --target 10.10.11.5
```

muzzle takes a script from a file, URL, GitHub repo, gist or exploit-db ID,
works out what it needs, checks it for behaviour aimed at your machine, and runs
it inside a sandbox with no network and no access to your home directory.

The project is under construction. The full specification is in
[docs/SPEC.md](docs/SPEC.md).

## Licence

MIT. See [LICENSE](LICENSE).
