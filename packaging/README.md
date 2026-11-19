# Packaging

- `man/coldrun.1` and `completions/` (bash, zsh, fish) are generated from the CLI by
  `uv run python packaging/generate.py`. A unit test fails while they are stale.
- `aur/` holds the Arch User Repository packages; see `aur/README.md` for publishing.
