# AUR packages

Until the AUR takes new accounts again, `.github/workflows/arch-package.yml` builds the
release package from each tag, tests it and attaches it to the GitHub release.

- `coldrun/` builds a tagged release from the GitHub tag tarball.
- `coldrun-git/` builds the latest `main`.

CI (`.github/workflows/aur.yml`) builds both from the checkout in an Arch container,
runs `namcap`, checks `.SRCINFO`, installs the release package and runs it.

## Publishing a release

After tagging `vX.Y.Z` (the release PR already set `pkgver`):

```sh
cd packaging/aur/coldrun
updpkgsums                        # pins the tag tarball's sha256
makepkg --printsrcinfo > .SRCINFO
git clone ssh://aur@aur.archlinux.org/coldrun.git /tmp/aur-coldrun
cp PKGBUILD .SRCINFO /tmp/aur-coldrun/
cd /tmp/aur-coldrun && git add PKGBUILD .SRCINFO && git commit -m "coldrun X.Y.Z" && git push
```

`coldrun-git` is published the same way once; its version comes from `git describe`.
