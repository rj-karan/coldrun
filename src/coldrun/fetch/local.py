"""Fetch a script that is already on disk by copying it into quarantine."""

from __future__ import annotations

import shutil
from pathlib import Path

from coldrun.fetch.base import FetchError, safe_filename


class LocalFetcher:
    """Copies a regular file. Directories and archives come later."""

    kind = "file"

    def matches(self, spec: str) -> bool:
        """Anything that is not a URL scheme is treated as a path."""
        return "://" not in spec

    def fetch(self, spec: str, dest: Path) -> Path:
        """Copy ``spec`` into ``dest`` without following it anywhere surprising."""
        src = Path(spec).expanduser()
        if not src.exists():
            raise FetchError(
                f"{spec} does not exist.",
                "Check the path, or pass a URL such as https://… to fetch it.",
            )
        if src.is_dir():
            raise FetchError(
                f"{spec} is a directory.",
                "Point coldrun at the script inside it; repos arrive with the GitHub fetcher.",
            )
        resolved = src.resolve()
        if not resolved.is_file():
            raise FetchError(
                f"{spec} is not a regular file.",
                "coldrun fetches scripts and archives only.",
            )
        target = dest / safe_filename(src.name)
        try:
            shutil.copyfile(resolved, target, follow_symlinks=False)
        except OSError as exc:
            raise FetchError(
                f"Could not read {spec}: {exc.strerror}.", "Check permissions."
            ) from exc
        return target
