"""Host-side file writes that a sandbox cannot redirect.

Code inside the sandbox can create symlinks in any directory it can write.
When the host later writes a file there, a plain ``open`` follows the link
and lands wherever the sandbox chose, such as ``~/.bashrc``. Every host write
into a place the sandbox could have touched goes through here.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path


def write_nofollow(path: Path, data: bytes | str, mode: int = 0o600) -> None:
    """Create or replace ``path`` without following a symlink at it.

    A symlink already at ``path`` is removed first; if one appears again before
    the open, ``O_NOFOLLOW`` makes the open fail instead of writing through it.
    The parent directories must be ones the sandbox cannot change.
    """
    with contextlib.suppress(FileNotFoundError):
        if path.is_symlink():
            path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data.encode() if isinstance(data, str) else data)


def tree_size(path: Path) -> int:
    """Bytes in the regular files under ``path``, never following a symlink."""
    total = 0
    for root, _, files in os.walk(path):  # os.walk does not follow symlinked directories
        for name in files:
            f = Path(root, name)
            if not f.is_symlink():
                total += f.lstat().st_size
    return total
