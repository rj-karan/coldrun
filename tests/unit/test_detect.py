from __future__ import annotations

from pathlib import Path

import pytest

from coldrun.detect import (
    THRESHOLD,
    DetectError,
    FileKind,
    detect,
    interpreter_from_shebang,
    read_shebang,
    signals_for,
    sniff_kind,
)
from coldrun.runners.base import RunnerInfo
from coldrun.runners.registry import Registry
from tests.unit.runners.fake_runner import FakeRunner

FX = Path(__file__).resolve().parents[1] / "fixtures" / "detect"


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("hello.py", FileKind.SCRIPT),
        ("noshebang.py", FileKind.TEXT),
        ("hello.sh", FileKind.SCRIPT),
        ("hello.php", FileKind.TEXT),
        ("hello.go", FileKind.TEXT),
        ("hello.ps1", FileKind.TEXT),
        ("hello.c", FileKind.TEXT),
        ("utf8.txt", FileKind.TEXT),
        ("fake_elf.bin", FileKind.ELF),
        ("fake.zip", FileKind.ZIP),
        ("fake.gz", FileKind.GZIP),
        ("fake.exe", FileKind.PE),
        ("random.bin", FileKind.BINARY),
        ("empty", FileKind.EMPTY),
        ("shebang_only", FileKind.SCRIPT),
    ],
)
def test_sniff_kind(name: str, kind: FileKind) -> None:
    assert sniff_kind(FX / name) is kind


@pytest.mark.parametrize(
    ("magic", "kind"),
    [
        (b"\xcf\xfa\xed\xfe", FileKind.MACHO),
        (b"\xfd7zXZ\x00", FileKind.XZ),
        (b"BZh9", FileKind.BZIP2),
        (b"\x28\xb5\x2f\xfd", FileKind.ZSTD),
    ],
)
def test_sniff_more_magic(tmp_path: Path, magic: bytes, kind: FileKind) -> None:
    f = tmp_path / "x"
    f.write_bytes(magic + b"rest")
    assert sniff_kind(f) is kind


def test_control_heavy_text_is_binary(tmp_path: Path) -> None:
    f = tmp_path / "ctl"
    f.write_bytes(b"abc" + bytes([1, 2, 3, 4, 5, 6]) * 20)
    assert sniff_kind(f) is FileKind.BINARY


@pytest.mark.parametrize(
    ("name", "shebang", "interp"),
    [
        ("hello.py", "/usr/bin/env python3", "python3"),
        ("env_s.py", "/usr/bin/env -S python3 -u", "python3"),
        ("hello.sh", "/bin/bash", "bash"),
        ("hello.js", "/usr/bin/env node", "node"),
        ("hello.rb", "/usr/bin/env ruby", "ruby"),
        ("hello.pl", "/usr/bin/perl -w", "perl"),
        ("shebang_only", "/bin/sh", "sh"),
        ("noshebang.py", None, None),
        ("fake_elf.bin", None, None),
    ],
)
def test_shebang_and_interpreter(name: str, shebang: str | None, interp: str | None) -> None:
    assert read_shebang(FX / name) == shebang
    sig = signals_for(FX / name)
    assert sig.shebang == shebang
    assert sig.interpreter == interp
    assert sig.extension == (FX / name).suffix.lower()


@pytest.mark.parametrize(
    ("line", "interp"),
    [
        ("/usr/bin/env PYTHONUNBUFFERED=1 python3", "python3"),
        ("/usr/bin/env -S -i bash --norc", "bash"),
        ("/usr/bin/env", None),
        ("", None),
        ("/usr/bin/env 'unterminated", None),
        ("/usr/local/bin/python3.12", "python3.12"),
    ],
)
def test_interpreter_from_shebang_edge_cases(line: str, interp: str | None) -> None:
    assert interpreter_from_shebang(line) == interp


def test_shebang_with_invalid_utf8_is_ignored(tmp_path: Path) -> None:
    f = tmp_path / "bad"
    f.write_bytes(b"#!/bin/\xff\xfe\n")
    assert read_shebang(f) is None


def test_shebang_is_cut_at_newline_and_crlf(tmp_path: Path) -> None:
    f = tmp_path / "crlf"
    f.write_bytes(b"#!/bin/sh \r\necho\n")
    assert read_shebang(f) == "/bin/sh"


class Scorer(FakeRunner):
    def __init__(self, name: str, score: float) -> None:
        self.name = name
        self.score = score

    def detect(self, path: Path) -> float:
        return self.score


def reg(*runners: Scorer) -> Registry:
    r = Registry([])
    r._loaded = {x.name: RunnerInfo(x, "test") for x in runners}
    return r


def test_picks_highest_confidence_and_lists_candidates() -> None:
    d = detect(FX / "hello.py", reg(Scorer("bash", 0.2), Scorer("python", 0.9)))
    assert d.runner.name == "python"
    assert d.confidence == 0.9
    assert d.candidates == [("python", 0.9), ("bash", 0.2)]
    assert not d.forced
    assert d.reasons == ["shebang /usr/bin/env python3", "extension .py"]


def test_scores_are_clamped() -> None:
    d = detect(FX / "hello.py", reg(Scorer("x", 7.0), Scorer("y", -3.0)))
    assert d.candidates == [("x", 1.0), ("y", 0.0)]


def test_below_threshold_names_kind_shebang_and_available_runners() -> None:
    with pytest.raises(DetectError) as exc:
        detect(FX / "hello.sh", reg(Scorer("python", THRESHOLD - 0.01)))
    assert "hello.sh" in exc.value.what
    assert "script, shebang /bin/bash" in exc.value.what
    assert "--lang NAME" in exc.value.hint
    assert "Available: python" in exc.value.hint
    assert [name for name, _ in exc.value.candidates] == ["python"]
    assert exc.value.candidates[0][1] == pytest.approx(0.49)


def test_no_runners_installed() -> None:
    with pytest.raises(DetectError, match="none installed"):
        detect(FX / "hello.sh", reg())


def test_tie_asks_for_lang() -> None:
    with pytest.raises(DetectError, match=r"equally \(a, b\)"):
        detect(FX / "hello.sh", reg(Scorer("a", 0.8), Scorer("b", 0.8)))


def test_lang_override_skips_scoring() -> None:
    d = detect(FX / "fake_elf.bin", reg(Scorer("bash", 0.0)), lang="bash")
    assert d.runner.name == "bash"
    assert d.forced
    assert d.confidence == 1.0
    assert d.reasons == ["--lang bash", "extension .bin", "magic elf"]


def test_unknown_lang_lists_available() -> None:
    with pytest.raises(DetectError) as exc:
        detect(FX / "hello.sh", reg(Scorer("bash", 1.0)), lang="cobol")
    assert "no runner named 'cobol'" in exc.value.what
    assert "available: bash" in exc.value.what


def test_binary_reason_when_not_text() -> None:
    d = detect(FX / "fake.zip", reg(Scorer("archive", 0.9)))
    assert d.signals.kind is FileKind.ZIP
    assert not d.signals.is_text
    assert "magic zip" in d.reasons
