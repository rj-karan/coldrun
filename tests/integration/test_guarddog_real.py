"""Real GuardDog on the synthetic fixtures: the install hook is flagged, the plain one is not."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from coldrun.vet import guarddog
from coldrun.vet.findings import Severity

pytestmark = pytest.mark.e2e
FX = Path(__file__).resolve().parents[1] / "fixtures" / "deps"
EXE = shutil.which("guarddog")


@pytest.mark.skipif(EXE is None, reason="guarddog not installed")
def test_install_hook_is_flagged_and_benign_is_not() -> None:
    assert EXE is not None
    hooked = guarddog.scan_package(EXE, "pypi", str(FX / "hook"))
    assert [f.rule_id for f in hooked] == ["guarddog.capability-process-hooks"], hooked
    assert hooked[0].severity is Severity.MEDIUM
    assert hooked[0].line == 13
    assert guarddog.scan_package(EXE, "pypi", str(FX / "benign")) == []
