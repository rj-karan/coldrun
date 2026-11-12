from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit.runners.contract import RunnerContract
from tests.unit.runners.fake_runner import FakeRunner


class TestFakeRunner(RunnerContract):
    runner = FakeRunner()
    fixtures: list[Path]

    @pytest.fixture(autouse=True)
    def _fixtures(self, tmp_path: Path) -> None:
        fx = tmp_path / "hello.fake"
        fx.write_text("echo hi\n")
        self.fixtures = [fx]
