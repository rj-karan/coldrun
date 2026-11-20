"""End to end: ``coldrun run`` on shell fixtures, through the real CLI and bubblewrap."""

from __future__ import annotations

import http.server
import os
import subprocess
import sys
import threading
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

FX = Path(__file__).resolve().parents[1] / "fixtures" / "sh"


def coldrun(*args: str, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - our own CLI
        [sys.executable, "-m", "coldrun", *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd,
        env=env,
        timeout=120,
    )


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    e = dict(os.environ)
    e["XDG_CACHE_HOME"] = str(tmp_path / "cache")
    e["COLDRUN_E2E_SECRET"] = "must-not-leak"  # noqa: S105 - a canary, not a credential
    return e


def test_hello_world_runs_sandboxed(tmp_path: Path, env: dict[str, str]) -> None:
    res = coldrun("run", str(FX / "hello.sh"), cwd=tmp_path, env=env)
    assert res.returncode == 0, res.stderr
    assert "hello from coldrun" in res.stdout
    assert "runner" in res.stderr and "sh" in res.stderr
    assert "all network access" in res.stderr
    assert not (tmp_path / "coldrun-out").exists()


def test_home_is_hidden_from_the_script(tmp_path: Path, env: dict[str, str]) -> None:
    res = coldrun("run", str(FX / "no_home.sh"), cwd=tmp_path, env=env)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "home hidden" in res.stdout


def test_args_exit_code_and_outputs(tmp_path: Path, env: dict[str, str]) -> None:
    out = tmp_path / "results"
    res = coldrun(
        "run", str(FX / "writes_and_exits_3.sh"), "--out", str(out), "--", "--target", "10.0.0.1",
        cwd=tmp_path, env=env,
    )  # fmt: skip
    assert res.returncode == 3, res.stderr
    assert "args: --target 10.0.0.1" in res.stdout
    assert (out / "result.txt").read_text() == "written\n"
    assert "result.txt" in res.stderr


def test_python_script_with_three_imports_installs_and_runs(
    tmp_path: Path, env: dict[str, str]
) -> None:
    fixture = FX.parent / "python" / "imports.py"
    res = coldrun("run", fixture.as_posix(), cwd=tmp_path, env=env)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "imports ok requests yaml BeautifulSoup" in res.stdout
    assert "PyYAML, beautifulsoup4, requests" in res.stderr
    assert "(installed)" in res.stderr
    assert not (tmp_path / "coldrun-out").exists()  # deps dir is not an output
    again = coldrun("run", fixture.as_posix(), cwd=tmp_path, env=env)
    assert again.returncode == 0, again.stdout + again.stderr
    assert "(cached)" in again.stderr


def test_bash_script_using_jq_and_curl(tmp_path: Path, env: dict[str, str]) -> None:
    res = coldrun("run", str(FX / "jq_curl.sh"), cwd=tmp_path, env=env)
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout.splitlines() == ["curl", "42"]
    assert "binaries: curl, cut, head, jq" in res.stderr


def test_deps_command_on_python_fixture(tmp_path: Path, env: dict[str, str]) -> None:
    res = coldrun("deps", (FX.parent / "python" / "imports.py").as_posix(), cwd=tmp_path, env=env)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "pypi: PyYAML, beautifulsoup4, requests" in res.stdout
    assert "sandbox" not in res.stdout


def test_unknown_lang_is_a_usage_error(tmp_path: Path, env: dict[str, str]) -> None:
    res = coldrun("run", str(FX / "hello.sh"), "--lang", "cobol", cwd=tmp_path, env=env)
    assert res.returncode == 2
    assert "no runner named 'cobol'" in res.stderr
    assert "next:" in res.stderr


def test_net_allow_without_hosts_is_a_usage_error(tmp_path: Path, env: dict[str, str]) -> None:
    res = coldrun("run", (FX / "hello.sh").as_posix(), "--net", "allow", cwd=tmp_path, env=env)
    assert res.returncode == 2
    assert "go together" in res.stderr


@pytest.mark.parametrize(
    "sample",
    [
        "yara/persistence_shell_rc.match.sh",
        "yara/obfuscated_shell.match.sh",
        "semgrep/py-exec-decoded.match.py",
    ],
)
def test_synthetic_malicious_samples_are_refused(
    tmp_path: Path, env: dict[str, str], sample: str
) -> None:
    res = coldrun("run", (FX.parent / "vet" / sample).as_posix(), cwd=tmp_path, env=env)
    assert res.returncode == 100, res.stdout + res.stderr
    assert "refusing to run" in res.stderr


def test_benign_network_script_is_not_refused(tmp_path: Path, env: dict[str, str]) -> None:
    sample = FX.parent / "vet" / "yara" / "download_exec.nomatch.sh"
    res = coldrun("run", sample.as_posix(), cwd=tmp_path, env=env)
    assert res.returncode != 100, res.stdout + res.stderr  # curl fails offline, vetting lets it run
    assert "verdict       low" in res.stderr


def test_scan_reports_high_without_running(tmp_path: Path, env: dict[str, str]) -> None:
    sample = FX.parent / "vet" / "yara" / "persistence_shell_rc.match.sh"
    res = coldrun("scan", sample.as_posix(), cwd=tmp_path, env=env)
    assert res.returncode == 100, res.stdout + res.stderr
    assert "yara.persistence_shell_rc" in res.stdout and "high" in res.stdout
    assert "sandbox" not in res.stdout and res.stderr == ""


def test_allow_host_through_the_cli(tmp_path: Path, env: dict[str, str]) -> None:
    class Hello(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "3")
            self.end_headers()
            self.wfile.write(b"ok\n")

        def log_message(self, *a: object) -> None:
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Hello)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    script = tmp_path / "fetch.sh"
    script.write_text(f"#!/bin/sh\ncurl -sS --max-time 10 http://127.0.0.1:{port}/\n")
    try:
        res = coldrun(
            "run", script.as_posix(), "--allow-host", f"127.0.0.1:{port}", cwd=tmp_path, env=env
        )
    finally:
        srv.shutdown()
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout == "ok\n"
    assert "network except --allow-host destinations" in res.stderr


def test_archive_runs_with_its_siblings_visible(tmp_path: Path, env: dict[str, str]) -> None:
    with zipfile.ZipFile(tmp_path / "tool.zip", "w") as zf:
        zf.writestr("tool/run.sh", '#!/bin/sh\nsh "$(dirname "$0")/lib/helper.sh"\necho "$0"\n')
        zf.writestr("tool/lib/helper.sh", "echo from helper\n")
    res = coldrun("run", (tmp_path / "tool.zip").as_posix(), cwd=tmp_path, env=env)
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout == "from helper\n/work/src/tool/run.sh\n"
    assert not (tmp_path / "coldrun-out").exists()


def test_a_symlink_in_work_cannot_copy_home_files_out(tmp_path: Path, env: dict[str, str]) -> None:
    # the external review's loot attack, end to end: ~/.cache sits under the fake home
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_test").write_text("PRIVATE KEY")
    env = dict(env, XDG_CACHE_HOME=str(home / ".cache"))
    script = tmp_path / "loot.sh"
    script.write_text(
        "#!/bin/sh\n"
        # scratch is home/.cache/coldrun/quarantine/q-*/scratch, five levels below home
        "ln -s ../../../../../.ssh /work/loot\n"
        "echo found > /work/real.txt\n"
    )
    res = coldrun("run", script.as_posix(), cwd=tmp_path, env=env)
    assert res.returncode == 0, res.stdout + res.stderr
    out = tmp_path / "coldrun-out"
    assert (out / "real.txt").read_text() == "found\n"
    assert not (out / "loot").exists() and not (out / "loot").is_symlink()
    assert "PRIVATE KEY" not in "".join(p.read_text() for p in out.rglob("*") if p.is_file())
    assert "loot (symlink, not copied)" in res.stderr
