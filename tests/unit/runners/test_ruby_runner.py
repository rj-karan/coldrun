from __future__ import annotations

from pathlib import Path

import pytest

from coldrun.runners.base import GUEST_DEPS_DIR
from coldrun.runners.ruby import RubyRunner, _gems
from tests.unit.runners.contract import RunnerContract

FX = Path(__file__).resolve().parents[2] / "fixtures" / "ruby"


class TestRubyRunnerContract(RunnerContract):
    runner = RubyRunner()
    fixtures = sorted(FX.glob("*.rb"))


@pytest.mark.parametrize(
    ("content", "suffix", "score"),
    [
        ("#!/usr/bin/env ruby\n", "", 1.0),
        ("#!/usr/bin/ruby -w\n", ".txt", 1.0),
        ("#!/bin/sh\n", ".rb", 0.0),
        ("puts 1\n", ".rb", 0.8),
        ("puts 1\n", ".py", 0.0),
    ],
)
def test_detect(tmp_path: Path, content: str, suffix: str, score: float) -> None:
    f = tmp_path / f"s{suffix}"
    f.write_text(content)
    assert RubyRunner().detect(f) == score


def test_gems_from_require() -> None:
    src = """
require 'socket'
require "net/http"
require 'net/ssh'
require('nokogiri')
require "colorize/version"
require_relative 'lib/helper'
require './local'
  require 'active_support'
"""
    assert _gems(src) == ["activesupport", "colorize", "net-ssh", "nokogiri"]


def test_resolve_install_and_run(tmp_path: Path) -> None:
    r = RubyRunner()
    hello = r.resolve_deps(FX / "hello.rb")
    assert (hello.packages, hello.system_binaries) == ((), ("/usr/bin/ruby",))
    assert r.install_cmd(hello) == []
    deps = r.resolve_deps(FX / "deps.rb")
    assert (deps.packages, deps.ecosystem) == (("colorize",), "rubygems")
    assert r.install_cmd(deps)[-3:] == ["--install-dir", GUEST_DEPS_DIR, "colorize"]
    assert r.run_cmd(Path("/work/x.rb"), ["a"])[-3:] == ["/usr/bin/ruby", "/work/x.rb", "a"]
    (tmp_path / "Gemfile").write_text(
        "source 'https://rubygems.org'\ngem 'httparty', '~> 0.21'\n  gem \"pry\"\n"
    )
    (tmp_path / "x.rb").write_text("require 'ignored'\n")
    gf = r.resolve_deps(tmp_path / "x.rb")
    assert (gf.packages, gf.source) == (("httparty", "pry"), "Gemfile")
