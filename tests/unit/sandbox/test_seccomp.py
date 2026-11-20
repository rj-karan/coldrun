"""The seccomp program, evaluated by a tiny classic-BPF interpreter for every architecture."""

from __future__ import annotations

import errno
import os
import struct

import pytest

from coldrun.sandbox import seccomp

ALLOW = 0x7FFF0000
DENY = 0x00050000 | errno.ENOSYS


def run_bpf(prog: bytes, arch: int, nr: int) -> int:
    """Evaluate a seccomp filter the way the kernel does, for the opcodes we emit."""
    insns = [struct.unpack("=HBBI", prog[i : i + 8]) for i in range(0, len(prog), 8)]
    data = {0: nr, 4: arch}
    acc, pc = 0, 0
    while True:
        op, jt, jf, k = insns[pc]
        if op == 0x20:  # ld [k]
            acc = data[k]
            pc += 1
        elif op == 0x15:  # jeq #k
            pc += 1 + (jt if acc == k else jf)
        elif op == 0x35:  # jge #k
            pc += 1 + (jt if acc >= k else jf)
        elif op == 0x06:  # ret #k
            return int(k)
        else:  # pragma: no cover - would mean the program grew an opcode
            raise AssertionError(f"unknown opcode {op:#x}")


@pytest.mark.parametrize("arch", list(seccomp.ARCHES))
def test_every_blocked_call_is_refused_on_every_architecture(arch: int) -> None:
    prog = seccomp.program()
    for name in seccomp.BLOCKED:
        assert run_bpf(prog, arch, seccomp.ARCHES[arch][name]) == DENY, name


@pytest.mark.parametrize("arch", list(seccomp.ARCHES))
def test_ordinary_calls_pass(arch: int) -> None:
    blocked = set(seccomp.ARCHES[arch].values())
    prog = seccomp.program()
    for nr in range(460):
        if nr not in blocked:
            assert run_bpf(prog, arch, nr) == ALLOW, nr


def test_x32_is_refused_and_unknown_architectures_pass() -> None:
    prog = seccomp.program()
    assert run_bpf(prog, seccomp.X86_64, seccomp.X32_BIT | 0) == DENY
    assert run_bpf(prog, seccomp.X86_64, seccomp.X32_BIT | 250) == DENY
    assert run_bpf(prog, 0xC00000F3, 219) == ALLOW  # riscv64: not covered


def test_jump_offsets_fit_and_memfd_is_rewound() -> None:
    prog = seccomp.program()
    assert len(prog) % 8 == 0 and len(prog) // 8 < 256
    fd = seccomp.memfd()
    try:
        assert os.read(fd, len(prog) + 1) == prog
    finally:
        os.close(fd)


def test_covers() -> None:
    assert seccomp.covers("x86_64") and seccomp.covers("aarch64") and seccomp.covers("armv7l")
    assert not seccomp.covers("riscv64") and not seccomp.covers("ppc64le")
    assert isinstance(seccomp.covers(), bool)
