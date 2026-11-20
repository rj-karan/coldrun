"""A small seccomp filter for the bubblewrap sandbox.

It returns ``ENOSYS`` ("not implemented") for kernel interfaces that ordinary
scripts and package managers do not need and that have a long record of
privilege-escalation bugs: io_uring, eBPF, perf events, userfaultfd and the
kernel keyring. ``ENOSYS`` is what an older kernel would say, so programs
that can use these interfaces fall back instead of failing.

Programs on x86_64 can also enter the kernel through the 32-bit (i386) and
x32 interfaces, and on aarch64 through 32-bit arm, so each of those gets the
same rules; x32 is refused outright. An architecture not listed here passes
through unfiltered, and ``coldrun doctor`` says so.
"""

from __future__ import annotations

import errno
import os
import platform
import struct

#: The syscalls refused, by name.
BLOCKED = (
    "keyctl", "add_key", "request_key", "bpf", "perf_event_open", "userfaultfd",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
)  # fmt: skip
#: ``AUDIT_ARCH_*`` value -> syscall numbers, from the kernel's unistd tables.
ARCHES: dict[int, dict[str, int]] = {
    0xC000003E: {  # x86_64
        "add_key": 248, "request_key": 249, "keyctl": 250, "perf_event_open": 298,
        "bpf": 321, "userfaultfd": 323,
        "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    },
    0x40000003: {  # i386, also reachable from x86_64
        "add_key": 286, "request_key": 287, "keyctl": 288, "perf_event_open": 336,
        "bpf": 357, "userfaultfd": 374,
        "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    },
    0xC00000B7: {  # aarch64 (asm-generic table)
        "add_key": 217, "request_key": 218, "keyctl": 219, "perf_event_open": 241,
        "bpf": 280, "userfaultfd": 282,
        "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    },
    0x40000028: {  # arm EABI, also reachable from aarch64
        "add_key": 309, "request_key": 310, "keyctl": 311, "perf_event_open": 364,
        "bpf": 386, "userfaultfd": 388,
        "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    },
}  # fmt: skip
X86_64 = 0xC000003E
X32_BIT = 0x40000000
#: ``platform.machine()`` values whose native calls the filter covers.
COVERED_MACHINES = frozenset(
    {"x86_64", "amd64", "i386", "i686", "aarch64", "arm64", "armv7l", "armv8l"}
)

_LD_W_ABS = 0x20
_JEQ_K = 0x15
_JGE_K = 0x35
_RET_K = 0x06
_ALLOW = 0x7FFF0000
_DENY = 0x00050000 | errno.ENOSYS
_OFF_NR, _OFF_ARCH = 0, 4


def program() -> bytes:
    """The filter as the kernel's ``struct sock_filter`` array.

    Layout: load the architecture; for each known one, a test that skips its
    block when it does not match; the block loads the syscall number and
    jumps to the shared deny for each blocked call, else allows. Anything
    left (an unknown architecture) is allowed.
    """
    # (opcode, jump-if-false, k, true branch goes to deny)
    code: list[tuple[int, int, int, bool]] = [(_LD_W_ABS, 0, _OFF_ARCH, False)]
    for arch, numbers in ARCHES.items():
        block: list[tuple[int, int, int, bool]] = [(_LD_W_ABS, 0, _OFF_NR, False)]
        if arch == X86_64:
            block.append((_JGE_K, 0, X32_BIT, True))  # x32 is refused outright
        block += [(_JEQ_K, 0, numbers[name], True) for name in BLOCKED]
        block.append((_RET_K, 0, _ALLOW, False))
        # a mismatch skips the block, with the architecture still in the accumulator
        code.append((_JEQ_K, len(block), arch, False))
        code += block
    code.append((_RET_K, 0, _ALLOW, False))
    deny = len(code)
    code.append((_RET_K, 0, _DENY, False))
    out = bytearray()
    for i, (op, jf, k, to_deny) in enumerate(code):
        jt = deny - i - 1 if to_deny else 0
        out += struct.pack("=HBBI", op, jt, jf, k)
    return bytes(out)


def memfd() -> int:
    """A file descriptor holding the program, rewound, for ``bwrap --seccomp``."""
    fd = os.memfd_create("coldrun-seccomp")
    os.write(fd, program())
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def covers(machine: str | None = None) -> bool:
    """Whether the filter applies to this machine's native system calls."""
    return (machine or platform.machine()).lower() in COVERED_MACHINES
