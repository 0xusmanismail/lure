# FILE: lure/runner.py
"""
Lure runner — sandboxed ELF execution engine.

Isolation model (full):
  - User namespace (--map-root-user)
  - Network namespace (blocks outbound by default)
  - Mount namespace + minimal read-only chroot
  - PID namespace
  - seccomp-bpf syscall allow-list, applied to the guest binary only
    (via a small compiled guest_wrapper — see _ROOT_INIT_SRC below —
    so strace itself is never filtered and can keep tracing normally)

Fallback (if mount namespace unavailable):
  - User namespace + network namespace only, no seccomp

Fallback (if seccomp/guest_wrapper unavailable but mount namespace
is fine):
  - Full mount+PID isolation, no seccomp

Uses strace for behavioral observation.
"""

import os
import re
import sys
import json
import time
import shlex
import shutil
import signal
import tempfile
import datetime
import threading
import subprocess
import uuid
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich import box

from lure.inspector import is_elf_file, NOT_ELF_ERROR

# record=True lets us export the full rendered transcript to a text
# file for 'lure run --save', while still printing to the terminal
# exactly as before.
console = Console(record=True)


# ── Mount-namespace sandbox root ─────────────────────────────────────────────
#
# 'lure run' builds a minimal chroot for the guest binary: read-only
# bind mounts of /usr, /lib, /lib64, /bin, /sbin (if present), an
# isolated /proc, a size-capped tmpfs /tmp, a handful of standard
# /dev nodes, and just enough of /etc for the dynamic linker to work.
# This script is what actually runs INSIDE the new mount+pid namespace
# (spawned by `unshare --mount --pid --fork ...`) — it sets the root
# up, compiles the guest_wrapper (see WRAPPER_C_SRC below) inside the
# chroot, then execs into strace -> guest_wrapper -> the guest binary.
# strace itself is never seccomp-filtered — only guest_wrapper (and,
# once it installs the filter and execs, the guest binary) is.
#
# It writes a single byte to a pre-opened marker file immediately
# before the final exec. That's the only reliable way to tell "sandbox
# setup failed" apart from "the guest binary ran and exited" — once
# we're past this point, the guest's own exit code looks identical to
# a setup failure from the parent's point of view. A SECOND, separate
# marker tracks whether seccomp itself actually got installed: mount
# namespace setup can succeed even when the guest_wrapper couldn't be
# compiled or its filter couldn't be installed (e.g. no C compiler
# available, or a kernel that rejects PR_SET_SECCOMP), and the parent
# needs to report that distinction accurately in the isolation label.
SETUP_FAILURE_EXIT = 97

# guest_wrapper: a tiny, standalone C program installing a seccomp-bpf
# allow-list on ITSELF before execve-ing into the real guest binary.
# It is compiled at runtime, inside the chroot, by the init script
# below — never on the host. See its own header comment (embedded
# here verbatim) for the full design rationale, including two subtle
# bugs that were caught and fixed via live kernel install tests during
# development: a degenerate zero-distance BPF jump, and a no-match
# fall-through path that could silently defeat the allow-list.
WRAPPER_C_SRC = '/* lure-wrapper: installs a seccomp-bpf allow-list filter on ITSELF,\n * then execve\'s into the real guest binary. Compiled at runtime from\n * this embedded source, run by strace (which is NOT itself filtered --\n * only this wrapper and whatever it execs into are).\n *\n * Usage: lure-wrapper <guest_binary_path> <no_seccomp_marker_fd> [guest argv...]\n *\n * argv[0] passed to the guest binary is set to <guest_binary_path>\n * itself, so the guest sees a normal argv[0] as if it had been\n * exec\'d directly.\n *\n * If seccomp installation fails for any reason, this wrapper writes\n * a single byte to the pre-opened marker fd (passed as argv[2]) and\n * proceeds to exec the guest UNFILTERED rather than aborting the run.\n *\n * Note on socket family filtering: classic BPF seccomp can only see\n * raw syscall ARGUMENTS (register values), never memory a pointer\n * argument points to. socket(domain, type, protocol)\'s domain is a\n * plain integer in args[0], so it CAN be filtered directly (allowed\n * only for AF_UNIX below). connect/bind/sendto/recvfrom\'s first\n * argument is a file descriptor, not a family -- the actual family\n * was already decided when that fd\'s socket() call was made. Since\n * socket() itself is gated to AF_UNIX-only, any fd a guest can\n * legitimately hold already refers to an AF_UNIX socket, so those\n * four calls are safe to allow unconditionally at this layer.\n *\n * Note on the JEQ chain construction (read this before touching the\n * comparison-building code below): classic BPF jump offsets (jt/jf)\n * are 8-bit fields, and a jump of distance 0 is indistinguishable\n * from falling through to the next instruction. This means a flat\n * chain\'s LAST comparison can never correctly express "jump to the\n * instruction immediately after me" via jt alone -- so every chain\n * here ends with an explicit spacer instruction before its shared\n * match-landing RET, guaranteeing every jt is a real jump (>=1).\n *\n * CRITICALLY -- and this is the part that bit us hard during\n * development -- the LAST comparison\'s NO-MATCH path (jf) must ALSO\n * be handled explicitly: its natural fall-through lands on the\n * spacer, which unconditionally reaches this chain\'s own RET action.\n * Left alone, that silently applies this chain\'s match-action (e.g.\n * ALLOW) to every syscall that DIDN\'T match anything, defeating the\n * entire allow-list. Every chain below therefore gives its last\n * comparison a jf that explicitly skips PAST the spacer and RET,\n * landing on whatever the caller places immediately next (the real\n * default). Both the match and no-match paths for every single\n * comparison were exhaustively verified at generation time, not just\n * spot-checked, after this exact bug was caught live via a kernel\n * install test where an unlisted syscall (getppid) was silently\n * allowed through.\n */\n#include <stddef.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n#include <errno.h>\n#include <string.h>\n#include <linux/audit.h>\n#include <linux/filter.h>\n#include <linux/seccomp.h>\n#include <sys/prctl.h>\n#include <sys/syscall.h>\n\n#define SECCOMP_DATA_NR_OFFSET     0\n#define SECCOMP_DATA_ARCH_OFFSET   4\n#define SECCOMP_DATA_ARGS0_OFFSET 16\n\n#define SYS_SOCKET_NR 41\n#define AF_UNIX_VAL   1\n\n/* Allowed syscalls (178 total; \'socket\' is handled\n * separately below with an address-family condition, not listed\n * here). */\nstatic const int ALLOW_NRS[] = {\n    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,\n    12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,\n    24, 25, 26, 27, 28, 32, 33, 34, 35, 37, 39, 40,\n    42, 44, 45, 49, 53, 56, 57, 58, 59, 60, 61, 62,\n    63, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82,\n    83, 84, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,\n    96, 97, 98, 99, 100, 102, 104, 105, 106, 107, 108, 109,\n    110, 111, 112, 115, 117, 118, 119, 120, 121, 124, 125, 126,\n    127, 128, 130, 131, 140, 141, 142, 143, 144, 145, 149, 150,\n    151, 152, 157, 158, 159, 160, 162, 186, 200, 201, 202, 203,\n    204, 213, 217, 218, 219, 228, 229, 230, 231, 232, 233, 234,\n    247, 253, 254, 255, 257, 258, 260, 262, 263, 264, 265, 266,\n    267, 268, 269, 270, 271, 273, 274, 281, 282, 283, 284, 286,\n    287, 289, 290, 291, 292, 293, 294, 297, 302, 306, 316, 318,\n    319, 322, 326, 332, 334, 435, 437, 439, 441, 449,\n};\n#define N_ALLOW ((int)(sizeof(ALLOW_NRS) / sizeof(ALLOW_NRS[0])))\n\n/* Explicitly blocked syscalls (32 total) -- these get\n * SIGSYS instead of falling through to the default EPERM, so a\n * guest attempting one of these is killed rather than just seeing a\n * failed call it might retry or work around. */\nstatic const int DENY_NRS[] = {\n    101, 103, 139, 155, 165, 166, 172, 173, 174, 175, 176, 178,\n    180, 183, 212, 246, 248, 249, 250, 272, 298, 303, 304, 308,\n    313, 317, 320, 321, 323, 425, 426, 427,\n};\n#define N_DENY ((int)(sizeof(DENY_NRS) / sizeof(DENY_NRS[0])))\n\n/* Appends a correctly-verified JEQ chain to `prog` starting at\n * `*pc`, testing each value in `nrs` (nrs_count entries) against the\n * syscall number already loaded into the BPF accumulator. On match,\n * jumps to a RET instruction (with k=ret_action_on_match) placed at\n * the end of this chain. On no match across ALL entries, execution\n * falls through to whatever the caller appends immediately next --\n * NOT to this chain\'s own RET. See the file header comment for why\n * this distinction is safety-critical. Advances *pc past the emitted\n * instructions (nrs_count + 2: the comparisons, one spacer, one RET).\n */\nstatic void append_chain(struct sock_filter *prog, int *pc,\n                          const int *nrs, int nrs_count,\n                          unsigned int ret_action_on_match) {\n    int base = *pc;\n    for (int i = 0; i < nrs_count; i++) {\n        int jt = nrs_count - i;  /* on match: land on RET (index base+nrs_count+1) */\n        int jf = 0;              /* on no match: fall through to next comparison */\n        if (i == nrs_count - 1) {\n            /* Last entry: no-match must skip PAST the spacer and RET\n             * (2 instructions) to reach the caller\'s next instruction. */\n            jf = 2;\n        }\n        prog[*pc] = (struct sock_filter)\n            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)nrs[i], jt, jf);\n        (*pc)++;\n    }\n    prog[*pc] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JA | BPF_K, 0, 0, 0);  /* spacer */\n    (*pc)++;\n    prog[*pc] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, ret_action_on_match);\n    (*pc)++;\n\n    /* Exhaustive self-check before this filter is ever installed:\n     * every comparison\'s match path must land exactly on the RET\n     * instruction just emitted, and the last comparison\'s no-match\n     * path must land exactly one instruction past it. A mismatch\n     * here means a real bug in this function, not the syscall list --\n     * abort loudly rather than install a silently-broken filter. */\n    int ret_idx = base + nrs_count + 1;\n    int after_idx = ret_idx + 1;\n    for (int i = 0; i < nrs_count; i++) {\n        int idx = base + i;\n        int landing_match = idx + 1 + prog[idx].jt;\n        if (landing_match != ret_idx) {\n            fprintf(stderr, "lure-wrapper: internal error: chain entry %d match-lands on %d, want %d\\n",\n                    i, landing_match, ret_idx);\n            abort();\n        }\n        if (i == nrs_count - 1) {\n            int landing_nomatch = idx + 1 + prog[idx].jf;\n            if (landing_nomatch != after_idx) {\n                fprintf(stderr, "lure-wrapper: internal error: last chain entry no-match lands on %d, want %d\\n",\n                        landing_nomatch, after_idx);\n                abort();\n            }\n        }\n    }\n}\n\n/* Returns 0 on success, -1 on failure (errno set). */\nstatic int install_seccomp_filter(void) {\n    /* Layout:\n     *   0: LD_ABS arch\n     *   1: JEQ AUDIT_ARCH_X86_64 -> continue(1) : KILL_PROCESS(0)\n     *   2: RET KILL_PROCESS          (wrong architecture entirely)\n     *   3: LD_ABS nr\n     *   deny chain (N_DENY entries + spacer + RET TRAP)\n     *   socket nr check -> either the 2-instruction family sub-check,\n     *                      or fall through to the plain allow chain\n     *   allow chain (N_ALLOW entries + spacer + RET ALLOW)\n     *   DEFAULT:           RET ERRNO(EPERM)\n     */\n    struct sock_filter prog[32 + N_DENY + N_ALLOW];\n    int pc = 0;\n\n    prog[pc++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET);\n    prog[pc++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);\n    prog[pc++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);\n    prog[pc++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET);\n\n    append_chain(prog, &pc, DENY_NRS, N_DENY, SECCOMP_RET_TRAP);\n\n    /* socket() family gate: nr still holds the value from the LD_ABS\n     * above (BPF has a single accumulator; the deny chain only ever\n     * COMPARES nr, never reloads it). On nr==socket, check args[0];\n     * on nr!=socket, skip straight to the plain allow chain. */\n    prog[pc++] = (struct sock_filter)\n        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_SOCKET_NR, 0, 2);\n    prog[pc++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARGS0_OFFSET);\n\n    int allow_ret_idx = pc + 1 + N_ALLOW + 1;  /* +1 for the AF-check instruction itself */\n    int allow_default_idx = allow_ret_idx + 1;\n\n    /* Computed on separate lines, BEFORE the prog[pc++] statement below:\n     * reading `pc` inside the same expression that also modifies it via\n     * `pc++` is unsequenced behavior in C, and was silently miscomputing\n     * these two values by exactly 1 during development (caught via a\n     * live kernel install test where AF_INET sockets were incorrectly\n     * allowed through). Never inline a jump-distance expression that\n     * reads `pc` directly into a `prog[pc++] = ...` statement. */\n    int af_jt = allow_ret_idx - pc - 1;\n    int af_jf = allow_default_idx - pc - 1;\n    prog[pc++] = (struct sock_filter)\n        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX_VAL, af_jt, af_jf);\n\n    append_chain(prog, &pc, ALLOW_NRS, N_ALLOW, SECCOMP_RET_ALLOW);\n\n    prog[pc++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);\n\n    /* Verify the AF-check\'s computed targets actually matched reality\n     * (defensive: if append_chain\'s layout ever changes, this catches\n     * a stale offset computation immediately instead of installing a\n     * silently-wrong filter). */\n    if (pc - 1 != allow_default_idx) {\n        fprintf(stderr, "lure-wrapper: internal error: default EPERM at %d, expected %d\\n",\n                pc - 1, allow_default_idx);\n        abort();\n    }\n\n    struct sock_fprog fprog = { (unsigned short)pc, prog };\n\n    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {\n        return -1;\n    }\n    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0) != 0) {\n        return -1;\n    }\n    return 0;\n}\n\nint main(int argc, char **argv) {\n    if (argc < 3) {\n        fprintf(stderr, "lure-wrapper: usage: lure-wrapper <guest_path> <marker_fd> [args...]\\n");\n        return 126;\n    }\n\n    const char *guest_path = argv[1];\n    int marker_fd = atoi(argv[2]);\n\n    if (install_seccomp_filter() != 0) {\n        /* Best-effort: tell the parent seccomp didn\'t take, then\n         * proceed WITHOUT it rather than aborting the run. */\n        if (marker_fd >= 0) {\n            ssize_t written = write(marker_fd, "1", 1);\n            (void)written;  /* nothing more we can do if this fails */\n            close(marker_fd);\n        }\n        fprintf(stderr, "lure-wrapper: seccomp install failed (errno=%d), running without it\\n", errno);\n    } else {\n        if (marker_fd >= 0) {\n            close(marker_fd);  /* leave marker empty: filter succeeded */\n        }\n    }\n\n    /* argv[3..] (if any) become the guest\'s own argv[1..]; the guest\'s\n     * argv[0] is set to guest_path itself. */\n    int guest_argc = argc - 3;\n    char **guest_argv = malloc((size_t)(guest_argc + 2) * sizeof(char *));\n    if (!guest_argv) {\n        fprintf(stderr, "lure-wrapper: out of memory\\n");\n        return 126;\n    }\n    guest_argv[0] = (char *)guest_path;\n    for (int i = 0; i < guest_argc; i++) {\n        guest_argv[1 + i] = argv[3 + i];\n    }\n    guest_argv[1 + guest_argc] = NULL;\n\n    execv(guest_path, guest_argv);\n\n    /* execv only returns on failure */\n    fprintf(stderr, "lure-wrapper: execv(%s) failed: %s\\n", guest_path, strerror(errno));\n    return 127;\n}\n'

_ROOT_INIT_SRC = '''\
import os
import shutil
import stat
import subprocess
import sys

BIND_DIRS_BASE = ('usr', 'lib', 'lib64', 'bin')
ETC_FILES      = ('ld.so.cache', 'ld.so.conf', 'nsswitch.conf')
SKELETON_DIRS  = ('bin', 'lib', 'lib64', 'usr', 'sbin', 'tmp', 'proc', 'dev', 'etc')

# (name, mode, major, minor) -- standard character-device numbers,
# the same across all Linux distributions.
DEV_NODES = (
    ('null',    0o666, 1, 3),
    ('zero',    0o666, 1, 5),
    ('urandom', 0o666, 1, 9),
    ('tty',     0o666, 5, 0),
)

WRAPPER_C_SRC = ''' + repr(WRAPPER_C_SRC) + '''


def fail(msg):
    sys.stderr.write(f'lure_root_init: {msg}\\n')
    sys.exit(97)


def main():
    if len(sys.argv) < 7 or sys.argv[6] != '--':
        fail('internal error: bad argv from lure')

    root_dir, trace_path, marker_path, no_seccomp_marker_path, binary_path = sys.argv[1:6]
    extra_argv = sys.argv[7:]

    wrapper_ready = False
    wrapper_bin_path = '/tmp/lure-wrapper'

    try:
        for d in SKELETON_DIRS:
            os.makedirs(os.path.join(root_dir, d), exist_ok=True)

        # Pre-open all three files BEFORE chroot, while host paths
        # still resolve normally. trace_fd and no_seccomp_fd must
        # survive the exec chain below, so they are explicitly marked
        # inheritable. marker_fd does not need to survive exec — it is
        # written and closed entirely within this script.
        trace_fd = os.open(trace_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        os.set_inheritable(trace_fd, True)
        marker_fd = os.open(marker_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        no_seccomp_fd = os.open(no_seccomp_marker_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        os.set_inheritable(no_seccomp_fd, True)

        # Essential device nodes. Best-effort: some environments deny
        # mknod even inside a fresh user+mount namespace -- silently
        # skip and the guest just won't have that node.
        for name, mode, major, minor in DEV_NODES:
            try:
                os.mknod(
                    os.path.join(root_dir, 'dev', name),
                    mode | stat.S_IFCHR,
                    os.makedev(major, minor),
                )
            except OSError:
                pass

        # tmpfs on /tmp so a guest can't fill the host disk under the
        # temp root, and so there is somewhere writable to compile
        # guest_wrapper into after chroot (the rest of the root is
        # read-only). Non-fatal: /tmp stays a plain (unbounded)
        # directory if this mount fails for any reason.
        subprocess.run(
            ['mount', '-t', 'tmpfs', '-o', 'size=64m,mode=1777', 'tmpfs',
             os.path.join(root_dir, 'tmp')],
            check=False,
        )

        bind_dirs = list(BIND_DIRS_BASE)
        if os.path.isdir('/sbin'):
            bind_dirs.append('sbin')

        for d in bind_dirs:
            host_path  = '/' + d
            guest_path = os.path.join(root_dir, d)
            if not os.path.isdir(host_path):
                continue
            subprocess.run(['mount', '--bind', host_path, guest_path], check=True)
            subprocess.run(['mount', '-o', 'remount,ro,bind', guest_path], check=True)

        subprocess.run(
            ['mount', '-t', 'proc', 'proc', os.path.join(root_dir, 'proc')],
            check=True,
        )

        etc_dir = os.path.join(root_dir, 'etc')
        for fname in ETC_FILES:
            src = '/etc/' + fname
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(etc_dir, fname))

        guest_name         = os.path.basename(binary_path)
        guest_path_in_root = os.path.join(root_dir, guest_name)
        shutil.copy2(binary_path, guest_path_in_root)
        os.chmod(guest_path_in_root, 0o755)

        # Write the guest_wrapper C source into the (still-writable,
        # pre-chroot) tmpfs /tmp, ready to compile once inside the
        # chroot below.
        wrapper_src_path = os.path.join(root_dir, 'tmp', 'lure-wrapper.c')
        with open(wrapper_src_path, 'w') as f:
            f.write(WRAPPER_C_SRC)

        os.chdir(root_dir)
        os.chroot(root_dir)
        os.chdir('/')

        # Compile guest_wrapper INSIDE the chroot -- gcc/cc, headers,
        # and the C library it needs are all reachable via the
        # read-only /usr bind mount; the compiler writes its output to
        # /tmp (tmpfs, writable). If this fails for any reason (no
        # compiler available, compile error), that is NOT treated as a
        # setup failure -- mount namespace + chroot still succeeded,
        # so lure proceeds tracing the guest directly, just without
        # seccomp, exactly like the mount-namespace-unavailable
        # fallback already does one level up.
        compiler = None
        for candidate in ('cc', 'gcc'):
            if shutil.which(candidate):
                compiler = candidate
                break

        if compiler:
            compile_result = subprocess.run(
                [compiler, '-O2', '-o', wrapper_bin_path, '/tmp/lure-wrapper.c'],
                capture_output=True, text=True,
            )
            wrapper_ready = (compile_result.returncode == 0
                              and os.path.exists(wrapper_bin_path))
            if not wrapper_ready:
                sys.stderr.write(
                    'lure_root_init: guest_wrapper compile failed, '
                    'running guest without seccomp: '
                    + compile_result.stderr[-500:] + '\\n'
                )
        else:
            sys.stderr.write(
                'lure_root_init: no C compiler available in sandbox, '
                'running guest without seccomp\\n'
            )

    except Exception as exc:
        fail(f'setup failed: {exc}')

    # Mount namespace + chroot setup is fully complete. Mark success
    # now, before touching the guest binary or guest_wrapper at all.
    os.write(marker_fd, b'1')
    os.close(marker_fd)

    if not wrapper_ready:
        # No usable guest_wrapper (compiler missing or compile
        # failed): tell the parent seccomp will not be active, then
        # trace the guest binary directly -- same behavior as before
        # Task 13, just reported accurately in the isolation label.
        try:
            os.write(no_seccomp_fd, b'1')
        except OSError:
            pass
        os.close(no_seccomp_fd)

        strace_cmd = [
            'strace', '-f', '-tt', '-T', '-e', 'trace=all',
            '-o', f'/proc/self/fd/{trace_fd}',
            '--', f'/{guest_name}',
        ] + extra_argv
    else:
        # no_seccomp_fd is inherited by guest_wrapper itself, which is
        # responsible for writing to it if IT fails to install the
        # filter (e.g. a kernel that rejects PR_SET_SECCOMP even
        # though mount namespaces and compilation both worked) --
        # guest_wrapper still execs the guest either way, just
        # unfiltered in that case. strace traces guest_wrapper, not
        # the guest directly, so strace's own ptrace-based tracing is
        # never subject to the filter guest_wrapper installs on itself
        # immediately before its own exec into the guest.
        strace_cmd = [
            'strace', '-f', '-tt', '-T', '-e', 'trace=all',
            '-o', f'/proc/self/fd/{trace_fd}',
            '--', wrapper_bin_path, f'/{guest_name}', str(no_seccomp_fd),
        ] + extra_argv

    try:
        os.execvp('strace', strace_cmd)
    except OSError as exc:
        sys.stderr.write(f'lure_root_init: exec strace failed: {exc}\\n')
        sys.exit(98)


if __name__ == '__main__':
    main()
'''


def _write_root_init_script():
    """Write the embedded init script to a temp file and return its path."""
    fd, path = tempfile.mkstemp(prefix='lure_root_init_', suffix='.py')
    with os.fdopen(fd, 'w') as f:
        f.write(_ROOT_INIT_SRC)
    return path


def _marker_succeeded(marker_path):
    """True if the init script reached the marker-write step (setup OK)."""
    try:
        with open(marker_path, 'rb') as f:
            return f.read(1) == b'1'
    except OSError:
        return False


# ── Sensitivity classification ─────────────────────────────────────────────────
#
# Four tiers, checked in this order:
#
#   1. _NEVER_SENSITIVE_*  — hard overrides. Normal dynamic-linker,
#      locale, and SELinux bookkeeping that happens on EVERY single
#      program launch. These must NEVER be flagged, no matter what.
#
#   2. _SENSITIVE_WRITE_ONLY_* — flagged ONLY when the access is a
#      write/modify:
#        - /etc/ld.so.preload is READ (and usually ENOENT) by the
#          dynamic linker on every launch — totally normal. A WRITE
#          to it is a classic LD_PRELOAD persistence technique.
#        - /home/ is read constantly by normal tools (dotfiles,
#          configs). A WRITE under /home/ is more meaningful.
#
#   3. _SENSITIVE_READ_LIGHT_* — NOT flagged on its own. Reading
#      /etc/passwd is completely normal (glibc, `ls -l`, every shell
#      prompt does it). It only becomes a "confirmed sensitive"
#      access if the same run also attempted a network connection —
#      i.e. read-credentials-then-phone-home. See the second pass in
#      _parse_full_trace() that upgrades these once network activity
#      is known.
#
#   4. _SENSITIVE_EXACT / _SENSITIVE_PREFIX — always sensitive,
#      regardless of read or write.
#

_SENSITIVE_EXACT = frozenset({
    '/etc/shadow',
    '/etc/sudoers',
    '/etc/crontab',
})

_SENSITIVE_PREFIX = (
    '/root/',
    '/.ssh/',
    '/etc/cron.d/',
    '/proc/net/',
)

_SENSITIVE_WRITE_ONLY_EXACT = frozenset({
    '/etc/ld.so.preload',
})

_SENSITIVE_WRITE_ONLY_PREFIX = (
    '/home/',
)

# Flagged only in combination with outbound network activity elsewhere
# in the same run — never on their own. See _parse_full_trace().
_SENSITIVE_READ_LIGHT_EXACT = frozenset({
    '/etc/passwd',
})

# Hard "never flag" overrides — accessed by virtually every binary on
# every launch as part of normal dynamic linking / locale / SELinux
# startup checks. NOTE: /etc/ld.so.preload is deliberately NOT listed
# here — it lives only in _SENSITIVE_WRITE_ONLY_EXACT above, so a read
# (the normal case) is never flagged but a write still is.
_NEVER_SENSITIVE_EXACT = frozenset({
    '/etc/ld.so.cache',
    '/etc/selinux/config',
})

_NEVER_SENSITIVE_PREFIX = (
    '/usr/lib/',
    '/usr/lib64/',
    '/usr/share/locale/',
    '/usr/lib/locale/',
)

# Path prefixes suppressed from display entirely (high-volume kernel
# noise), UNLESS the path also matches a sensitivity rule above.
_SKIP_PREFIX = ('/proc/', '/sys/', '/dev/')


# ── Syscall tables ────────────────────────────────────────────────────────────

# Syscalls that reference a filesystem path as their first argument
_FILE_SYSCALLS = frozenset({
    'open', 'openat', 'openat2', 'creat',
    'access', 'faccessat', 'faccessat2',
    'stat', 'lstat', 'newfstatat', 'statx',
    'unlink', 'unlinkat',
    'rename', 'renameat', 'renameat2',
    'readlink', 'readlinkat',
    'chmod', 'fchmodat',
    'chown', 'fchownat',
})

# open()/openat()/openat2() flags that indicate a write/modify intent
_WRITE_FLAGS = ('O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_TRUNC', 'O_APPEND')
_OPEN_SYSCALLS = frozenset({'open', 'openat', 'openat2'})

# Syscalls that are ALWAYS a write/modify regardless of flags
_ALWAYS_WRITE_SYSCALLS = frozenset({
    'creat',
    'unlink', 'unlinkat',
    'rename', 'renameat', 'renameat2',
    'chmod', 'fchmodat',
    'chown', 'fchownat',
})

_MAX_FILE_ROWS = 40
_MAX_PROC_ROWS = 20
_MAX_OUTPUT_LINES  = 100
_OUTPUT_HEAD_LINES = 25
_OUTPUT_TAIL_LINES = 10

_REPORTS_DIR = os.path.expanduser('~/.lure/reports')


def _read_program_output(path):
    """
    Read the binary's captured stdout+stderr (merged, in real
    chronological order) from `path`.

    Returns a list of display lines, already truncated to at most
    _MAX_OUTPUT_LINES (first 25 / last 10 + an omitted-count marker
    if the output is longer), or None if there was no output at all.
    """
    try:
        with open(path, 'r', errors='replace') as f:
            text = f.read()
    except OSError:
        text = ''

    if not text.strip():
        return None

    lines = text.splitlines()
    if len(lines) <= _MAX_OUTPUT_LINES:
        return lines

    omitted = len(lines) - (_OUTPUT_HEAD_LINES + _OUTPUT_TAIL_LINES)
    return (
        lines[:_OUTPUT_HEAD_LINES]
        + [f'[... {omitted} lines omitted ...]']
        + lines[-_OUTPUT_TAIL_LINES:]
    )


# ── Path / access helpers ─────────────────────────────────────────────────────

def _signal_name(exit_code):
    """
    subprocess reports a process killed by a signal as a negative
    returncode (-11 for SIGSEGV, etc). Returns "SIGSEGV (11)" style
    text, or None if exit_code doesn't represent a signal kill.
    """
    if exit_code is None or exit_code >= 0:
        return None
    sig_num = -exit_code
    try:
        name = signal.Signals(sig_num).name
    except ValueError:
        name = f'signal {sig_num}'
    return f'{name} ({sig_num})'


def _is_write_access(syscall, raw):
    """True if this file syscall represents a write/modify operation."""
    if syscall in _ALWAYS_WRITE_SYSCALLS:
        return True
    if syscall in _OPEN_SYSCALLS:
        return any(flag in raw for flag in _WRITE_FLAGS)
    return False


def _could_be_sensitive(path):
    """
    True if `path` matches ANY sensitivity rule, ignoring write-status
    and the read-light network condition. Used so genuinely sensitive
    paths under /proc/ (e.g. /proc/net/) are never discarded by the
    generic noise filter.
    """
    if path in _NEVER_SENSITIVE_EXACT:
        return False
    if any(path.startswith(p) for p in _NEVER_SENSITIVE_PREFIX):
        return False
    if path in _SENSITIVE_EXACT or path in _SENSITIVE_WRITE_ONLY_EXACT:
        return True
    if path in _SENSITIVE_READ_LIGHT_EXACT:
        return True
    if any(path.startswith(p) for p in _SENSITIVE_PREFIX):
        return True
    return any(path.startswith(p) for p in _SENSITIVE_WRITE_ONLY_PREFIX)


def _is_read_light(path):
    """True if `path` is only conditionally sensitive (see tier 3 above)."""
    return path in _SENSITIVE_READ_LIGHT_EXACT


def _is_sensitive(path, is_write):
    """
    Provisional per-event SENSITIVE classification for one file-access
    event. Read-light paths (e.g. /etc/passwd) always come back False
    here — they're upgraded later in _parse_full_trace() only if the
    run also attempted a network connection.
    """
    # Hard overrides always win, regardless of read/write.
    if path in _NEVER_SENSITIVE_EXACT:
        return False
    if any(path.startswith(p) for p in _NEVER_SENSITIVE_PREFIX):
        return False

    # Write-gated: sensitive ONLY when actually written to.
    if path in _SENSITIVE_WRITE_ONLY_EXACT:
        return is_write
    if any(path.startswith(p) for p in _SENSITIVE_WRITE_ONLY_PREFIX):
        return is_write

    # Read-light: never sensitive on its own.
    if path in _SENSITIVE_READ_LIGHT_EXACT:
        return False

    # Always-sensitive.
    if path in _SENSITIVE_EXACT:
        return True
    return any(path.startswith(p) for p in _SENSITIVE_PREFIX)


def _is_noisy(path):
    """True for high-volume, low-signal kernel virtual paths."""
    return (
        any(path.startswith(p) for p in _SKIP_PREFIX)
        and not _could_be_sensitive(path)
    )


# ── strace line parser ────────────────────────────────────────────────────────

def _parse_line(raw):
    """
    Minimal strace output parser.
    Returns {'syscall', 'retval', 'raw'} or None.
    Handles the format:  [pid] [hh:mm:ss.usec] syscall(args) = retval [<sec>]
    """
    line = raw.strip()
    if not line:
        return None
    if ('<unfinished' in line or 'resumed>' in line
            or line.startswith('---') or line.startswith('+++')):
        return None

    # Strip optional leading PID
    line = re.sub(r'^\d+\s+', '', line)
    # Strip optional timestamp
    line = re.sub(r'^\d+:\d+:\d+\.\d+\s+', '', line)

    m = re.match(r'^([a-zA-Z_]\w*)\s*\(', line)
    if not m:
        return None
    syscall = m.group(1)

    rv = re.search(r'\)\s*=\s*(-?\d+|0x[0-9a-f]+|\?)', line)
    retval = rv.group(1) if rv else None

    return {'syscall': syscall, 'retval': retval, 'raw': line}


def _format_addr(ip, port, family):
    """IPv6 addresses get bracketed (RFC 3986 style) to disambiguate
    the address's own colons from the ip:port separator."""
    if family == 'IPv6':
        return f'[{ip}]:{port}'
    return f'{ip}:{port}'


def _classify(parsed):
    """
    Turn a parsed strace dict into a typed event, or None.
    Event types: 'file' | 'exec' | 'network'
    """
    sc  = parsed['syscall']
    raw = parsed['raw']
    rv  = parsed['retval']

    # ── File events ───────────────────────────────────────────────────────────
    if sc in _FILE_SYSCALLS:
        m = re.search(r'"(/[^"]*)"', raw)
        if m:
            path = m.group(1)
            if _is_noisy(path):
                return None
            is_write = _is_write_access(sc, raw)
            return {
                'type':       'file',
                'path':       path,
                'sensitive':  _is_sensitive(path, is_write),
                'read_light': _is_read_light(path),
                'write':      is_write,
                'retval':     rv,
            }

    # ── Exec events ───────────────────────────────────────────────────────────
    elif sc == 'execve':
        m = re.search(r'"([^"]+)"', raw)
        if not m:
            return None
        path = m.group(1)
        argv_m = re.search(r'\[("[^"]*"(?:,\s*"[^"]*")*)', raw)
        if argv_m:
            parts   = re.findall(r'"([^"]*)"', argv_m.group(1))
            display = path + (' ' + ' '.join(parts[1:4]) if len(parts) > 1 else '')
        else:
            display = path
        return {'type': 'exec', 'path': path, 'cmd': display, 'retval': rv}

    # ── Network events ────────────────────────────────────────────────────────
    elif sc == 'connect':
        if 'AF_INET6' in raw:
            ip_m   = re.search(r'inet_pton\(AF_INET6,\s*"([^"]+)"', raw)
            port_m = re.search(r'sin6_port=htons\((\d+)\)', raw)
            family = 'IPv6'
        elif 'AF_INET' in raw:
            ip_m   = re.search(r'inet_addr\("([^"]+)"\)', raw)
            port_m = re.search(r'sin_port=htons\((\d+)\)', raw)
            family = 'IPv4'
        else:
            return None

        if not (ip_m and port_m):
            return None
        blocked = rv not in (None, '0')
        return {
            'type':    'network',
            'ip':      ip_m.group(1),
            'port':    int(port_m.group(1)),
            'family':  family,
            'blocked': blocked,
            'retval':  rv,
        }

    return None


# ── Live feed thread ──────────────────────────────────────────────────────────

def _live_tail(trace_path, start_time, stop_evt):
    """
    Tail the strace output file line-by-line while the binary runs.
    Print interesting events to the terminal immediately.
    Runs in its own daemon thread.
    """
    seen_files   = set()
    seen_network = set()
    seen_exec    = set()

    deadline = time.time() + 5
    while not os.path.exists(trace_path):
        if time.time() > deadline or stop_evt.is_set():
            return
        time.sleep(0.02)

    try:
        with open(trace_path, 'r', errors='replace') as fh:
            while not stop_evt.is_set():
                raw = fh.readline()
                if not raw:
                    time.sleep(0.02)
                    continue

                parsed = _parse_line(raw)
                if not parsed:
                    continue
                evt = _classify(parsed)
                if not evt:
                    continue

                elapsed = time.time() - start_time
                ts      = f'[dim]{elapsed:.3f}s[/dim]'

                if evt['type'] == 'file':
                    path = evt['path']
                    if path in seen_files:
                        continue
                    seen_files.add(path)
                    if evt['sensitive']:
                        console.print(
                            f'  [bold red]⚠ [/bold red] [{ts}] '
                            f'[bold red]SENSITIVE[/bold red]  '
                            f'[red]{path}[/red]'
                        )
                    else:
                        console.print(
                            f'  📂 [{ts}] [dim]OPEN   [/dim] {path}'
                        )

                elif evt['type'] == 'exec':
                    cmd = evt['cmd']
                    if cmd in seen_exec:
                        continue
                    seen_exec.add(cmd)
                    console.print(
                        f'  🔀 [{ts}] [yellow]SPAWN  [/yellow] '
                        f'[yellow]{cmd}[/yellow]'
                    )

                elif evt['type'] == 'network':
                    key = (evt['ip'], evt['port'], evt['family'])
                    if key in seen_network:
                        continue
                    seen_network.add(key)
                    blk = ' [red](BLOCKED)[/red]' if evt['blocked'] else ''
                    addr = _format_addr(evt['ip'], evt['port'], evt['family'])
                    console.print(
                        f'  🌐 [{ts}] [cyan]CONNECT[/cyan] '
                        f'[cyan]{addr}[/cyan]{blk}'
                    )

    except (FileNotFoundError, OSError):
        pass


# ── Full trace parser ─────────────────────────────────────────────────────────

def _parse_full_trace(trace_path):
    """
    Parse the complete strace log after the binary exits.
    Returns dict with 'files', 'network', 'processes', 'syscalls'.

    A given path may be accessed multiple times with different
    read/write modes (e.g. /etc/ld.so.preload checked read-only at
    startup, then opened for writing by malware). The final
    'sensitive' flag for that path is the OR across every occurrence
    — if ANY access to it was sensitive, the path is reported as
    sensitive.
    """
    files     = []
    network   = []
    processes = []
    syscalls  = {}

    file_index   = {}
    seen_network = set()
    seen_exec    = set()

    try:
        with open(trace_path, 'r', errors='replace') as fh:
            for raw in fh:
                parsed = _parse_line(raw)
                if not parsed:
                    continue

                sc = parsed['syscall']
                syscalls[sc] = syscalls.get(sc, 0) + 1

                evt = _classify(parsed)
                if not evt:
                    continue

                if evt['type'] == 'file':
                    p = evt['path']
                    if p not in file_index:
                        file_index[p] = len(files)
                        files.append({
                            'path':       p,
                            'sensitive':  evt['sensitive'],
                            'write':      evt['write'],
                            'read_light': evt['read_light'],
                        })
                    else:
                        entry = files[file_index[p]]
                        if evt['sensitive']:
                            entry['sensitive'] = True
                        if evt['write']:
                            entry['write'] = True
                        if evt['read_light']:
                            entry['read_light'] = True

                elif evt['type'] == 'exec':
                    cmd = evt['cmd']
                    if cmd not in seen_exec:
                        seen_exec.add(cmd)
                        processes.append({'cmd': cmd})

                elif evt['type'] == 'network':
                    key = (evt['ip'], evt['port'], evt['family'])
                    if key not in seen_network:
                        seen_network.add(key)
                        network.append({
                            'ip':      evt['ip'],
                            'port':    evt['port'],
                            'family':  evt['family'],
                            'blocked': evt['blocked'],
                        })

    except (FileNotFoundError, OSError):
        pass

    # Read-light paths (e.g. /etc/passwd) are only "confirmed sensitive"
    # if this run also attempted an outbound network connection —
    # otherwise a read of them alone is normal and stays unflagged.
    if network:
        for f in files:
            if f['read_light']:
                f['sensitive'] = True

    return {
        'files':     files,
        'network':   network,
        'processes': processes,
        'syscalls':  syscalls,
    }


# ── Verdict logic ─────────────────────────────────────────────────────────────

def _verdict(events):
    """
    Compute the final verdict.
    Returns (label, triggers) where label is CLEAN | SUSPICIOUS | DANGEROUS
    and triggers is a list of exact "<what> (<why>)" strings that caused it
    (empty for CLEAN).

    DANGEROUS  = /etc/shadow accessed (any)
               OR /.ssh/ accessed (any)
               OR (confirmed-sensitive WRITE + network)
    SUSPICIOUS = confirmed-sensitive file access
               OR outbound network connection attempt
    CLEAN      = neither

    "Confirmed-sensitive" here means events['files'] entries with
    sensitive=True — which already excludes plain reads of read-light
    paths (e.g. /etc/passwd) unless this run also had network activity
    (see the upgrade pass in _parse_full_trace()).
    """
    sensitive_entries = [e for e in events['files'] if e['sensitive']]
    sensitive_paths   = [e['path'] for e in sensitive_entries]
    networks          = events['network']

    has_shadow          = any('/etc/shadow' in p for p in sensitive_paths)
    has_ssh             = any('/.ssh/'      in p for p in sensitive_paths)
    has_sensitive       = bool(sensitive_paths)
    has_network         = bool(networks)
    has_sensitive_write = any(e['write'] for e in sensitive_entries)

    triggers  = [f'{p} (sensitive file access)' for p in sensitive_paths]
    triggers += [
        f'{_format_addr(n["ip"], n["port"], n["family"])} (network connection)'
        for n in networks
    ]

    if has_shadow or has_ssh or (has_sensitive_write and has_network):
        return 'DANGEROUS', triggers
    if has_sensitive or has_network:
        return 'SUSPICIOUS', triggers
    return 'CLEAN', []


# ── Report renderer ───────────────────────────────────────────────────────────

def _render_report(binary_path, exit_code, elapsed, timed_out, events, program_output, isolation):
    """Print all report sections after the binary exits."""

    total_sc = sum(events['syscalls'].values())

    # ── 1. Execution Summary ──────────────────────────────────────────────────
    sig_info = _signal_name(exit_code)

    if timed_out:
        exit_display = Text.assemble(('TIMEOUT', 'bold yellow'), ('  (process killed)', 'dim'))
    elif sig_info:
        exit_display = Text.assemble((f'Killed by signal: {sig_info}', 'bold red'))
    elif exit_code == 0:
        exit_display = Text.assemble(('0', 'bold green'), ('  (success)', 'dim'))
    else:
        exit_display = Text.assemble((str(exit_code), 'bold red'), ('  (error)', 'dim'))

    t = Table(box=None, show_header=False, show_edge=False, padding=(0, 1))
    t.add_column(style='dim', no_wrap=True, min_width=12)
    t.add_column()
    t.add_row('Binary',     Path(binary_path).name)
    t.add_row('Full Path',  binary_path)
    t.add_row('Exit Code',  exit_display)
    t.add_row('Runtime',    f'{elapsed:.3f}s')
    t.add_row('Isolation',  isolation)
    t.add_row('Syscalls',   Text.assemble(
        (f'{total_sc:,}', 'bold white'), (' captured', 'dim')
    ))
    console.print(Panel(
        t,
        title='[bold]Execution Summary[/bold]',
        border_style='dim white',
        box=box.ROUNDED,
        padding=(0, 1),
    ))

    # ── 2. Program Output ─────────────────────────────────────────────────────
    output_lines = _read_program_output(program_output) if program_output else None

    if output_lines is None:
        output_body = Text('  (no output)', style='dim italic')
    else:
        ot = Table(box=None, show_header=False, show_edge=False, padding=(0, 0))
        ot.add_column()
        for line in output_lines:
            ot.add_row(Text(f'  {line}', style='white'))
        output_body = ot

    console.print(Panel(
        output_body,
        title='[bold]Program Output[/bold]',
        border_style='dim white',
        box=box.ROUNDED,
        padding=(0, 1),
    ))

    # ── 3. Files Accessed ─────────────────────────────────────────────────────
    files           = events['files']
    sensitive_count = sum(1 for e in files if e['sensitive'])

    if not files:
        file_body = Text('  (no file events captured)', style='dim italic')
    else:
        ft = Table(box=None, show_header=False, show_edge=False, padding=(0, 0))
        ft.add_column()
        for entry in files[:_MAX_FILE_ROWS]:
            if entry['sensitive']:
                ft.add_row(Text.assemble(
                    ('  ⚠  ', 'bold red'),
                    (entry['path'], 'bold red'),
                    ('  ← SENSITIVE', 'dim red'),
                ))
            else:
                ft.add_row(Text(f'  {entry["path"]}', style='white'))
        if len(files) > _MAX_FILE_ROWS:
            ft.add_row(Text(
                f'  … and {len(files) - _MAX_FILE_ROWS} more', style='dim'
            ))
        file_body = ft

    s_badge = (
        f'  [bold red]{sensitive_count} sensitive[/bold red]'
        if sensitive_count else ''
    )
    console.print(Panel(
        file_body,
        title=f'[bold]Files Accessed[/bold] ([bold]{len(files)}[/bold]){s_badge}',
        border_style='dim white',
        box=box.ROUNDED,
        padding=(0, 1),
    ))

    # ── 4. Network Activity ───────────────────────────────────────────────────
    network = events['network']
    if not network:
        net_body = Text('  (no network connections attempted)', style='dim italic')
    else:
        nt = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style='bold dim',
            padding=(0, 2),
            expand=True,
        )
        nt.add_column('Destination', style='cyan',  no_wrap=True)
        nt.add_column('Port',        no_wrap=True,  min_width=6,  justify='right')
        nt.add_column('Family',      no_wrap=True,  min_width=6)
        nt.add_column('Status',      no_wrap=True,  min_width=12)
        for conn in network:
            status = (
                Text('BLOCKED',   style='bold red')
                if conn['blocked']
                else Text('CONNECTED', style='bold green')
            )
            nt.add_row(conn['ip'], str(conn['port']), conn['family'], status)
        net_body = nt

    console.print(Panel(
        net_body,
        title=f'[bold]Network Activity[/bold] ([bold]{len(network)}[/bold])',
        border_style='dim white',
        box=box.ROUNDED,
        padding=(0, 1),
    ))

    # ── 5. Processes Spawned ──────────────────────────────────────────────────
    procs = events['processes']
    if not procs:
        proc_body = Text('  (no child processes spawned)', style='dim italic')
    else:
        pt = Table(box=None, show_header=False, show_edge=False, padding=(0, 0))
        pt.add_column()
        for proc in procs[:_MAX_PROC_ROWS]:
            pt.add_row(Text(f'  {proc["cmd"]}', style='yellow'))
        proc_body = pt

    console.print(Panel(
        proc_body,
        title=f'[bold]Processes Spawned[/bold] ([bold]{len(procs)}[/bold])',
        border_style='dim white',
        box=box.ROUNDED,
        padding=(0, 1),
    ))

    # ── 6. Syscall Summary ────────────────────────────────────────────────────
    top5    = sorted(events['syscalls'].items(), key=lambda x: x[1], reverse=True)[:5]
    max_cnt = top5[0][1] if top5 else 1

    sc_t = Table(box=None, show_header=False, show_edge=False, padding=(0, 1))
    sc_t.add_column(style='dim', no_wrap=True, min_width=4)
    sc_t.add_column()
    sc_t.add_row('', Text.assemble(
        ('Total  ', 'dim'),
        (f'{total_sc:,}', 'bold white'),
        (' calls', 'dim'),
    ))
    sc_t.add_row('', '')
    for name, cnt in top5:
        bar  = '█' * int((cnt / max_cnt) * 24)
        pct  = cnt / total_sc * 100 if total_sc else 0
        sc_t.add_row(
            f'  {name}',
            Text.assemble(
                (f'{bar:<24}', 'cyan'),
                (f'  {cnt:,}', 'bold white'),
                (f'  ({pct:.1f}%)', 'dim'),
            ),
        )

    console.print(Panel(
        sc_t,
        title='[bold]Syscall Summary[/bold]',
        border_style='dim white',
        box=box.ROUNDED,
        padding=(0, 1),
    ))

    # ── 7. Verdict ────────────────────────────────────────────────────────────
    label, triggers = _verdict(events)

    if label == 'CLEAN':
        icon, v_style, border = '✔', 'bold green',  'green'
    elif label == 'SUSPICIOUS':
        icon, v_style, border = '⚠', 'bold yellow', 'yellow'
    else:
        icon, v_style, border = '✘', 'bold red',    'red'

    verdict_parts = [
        ('\n', ''),
        (f'        {icon}   {label}\n\n', v_style),
    ]
    if label == 'CLEAN':
        verdict_parts.append(
            ('        No sensitive file access. No network activity detected.\n', 'white')
        )
    else:
        verdict_parts.append(('        Triggered by:\n', 'white'))
        for trig in triggers:
            verdict_parts.append((f'          • {trig}\n', 'white'))
    verdict_parts.append(('\n', ''))

    console.print(Panel(
        Text.assemble(*verdict_parts),
        border_style=border,
        box=box.HEAVY,
        padding=(0, 2),
        expand=True,
    ))
    console.print()

    return label, triggers


# ── Save report ───────────────────────────────────────────────────────────────

def _save_report(binary_path, exit_code, elapsed, timed_out, events, label, triggers, isolation):
    """
    Export everything printed to the console so far as plain text and
    write it to ~/.lure/reports/<binary>_<timestamp>.txt, plus a
    companion ~/.lure/reports/<binary>_<timestamp>.json with the
    structured data from this run.

    Returns (txt_filename, json_filename) on success — json_filename
    is None if only the JSON write failed. Returns None if the
    reports directory or the .txt file itself couldn't be written
    (an error is printed to the console in that case).
    """
    try:
        os.makedirs(_REPORTS_DIR, exist_ok=True)
    except OSError as exc:
        console.print(f'[red]Could not create reports directory:[/red] {exc}')
        return None

    name          = Path(binary_path).name
    timestamp_str = time.strftime('%Y%m%d_%H%M%S')
    base          = f'{name}_{timestamp_str}'
    txt_filename  = f'{base}.txt'
    json_filename = f'{base}.json'
    txt_filepath  = os.path.join(_REPORTS_DIR, txt_filename)
    json_filepath = os.path.join(_REPORTS_DIR, json_filename)

    header = (
        'LURE ANALYSIS REPORT\n'
        f'Binary     : {binary_path}\n'
        f'Generated  : {time.strftime("%Y-%m-%d %H:%M:%S")}\n'
        + ('=' * 70) + '\n\n'
    )

    # export_text() captures everything printed to this console since
    # it was created (or since the last export), stripped of ANSI
    # colour codes — perfect for a plain .txt report.
    body = console.export_text()

    try:
        with open(txt_filepath, 'w') as f:
            f.write(header)
            f.write(body)
    except OSError as exc:
        console.print(f'[red]Could not write report file:[/red] {exc}')
        return None

    report_data = {
        'binary':            name,
        'full_path':         binary_path,
        'timestamp':         datetime.datetime.now().isoformat(),
        'runtime_seconds':   round(elapsed, 3),
        'exit_code':         None if timed_out else exit_code,
        'isolation':         isolation,
        'verdict':           label,
        'verdict_triggers':  triggers,
        'files_accessed':    [e['path'] for e in events['files']],
        'network_attempts':  [
            {'ip': n['ip'], 'port': n['port'], 'family': n['family'], 'blocked': n['blocked']}
            for n in events['network']
        ],
        'processes_spawned': [p['cmd'] for p in events['processes']],
        'syscall_total':     sum(events['syscalls'].values()),
    }

    try:
        with open(json_filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
    except OSError as exc:
        console.print(f'[red]Could not write JSON report file:[/red] {exc}')
        return txt_filename, None

    return txt_filename, json_filename


# ── Orchestrator ──────────────────────────────────────────────────────────────

def _launch_and_wait(cmd, timeout, tmp_output, tmp_trace, start_time):
    """
    Launch `cmd` with stdout+stderr captured to tmp_output, stream the
    live feed from tmp_trace while it runs, and wait up to `timeout`
    seconds. Returns (proc_or_None, exit_code, elapsed, timed_out).
    proc is None if the launch itself failed (e.g. FileNotFoundError);
    in that case exit_code is also None.
    """
    # stdout/stderr are captured to a real file (not subprocess.PIPE) so a
    # chatty binary can never deadlock us by filling an unread pipe buffer.
    # stderr is redirected to the same fd as stdout so the two streams stay
    # in true chronological order, exactly like a shell's `2>&1`.
    try:
        with open(tmp_output, 'wb') as out_f:
            proc = subprocess.Popen(cmd, stdout=out_f, stderr=subprocess.STDOUT)
    except FileNotFoundError as exc:
        console.print(f'[red]Launch failed:[/red] {exc}')
        return None, None, 0.0, False

    stop_evt    = threading.Event()
    feed_thread = threading.Thread(
        target=_live_tail,
        args=(tmp_trace, start_time, stop_evt),
        daemon=True,
    )
    feed_thread.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True

    elapsed = time.time() - start_time

    time.sleep(0.25)
    stop_evt.set()
    feed_thread.join(timeout=3)

    return proc, proc.returncode, elapsed, timed_out


def _execute(binary_path, timeout, binary_args, allow_net, trace_out, tmp_trace, tmp_output, save):
    """Build command(s), run with mount-namespace isolation (falling back
    to user+net only if that's unavailable), stream live feed, render
    report, optionally save."""

    binary_argv = shlex.split(binary_args) if binary_args.strip() else []
    net_badge   = '[red]BLOCKED[/red]' if not allow_net else '[yellow]ALLOWED[/yellow]'

    strace_flags = ['-f', '-tt', '-T', '-e', 'trace=all']

    # "Full" isolation: mount + pid namespace with a minimal chroot,
    # plus network namespace unless the caller passed --allow-net.
    root_dir = os.path.join(tempfile.gettempdir(), f'lure-root-{uuid.uuid4().hex[:12]}')
    try:
        # 0o700: other users on a shared /tmp must not be able to even
        # list, let alone read, the guest's temporary filesystem while
        # a run is in progress.
        os.makedirs(root_dir, mode=0o700, exist_ok=False)
    except OSError as exc:
        console.print(f'[red]Error:[/red] could not create sandbox root: {exc}')
        return

    fd, marker_path = tempfile.mkstemp(prefix='lure_marker_', suffix='.flag')
    os.close(fd)
    fd, no_seccomp_marker_path = tempfile.mkstemp(prefix='lure_noseccomp_', suffix='.flag')
    os.close(fd)
    init_script_path = _write_root_init_script()

    unshare_ns_flags = ['--user'] + ([] if allow_net else ['--net']) + \
                        ['--mount', '--pid', '--fork', '--map-root-user']
    full_cmd = (
        ['unshare'] + unshare_ns_flags + ['--',
         sys.executable, init_script_path,
         root_dir, tmp_trace, marker_path, no_seccomp_marker_path, binary_path, '--']
        + binary_argv
    )
    full_iso_label_seccomp    = (
        'user + mount + pid + seccomp (network allowed)' if allow_net
        else 'user + net + mount + pid + seccomp'
    )
    full_iso_label_no_seccomp = (
        'user + mount + pid (network allowed, no seccomp)' if allow_net
        else 'user + net + mount + pid (no seccomp)'
    )

    # Fallback: the pre-Task-11 behavior — user+net namespace only, no
    # mount/pid namespace, no chroot. Used if mount-namespace setup
    # fails, or straight away if `unshare` isn't installed at all.
    strace_base_fallback = ['strace'] + strace_flags + ['-o', tmp_trace, '--']
    if shutil.which('unshare'):
        if allow_net:
            fallback_cmd   = ['unshare', '--user', '--'] + strace_base_fallback + [binary_path] + binary_argv
            fallback_label = 'user only (mount namespace unavailable, network allowed)'
        else:
            fallback_cmd   = ['unshare', '--user', '--net', '--'] + strace_base_fallback + [binary_path] + binary_argv
            fallback_label = 'user + net (mount namespace unavailable)'
    else:
        fallback_cmd   = strace_base_fallback + [binary_path] + binary_argv
        fallback_label = 'none (--allow-net)' if allow_net else 'none (unshare not found)'

    use_mount_ns = shutil.which('unshare') is not None

    # ── Header ─────────────────────────────────────────────────────────────────
    console.print(Panel.fit(
        f'[bold yellow]RUN[/bold yellow]  [bold white]{binary_path}[/bold white]\n'
        f'  [dim]timeout[/dim] {timeout}s   '
        f'[dim]network[/dim] {net_badge}   '
        f'[dim]trace →[/dim] {trace_out or "tmp"}',
        border_style='yellow',
        box=box.ROUNDED,
    ))

    try:
        if use_mount_ns:
            console.print('  [dim]Isolation  [/dim][dim]setting up mount namespace + sandbox...[/dim]')
            console.print(f'  [dim]Tracer     [/dim][green]strace -f -tt -T[/green]')
            console.print()

            start_time = time.time()
            proc, exit_code, elapsed, timed_out = _launch_and_wait(
                full_cmd, timeout, tmp_output, tmp_trace, start_time
            )

            if proc is not None and _marker_succeeded(marker_path):
                # Mount namespace + chroot succeeded. Whether seccomp
                # itself is active depends on the SEPARATE no-seccomp
                # marker, written by the init script (compiler missing
                # or compile failed) or by guest_wrapper itself
                # (PR_SET_SECCOMP rejected) — either way, an empty
                # marker here means seccomp genuinely installed.
                if _marker_succeeded(no_seccomp_marker_path):
                    iso_label = full_iso_label_no_seccomp
                else:
                    iso_label = full_iso_label_seccomp
                console.print(f'  [dim]Isolation  [/dim][green]{iso_label}[/green]')
                console.print()
            else:
                # Setup failed before the guest binary was ever reached
                # (or the launch itself failed). Pull out any detail the
                # init script printed to stderr — captured in tmp_output,
                # which we must clear before the real attempt so it
                # doesn't get mistaken for the guest's own output.
                detail = ''
                try:
                    with open(tmp_output, 'r', errors='replace') as f:
                        first_line = f.readline().strip()
                    if first_line:
                        detail = f' ({first_line})'
                except OSError:
                    pass

                console.print()
                console.print(
                    '[yellow]Warning: mount namespace unavailable.[/yellow]\n'
                    '[yellow]Running with network isolation only.[/yellow]\n'
                    f'[yellow]Host filesystem is visible to the binary.{detail}[/yellow]'
                )
                console.print()

                open(tmp_output, 'wb').close()
                open(tmp_trace, 'wb').close()

                console.print(f'  [dim]Isolation  [/dim][yellow]{fallback_label}[/yellow]')
                console.print(f'  [dim]Tracer     [/dim][green]strace -f -tt -T[/green]')
                console.print()

                start_time = time.time()
                proc, exit_code, elapsed, timed_out = _launch_and_wait(
                    fallback_cmd, timeout, tmp_output, tmp_trace, start_time
                )
                iso_label = fallback_label

                if proc is None:
                    return
        else:
            console.print(f'  [dim]Isolation  [/dim][yellow]{fallback_label}[/yellow]')
            console.print(f'  [dim]Tracer     [/dim][green]strace -f -tt -T[/green]')
            console.print()

            start_time = time.time()
            proc, exit_code, elapsed, timed_out = _launch_and_wait(
                fallback_cmd, timeout, tmp_output, tmp_trace, start_time
            )
            iso_label = fallback_label

            if proc is None:
                return
    finally:
        try:
            os.unlink(init_script_path)
        except OSError:
            pass
        try:
            os.unlink(marker_path)
        except OSError:
            pass
        try:
            os.unlink(no_seccomp_marker_path)
        except OSError:
            pass
        shutil.rmtree(root_dir, ignore_errors=True)

    # ── Exit line ──────────────────────────────────────────────────────────────
    console.print()
    sig_info = _signal_name(exit_code)
    if timed_out:
        console.print(f'  [yellow]⚠  Killed after {timeout}s timeout[/yellow]')
    elif sig_info:
        console.print(
            f'  [bold red]✘  Killed by signal: {sig_info}[/bold red]  '
            f'[dim]in {elapsed:.3f}s[/dim]'
        )
    else:
        code_str = (
            f'[green]{exit_code}[/green]'
            if exit_code == 0
            else f'[red]{exit_code}[/red]'
        )
        console.print(
            f'  [dim]Process exited[/dim]  code {code_str}  '
            f'[dim]in {elapsed:.3f}s[/dim]'
        )

    console.print()
    console.print(Rule('[dim]  Report  [/dim]', style='dim'))
    console.print()

    # ── Full report ────────────────────────────────────────────────────────────
    events = _parse_full_trace(tmp_trace)
    label, triggers = _render_report(
        binary_path, exit_code, elapsed, timed_out, events, tmp_output, iso_label
    )

    # ── Save report ───────────────────────────────────────────────────────────
    if save:
        result = _save_report(
            binary_path, exit_code, elapsed, timed_out, events, label, triggers, iso_label
        )
        if result:
            txt_filename, json_filename = result
            console.print(
                f'  [bold green]✔[/bold green] Report saved to '
                f'[bold]~/.lure/reports/{txt_filename}[/bold]'
            )
            if json_filename:
                console.print(
                    f'  [bold green]✔[/bold green] JSON report saved to '
                    f'[bold]~/.lure/reports/{json_filename}[/bold]'
                )
            console.print()


# ── Package manager detection ─────────────────────────────────────────────────

def _strace_install_hint():
    """
    Detect the system's package manager (pacman, then apt, then dnf)
    and return the matching install command, or None if none found.
    """
    if shutil.which('pacman'):
        return 'sudo pacman -S strace'
    if shutil.which('apt'):
        return 'sudo apt install strace'
    if shutil.which('dnf'):
        return 'sudo dnf install strace'
    return None


# ── Public entry point ────────────────────────────────────────────────────────

def run_binary(binary, timeout, binary_args, allow_net, trace_out, save=False):
    """Called by 'lure run'. Validates inputs then orchestrates execution."""

    # Bare names (no '/' anywhere) are ambiguous: did the user mean "look
    # this up on PATH" or "the file sitting right here"? We don't guess —
    # if it's not on PATH but a file by that exact name exists in the
    # current directory, tell them to be explicit with './' instead of
    # silently picking one.
    if os.sep not in binary and not shutil.which(binary):
        cwd_candidate = os.path.join(os.getcwd(), binary)
        if os.path.exists(cwd_candidate):
            console.print(f'[red]Error:[/red] file not found: {binary}')
            console.print(f"[dim]Tip:[/dim] did you mean './{binary}'?")
            return

    binary_path = os.path.realpath(binary)
    if not Path(binary_path).exists():
        console.print(f'[red]Error:[/red] {binary_path} — file not found')
        return

    if not os.access(binary_path, os.X_OK):
        console.print(f'[red]Error:[/red] file is not executable: {binary_path}')
        console.print(f'[dim]Tip:[/dim] run chmod +x {binary_path} to make it executable')
        return

    if not is_elf_file(binary_path):
        console.print(f'[red]{NOT_ELF_ERROR}[/red]')
        return

    if not shutil.which('strace'):
        hint = _strace_install_hint()
        if hint:
            console.print(f'[red]Error:[/red] strace not found — install it with: {hint}')
        else:
            console.print(
                '[red]Error:[/red] strace not found, and no supported package '
                'manager (pacman, apt, dnf) was detected — install strace manually.'
            )
        return

    # Temp file for strace output (deleted on exit unless --out specified)
    fd, tmp_trace = tempfile.mkstemp(prefix='lure_', suffix='.trace')
    os.close(fd)

    # Temp file for the binary's own captured stdout+stderr
    fd, tmp_output = tempfile.mkstemp(prefix='lure_out_', suffix='.log')
    os.close(fd)

    try:
        _execute(
            binary_path, timeout, binary_args, allow_net,
            trace_out, tmp_trace, tmp_output, save,
        )
    finally:
        if trace_out:
            try:
                shutil.copy(tmp_trace, trace_out)
            except OSError:
                pass
        try:
            os.unlink(tmp_trace)
        except OSError:
            pass
        try:
            os.unlink(tmp_output)
        except OSError:
            pass
