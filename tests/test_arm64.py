# FILE: tests/test_arm64.py
"""
ARM64 / QEMU emulation tests for Lure v0.7.0.

Coverage
--------
TestARM64Inspect
  test_inspect_arm64_arch_display   (a) lure inspect on ARM64 ELF shows "ARM64"
  test_inspect_arm64_json_arch      (b) lure inspect --json has elf.arch == "ARM64"

TestARM64Run
  test_run_arm64_missing_qemu       (c) lure run prints clean error when
                                        qemu-aarch64 is not on PATH and binary
                                        is ARM64.  Skipped if qemu IS installed.
  test_run_arm64_with_qemu          (d) lure run succeeds (exit 0) with an ARM64
                                        binary when qemu-aarch64 is available and
                                        report contains ARM64/QEMU indicator.
                                        Skipped if qemu is NOT installed.

The arm64_elf fixture (defined in conftest.py) creates a 132-byte ARM64 ELF
that executes exit(0) via AArch64 Linux syscall 93.  No cross-compiler or
gcc is required — the binary is assembled from raw bytes using Python's
struct module.
"""

import json
import shutil
import subprocess

import pytest


# ── helpers ───────────────────────────────────────────────────────────────────

def _inspect(*args, timeout=30):
    """Run `lure inspect <args>` and return the CompletedProcess."""
    return subprocess.run(
        ['lure', 'inspect', *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _run(*args, timeout=90):
    """Run `lure run <args>` and return the CompletedProcess."""
    return subprocess.run(
        ['lure', 'run', *args],
        capture_output=True, text=True, timeout=timeout,
    )


# ── inspect tests ─────────────────────────────────────────────────────────────

class TestARM64Inspect:
    def test_inspect_arm64_arch_display(self, arm64_elf):
        """
        (a) lure inspect on an ARM64 ELF must exit 0 and display "ARM64"
        in the Architecture panel.  pyelftools maps EM_AARCH64 (183) to
        'AArch64', which _get_arch() normalises to 'ARM64'.
        """
        result = _inspect(arm64_elf)
        assert result.returncode == 0, (
            f'lure inspect exited {result.returncode};\n'
            f'stdout: {result.stdout}\nstderr: {result.stderr}'
        )
        assert 'ARM64' in result.stdout, (
            f'"ARM64" not found in lure inspect output:\n{result.stdout}'
        )

    def test_inspect_arm64_json_arch(self, arm64_elf):
        """
        (b) lure inspect --json on an ARM64 ELF must produce parseable JSON
        whose elf.arch field equals "ARM64".
        """
        result = _inspect('--json', arm64_elf)
        assert result.returncode == 0, (
            f'lure inspect --json exited {result.returncode};\n'
            f'stdout: {result.stdout}\nstderr: {result.stderr}'
        )
        data = json.loads(result.stdout)
        assert 'elf' in data, (
            f"Expected 'elf' key in JSON; got: {list(data)}"
        )
        assert data['elf']['arch'] == 'ARM64', (
            f"Expected elf.arch == 'ARM64'; got: {data['elf'].get('arch')!r}"
        )


# ── run tests ─────────────────────────────────────────────────────────────────

class TestARM64Run:

    @pytest.mark.skipif(
        shutil.which('qemu-aarch64') is not None,
        reason='qemu-aarch64 is installed — cannot test the missing-qemu error path',
    )
    def test_run_arm64_missing_qemu(self, arm64_elf):
        """
        (c) When qemu-aarch64 is not on PATH and the target binary is ARM64,
        lure run must exit non-zero and print a clear error message that names
        both the architecture ("ARM64") and the missing tool ("qemu-aarch64"),
        along with an install hint.

        Skipped when qemu-aarch64 IS installed (the error path cannot be
        triggered in that environment).
        """
        result = _run(arm64_elf)
        output = result.stdout + result.stderr

        assert result.returncode != 0, (
            'Expected lure run to exit non-zero when qemu-aarch64 is absent, '
            f'but it exited {result.returncode}.\nOutput:\n{output}'
        )
        assert 'qemu-aarch64' in output, (
            f'"qemu-aarch64" not found in error output:\n{output}'
        )
        assert 'ARM64' in output or 'aarch64' in output.lower(), (
            f'Architecture reference not found in error output:\n{output}'
        )

    @pytest.mark.skipif(
        shutil.which('qemu-aarch64') is None,
        reason='qemu-aarch64 not installed — cannot test ARM64 emulation',
    )
    def test_run_arm64_with_qemu(self, arm64_elf):
        """
        (d) When qemu-aarch64 is available, lure run on an ARM64 binary must
        exit 0 (lure itself succeeds) and the output must contain an ARM64 or
        QEMU indicator from the Execution Summary or run header.

        The ARM64 binary is a minimal static ELF that immediately exits with
        code 0 via the AArch64 Linux exit syscall — it needs no libraries and
        produces no output, so the CLEAN verdict is expected.

        Skipped when qemu-aarch64 is NOT installed.
        """
        result = _run(arm64_elf)
        output = result.stdout + result.stderr

        assert result.returncode == 0, (
            f'lure run exited {result.returncode} (expected 0).\n'
            f'Output:\n{output}'
        )
        # The Execution Summary panel shows "Architecture: ARM64 (QEMU emulated)"
        # or the run header may reference qemu-aarch64 in trace output.
        assert (
            'ARM64' in output
            or 'QEMU' in output
            or 'qemu' in output.lower()
        ), (
            'No ARM64/QEMU indicator found in lure run output.\n'
            f'Output:\n{output}'
        )
