# FILE: tests/test_inspect.py
"""
Tests for `lure inspect` — static ELF analysis without execution.

Coverage
--------
TestInspectValid
  test_inspect_valid_elf              exit 0 on a real ELF
  test_inspect_shows_architecture     "x86-64" in output
  test_inspect_shows_security_features "NX" and "PIE" in output
  test_inspect_shows_libraries        "libc" in output

TestInspectErrors
  test_inspect_not_elf                non-ELF file → exit ≠ 0 + "not a valid ELF"
  test_inspect_empty_file             empty file   → exit ≠ 0 + "empty" (case-insensitive)
  test_inspect_nonexistent_file       missing path → exit ≠ 0
"""

import os
import subprocess
import tempfile

import pytest


# ── helper ────────────────────────────────────────────────────────────────────

def _inspect(*args):
    """Run `lure inspect <args>` and return the CompletedProcess."""
    return subprocess.run(
        ['lure', 'inspect', *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


# ── valid ELF tests ───────────────────────────────────────────────────────────

class TestInspectValid:
    def test_inspect_valid_elf(self, binary_ls):
        """lure inspect on a real ELF binary must exit 0."""
        result = _inspect(binary_ls)
        assert result.returncode == 0

    def test_inspect_shows_architecture(self, binary_ls):
        """The architecture field must report x86-64 on this platform."""
        result = _inspect(binary_ls)
        assert 'x86-64' in result.stdout

    def test_inspect_shows_security_features(self, binary_ls):
        """NX and PIE mitigations must appear in the security-features table."""
        result = _inspect(binary_ls)
        assert 'NX'  in result.stdout
        assert 'PIE' in result.stdout

    def test_inspect_shows_libraries(self, binary_ls):
        """/usr/bin/ls is dynamically linked; libc must appear in linked libs."""
        result = _inspect(binary_ls)
        assert 'libc' in result.stdout


# ── error path tests ──────────────────────────────────────────────────────────

class TestInspectErrors:
    def test_inspect_not_elf(self):
        """A plain-text file must be rejected with a 'not a valid ELF' message."""
        with tempfile.NamedTemporaryFile(
            mode='w',
            prefix='lure_test_',
            suffix='.txt',
            delete=False,
        ) as f:
            f.write('not an elf')
            path = f.name
        try:
            result = _inspect(path)
            output = result.stdout + result.stderr
            assert result.returncode != 0
            assert 'not a valid ELF' in output
        finally:
            os.unlink(path)

    def test_inspect_empty_file(self):
        """An empty file must be rejected with an 'empty' error message."""
        with tempfile.NamedTemporaryFile(
            prefix='lure_test_',
            suffix='.elf',
            delete=False,
        ) as f:
            path = f.name  # created empty
        try:
            result = _inspect(path)
            output = result.stdout + result.stderr
            assert result.returncode != 0
            assert 'empty' in output.lower()
        finally:
            os.unlink(path)

    def test_inspect_nonexistent_file(self):
        """A missing path must be rejected with a non-zero exit code."""
        result = _inspect('/nonexistent/path/lure_test_binary')
        assert result.returncode != 0
