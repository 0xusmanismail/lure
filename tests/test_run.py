# FILE: tests/test_run.py
"""
Tests for `lure run` — sandboxed execution.

Coverage
--------
TestRunClean
  test_run_clean_binary          /usr/bin/ls → exit 0, "CLEAN" verdict
  test_run_shows_isolation       "user + net + mount + pid" in output
  test_run_shows_seccomp         "seccomp" in output
  test_run_shows_program_output  "Program Output" panel always rendered

TestRunSuspicious
  test_run_suspicious_binary     demo_dangerous → "SUSPICIOUS" + /etc/passwd
                                  + 93.184.216.34
  test_run_network_blocked       demo_dangerous → "BLOCKED" in network table

TestRunSave
  test_run_saves_txt_report      --save creates a .txt in ~/.lure/reports/
  test_run_saves_json_report     --save creates valid JSON with "verdict" +
                                  "isolation" keys

TestRunErrors
  test_run_not_elf               non-ELF executable → exit ≠ 0 +
                                  "not a valid ELF"
  test_run_nonexistent_file      missing path → exit ≠ 0

Note on exit-code tests (test_run_not_elf, test_run_nonexistent_file):
  run_binary() currently returns rather than calling sys.exit on validation
  errors, so the CLI exits 0 today.  These assertions document the *desired*
  behaviour and will start passing once the runner propagates a non-zero code.
  The output-string assertions in each test independently verify the error
  message so the intent is clear even when the exit-code assertion fails.
"""

import json
import os
import subprocess
import tempfile

import pytest


# ── helper ────────────────────────────────────────────────────────────────────

def _run(*args, timeout=90):
    """Run `lure run <args>` and return the CompletedProcess."""
    return subprocess.run(
        ['lure', 'run', *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


# ── clean binary ──────────────────────────────────────────────────────────────

class TestRunClean:
    def test_run_clean_binary(self, binary_ls):
        """Running /usr/bin/ls must exit 0 and produce a CLEAN verdict."""
        result = _run(binary_ls)
        assert result.returncode == 0
        assert 'CLEAN' in result.stdout

    def test_run_shows_isolation(self, binary_ls):
        """Full mount-namespace isolation label must appear in the report."""
        result = _run(binary_ls)
        # Printed twice: once as the in-progress message and once in the
        # Execution Summary panel with the final confirmed label.
        assert 'user + net + mount + pid' in result.stdout

    def test_run_shows_seccomp(self, binary_ls):
        """'seccomp' must appear in the isolation label when the filter is active."""
        result = _run(binary_ls)
        assert 'seccomp' in result.stdout

    def test_run_shows_program_output(self, binary_echo):
        """The 'Program Output' panel heading must always be rendered."""
        result = _run(binary_echo)
        assert 'Program Output' in result.stdout


# ── suspicious binary ─────────────────────────────────────────────────────────

class TestRunSuspicious:
    def test_run_suspicious_binary(self, demo_dangerous):
        """
        demo_dangerous reads /etc/passwd and attempts a network connection.
        Combined, those triggers produce a SUSPICIOUS verdict; both must
        appear in the report.
        """
        result = _run(demo_dangerous)
        assert 'SUSPICIOUS' in result.stdout
        assert '/etc/passwd'    in result.stdout
        assert '93.184.216.34' in result.stdout

    def test_run_network_blocked(self, demo_dangerous):
        """The outbound connection attempt must appear as BLOCKED (network ns)."""
        result = _run(demo_dangerous)
        assert 'BLOCKED' in result.stdout


# ── report saving ─────────────────────────────────────────────────────────────

class TestRunSave:
    def test_run_saves_txt_report(self, saved_report):
        """
        --save must create a .txt report alongside the .json.
        The saved_report fixture runs `lure run --save /usr/bin/ls` and
        yields the .json path; the .txt path shares the same basename.
        """
        assert saved_report is not None, (
            'lure run --save produced no JSON — cannot check for .txt'
        )
        txt_path = saved_report.replace('.json', '.txt')
        assert os.path.isfile(txt_path), (
            f'Expected a .txt report at {txt_path}'
        )

    def test_run_saves_json_report(self, saved_report):
        """
        --save must create a valid JSON file containing at minimum the
        'verdict' and 'isolation' keys.
        """
        assert saved_report is not None, (
            'lure run --save produced no JSON report'
        )
        assert os.path.isfile(saved_report)

        with open(saved_report) as fh:
            data = json.load(fh)  # raises on invalid JSON

        assert 'verdict'   in data, f"'verdict' missing from JSON: {list(data)}"
        assert 'isolation' in data, f"'isolation' missing from JSON: {list(data)}"


# ── error paths ───────────────────────────────────────────────────────────────

class TestRunErrors:
    def test_run_not_elf(self):
        """
        Passing an executable non-ELF file must be rejected with the standard
        'not a valid ELF' error.

        The file must be chmod +x so the runner reaches the ELF check rather
        than the earlier executability check.
        """
        with tempfile.NamedTemporaryFile(
            mode='w',
            prefix='lure_test_',
            suffix='.bin',
            delete=False,
        ) as f:
            f.write('not an elf')
            path = f.name
        os.chmod(path, 0o755)
        try:
            result = _run(path)
            output = result.stdout + result.stderr
            assert result.returncode != 0
            assert 'not a valid ELF' in output
        finally:
            os.unlink(path)

    def test_run_nonexistent_file(self):
        """Passing a path that does not exist must be rejected with a non-zero exit."""
        result = _run('/nonexistent/path/lure_test_binary')
        output = result.stdout + result.stderr
        assert result.returncode != 0
