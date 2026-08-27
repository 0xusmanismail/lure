# FILE: tests/test_diff.py
"""
Tests for `lure diff` — comparison of two saved execution reports.

Coverage
--------
TestDiffValid
  test_diff_exits_zero             two valid reports → exit 0
  test_diff_produces_output        diff must print something non-empty
  test_diff_shows_binary_names     both binary names ("ls", "echo") in output
  test_diff_shows_verdict          "CLEAN" appears (both binaries are clean)
  test_diff_same_report_twice      diffing a report against itself → exit 0

TestDiffErrors
  test_diff_missing_file           nonexistent first report → error
  test_diff_invalid_json           malformed JSON file → error
"""

import json
import os
import subprocess
import tempfile

import pytest


# ── helper ────────────────────────────────────────────────────────────────────

def _diff(*args, timeout=30):
    """Run `lure diff <args>` and return the CompletedProcess."""
    return subprocess.run(
        ['lure', 'diff', *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


# ── valid diffs ───────────────────────────────────────────────────────────────

class TestDiffValid:
    def test_diff_exits_zero(self, two_saved_reports):
        """Diffing two valid saved reports must exit 0."""
        report1, report2 = two_saved_reports
        assert report1 is not None and report2 is not None, (
            'Fixture did not produce two JSON reports'
        )
        result = _diff(report1, report2)
        assert result.returncode == 0

    def test_diff_produces_output(self, two_saved_reports):
        """Diff output must be non-empty."""
        report1, report2 = two_saved_reports
        assert report1 and report2
        result = _diff(report1, report2)
        assert (result.stdout + result.stderr).strip()

    def test_diff_shows_binary_names(self, two_saved_reports):
        """Both binary names ('ls' and 'echo') must appear somewhere in the diff."""
        report1, report2 = two_saved_reports
        assert report1 and report2
        result = _diff(report1, report2)
        output = result.stdout + result.stderr
        assert 'ls'   in output
        assert 'echo' in output

    def test_diff_shows_verdict(self, two_saved_reports):
        """Both runs were CLEAN; the verdict must appear in the diff output."""
        report1, report2 = two_saved_reports
        assert report1 and report2
        result = _diff(report1, report2)
        assert 'CLEAN' in (result.stdout + result.stderr)

    def test_diff_same_report_twice(self, saved_report):
        """Diffing a report against itself must be valid (exit 0)."""
        assert saved_report is not None
        result = _diff(saved_report, saved_report)
        assert result.returncode == 0


# ── error paths ───────────────────────────────────────────────────────────────

class TestDiffErrors:
    def test_diff_missing_file(self, saved_report):
        """Passing a nonexistent first report must result in an error."""
        assert saved_report is not None
        result = _diff('/nonexistent/lure_test_missing.json', saved_report)
        output = result.stdout + result.stderr
        # Accept either a non-zero exit code OR an explicit error message.
        assert result.returncode != 0 or any(
            kw in output.lower() for kw in ('error', 'not found', 'no such')
        )

    def test_diff_invalid_json(self, saved_report, tmp_path):
        """A syntactically invalid JSON file must be handled gracefully."""
        assert saved_report is not None
        bad = tmp_path / 'bad.json'
        bad.write_text('{ this is not valid json !! }')
        result = _diff(str(bad), saved_report)
        output = result.stdout + result.stderr
        assert result.returncode != 0 or any(
            kw in output.lower()
            for kw in ('error', 'invalid', 'json', 'parse', 'decode')
        )
