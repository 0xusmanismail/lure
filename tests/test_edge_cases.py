# FILE: tests/test_edge_cases.py
"""
Edge-case and flag-variation tests for lure inspect, lure run, and lure diff.

Coverage
--------
TestInspectFlags
  test_inspect_json_output       --json produces parseable JSON
  test_inspect_json_has_keys     JSON output includes expected top-level keys
  test_inspect_sections_flag     --sections adds section-header content to output
  test_inspect_strings_flag      --strings flag is accepted and runs without error

TestRunFlags
  test_run_allow_net_flag        --allow-net labels the network as ALLOWED
  test_run_with_binary_args      --args passes arguments through to the binary

TestRunTimeout
  test_run_timeout_kills_process a long-running binary is killed within the
                                  wall-clock timeout and output says TIMEOUT

TestRunJsonSchema
  test_run_json_report_full_schema  all expected JSON keys are present after
                                     --save (comprehensive key-set check)

TestVersionFlag
  test_version_flag              `lure --version` prints the version string
"""

import json
import os
import shutil
import subprocess
import tempfile
import time

import pytest


# ── helpers ───────────────────────────────────────────────────────────────────

def _inspect(*args, timeout=30):
    return subprocess.run(
        ['lure', 'inspect', *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _run(*args, timeout=90):
    return subprocess.run(
        ['lure', 'run', *args],
        capture_output=True, text=True, timeout=timeout,
    )


# ── lure inspect flag variations ──────────────────────────────────────────────

class TestInspectFlags:
    def test_inspect_json_output(self, binary_ls):
        """--json must emit text that can be parsed by json.loads."""
        result = _inspect('--json', binary_ls)
        assert result.returncode == 0
        # The JSON output goes to stdout; parse it directly.
        data = json.loads(result.stdout)
        assert isinstance(data, dict)

    def test_inspect_json_has_keys(self, binary_ls):
        """JSON output must include 'elf' with nested 'arch'."""
        result = _inspect('--json', binary_ls)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert 'elf' in data, (
            f"Expected 'elf' key in JSON; got: {list(data)}"
        )
        assert 'arch' in data['elf'], (
            f"Expected 'arch' inside data['elf']; got: {list(data['elf'])}"
        )

    def test_inspect_sections_flag(self, binary_ls):
        """--sections must add section-header information to the output."""
        plain  = _inspect(binary_ls)
        with_s = _inspect('--sections', binary_ls)
        assert with_s.returncode == 0
        # With --sections the output should be longer than without.
        assert len(with_s.stdout) > len(plain.stdout)

    def test_inspect_strings_flag(self, binary_ls):
        """--strings must be accepted without error."""
        result = _inspect('--strings', binary_ls)
        assert result.returncode == 0


# ── lure run flag variations ──────────────────────────────────────────────────

class TestRunFlags:
    def test_run_allow_net_flag(self, binary_ls):
        """
        --allow-net must label the network as ALLOWED in the header
        instead of the default BLOCKED.
        """
        result = _run('--allow-net', binary_ls)
        assert result.returncode == 0
        assert 'ALLOWED' in result.stdout

    def test_run_with_binary_args(self, binary_ls):
        """
        --args passes arguments through to the binary.
        `ls -la` produces longer output than bare `ls`.
        """
        bare  = _run(binary_ls)
        with_args = _run('--args', '-la', binary_ls)
        assert with_args.returncode == 0
        # Long-listing output is visibly longer than short listing.
        assert len(with_args.stdout) > len(bare.stdout)


# ── timeout behaviour ─────────────────────────────────────────────────────────

class TestRunTimeout:
    def test_run_timeout_kills_process(self):
        """
        A binary that runs longer than --timeout seconds must be killed and
        the report must say TIMEOUT.

        Uses /usr/bin/sleep (coreutils ELF) with `--args 30` and a 1-second
        wall-clock timeout.  The `subprocess.run` timeout is generous (15s)
        so the test itself never hangs.
        """
        sleep_path = shutil.which('sleep') or '/usr/bin/sleep'
        wall_start = time.monotonic()
        result = _run(
            '--timeout', '1',
            '--args', '30',
            sleep_path,
            timeout=15,
        )
        wall_elapsed = time.monotonic() - wall_start
        output = result.stdout + result.stderr
        # The process should have been killed well under 15 seconds.
        assert wall_elapsed < 13, (
            f'lure run did not return within 13 s (took {wall_elapsed:.1f}s)'
        )
        assert 'TIMEOUT' in output or 'Killed' in output or 'timeout' in output.lower()


# ── JSON schema completeness ──────────────────────────────────────────────────

class TestRunJsonSchema:
    # Every key documented in runner._save_report().
    _EXPECTED_KEYS = {
        'binary',
        'full_path',
        'timestamp',
        'runtime_seconds',
        'exit_code',
        'isolation',
        'resource_limits',
        'verdict',
        'verdict_triggers',
        'files_accessed',
        'network_attempts',
        'processes_spawned',
        'syscall_total',
    }

    def test_run_json_report_full_schema(self, saved_report):
        """
        All keys produced by _save_report() must be present in the JSON file.
        This test pins the public JSON schema so any accidental removal is
        caught immediately.
        """
        assert saved_report is not None, (
            'lure run --save produced no JSON report'
        )
        with open(saved_report) as fh:
            data = json.load(fh)

        missing = self._EXPECTED_KEYS - set(data)
        assert not missing, (
            f'JSON report is missing expected keys: {sorted(missing)}'
        )

        # Spot-check a few value types.
        assert isinstance(data['files_accessed'],   list)
        assert isinstance(data['network_attempts'], list)
        assert isinstance(data['syscall_total'],    int)
        assert data['verdict'] in ('CLEAN', 'SUSPICIOUS', 'DANGEROUS')


# ── version flag ──────────────────────────────────────────────────────────────

class TestVersionFlag:
    def test_version_flag(self):
        """`lure --version` must print the current version string."""
        result = subprocess.run(
            ['lure', '--version'],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        output = result.stdout + result.stderr
        # Version is defined in lure/__init__.py as "0.7.0".
        assert '0.7.0' in output
