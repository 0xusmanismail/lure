# FILE: tests/conftest.py
"""
Shared pytest fixtures for the Lure test suite.

Fixture summary
---------------
binary_ls          str  — always '/usr/bin/ls'
binary_echo        str  — always '/usr/bin/echo'
demo_dangerous     str  — path to a compiled binary that reads /etc/passwd
                          and attempts a TCP connect to 93.184.216.34:443;
                          compiled once per session, cached at a fixed temp path
saved_report       str  — path to the .json written by `lure run --save /usr/bin/ls`;
                          both .json and .txt are deleted after the test
two_saved_reports  tuple[str,str]  — (ls_json, echo_json) from --save runs;
                          cleaned up after the test
"""

import glob
import os
import subprocess
import textwrap
from pathlib import Path

import pytest

# ── constants ─────────────────────────────────────────────────────────────────

REPORTS_DIR = os.path.expanduser('~/.lure/reports')

# Fixed temp path so the binary is compiled once and reused across
# sessions without re-running gcc every `pytest` invocation.
_DEMO_BIN_PATH = Path('/tmp/lure_test_demo_dangerous')
_DEMO_SRC_PATH = Path('/tmp/lure_test_demo_dangerous.c')

_DEMO_DANGEROUS_SRC = textwrap.dedent("""\
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    int main(void) {
      FILE *f = fopen("/etc/passwd", "r");
      if (f) { char buf[256];
        fgets(buf, sizeof(buf), f); fclose(f); }
      int sock = socket(AF_INET, SOCK_STREAM, 0);
      struct sockaddr_in addr;
      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons(443);
      addr.sin_addr.s_addr = inet_addr("93.184.216.34");
      connect(sock, (struct sockaddr*)&addr, sizeof(addr));
      close(sock);
      printf("done\\n");
      return 0;
    }
""")


# ── simple binary fixtures ────────────────────────────────────────────────────

@pytest.fixture
def binary_ls():
    """Return the path to /usr/bin/ls, which always exists on Arch Linux."""
    return '/usr/bin/ls'


@pytest.fixture
def binary_echo():
    """Return the path to /usr/bin/echo, which always exists on Arch Linux."""
    return '/usr/bin/echo'


# ── demo_dangerous ────────────────────────────────────────────────────────────

@pytest.fixture(scope='session')
def demo_dangerous():
    """
    Compile demo_dangerous.c if the binary does not already exist and return
    its path.  The binary reads /etc/passwd and attempts an outbound TCP
    connection to 93.184.216.34:443 — enough to trigger a SUSPICIOUS verdict
    and a BLOCKED network entry from lure.

    Uses a fixed path (/tmp/lure_test_demo_dangerous) so the binary survives
    across test sessions without recompilation.
    """
    if not _DEMO_BIN_PATH.exists():
        _DEMO_SRC_PATH.write_text(_DEMO_DANGEROUS_SRC)
        result = subprocess.run(
            ['gcc', '-o', str(_DEMO_BIN_PATH), str(_DEMO_SRC_PATH)],
            capture_output=True,
            text=True,
        )
        try:
            _DEMO_SRC_PATH.unlink()
        except OSError:
            pass
        if result.returncode != 0:
            raise RuntimeError(
                f'demo_dangerous.c failed to compile:\n{result.stderr}'
            )
    return str(_DEMO_BIN_PATH)


# ── report-save helpers ───────────────────────────────────────────────────────

def _snapshot_reports():
    """
    Return the current (.json set, .txt set) inside REPORTS_DIR.
    Creates the directory if absent (lure does the same on first --save).
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    return (
        set(glob.glob(os.path.join(REPORTS_DIR, '*.json'))),
        set(glob.glob(os.path.join(REPORTS_DIR, '*.txt'))),
    )


def _new_files_since(before_json, before_txt):
    """Return (new_json, new_txt) files created after the snapshot."""
    after_json = set(glob.glob(os.path.join(REPORTS_DIR, '*.json')))
    after_txt  = set(glob.glob(os.path.join(REPORTS_DIR, '*.txt')))
    return after_json - before_json, after_txt - before_txt


def _delete_files(*file_sets):
    """Best-effort delete for multiple sets of file paths."""
    for file_set in file_sets:
        for path in file_set:
            try:
                os.unlink(path)
            except OSError:
                pass


# ── saved_report ──────────────────────────────────────────────────────────────

@pytest.fixture
def saved_report():
    """
    Run `lure run --save /usr/bin/ls`, yield the path of the created .json
    report, then delete both the .json and .txt after the test completes.

    Yields None if the save operation produced no JSON (the test will fail its
    own assertion rather than the fixture itself raising).
    """
    before_json, before_txt = _snapshot_reports()

    subprocess.run(
        ['lure', 'run', '--save', '/usr/bin/ls'],
        capture_output=True,
        text=True,
        timeout=90,
    )

    new_json, new_txt = _new_files_since(before_json, before_txt)
    json_path = (
        max(new_json, key=os.path.getmtime) if new_json else None
    )

    yield json_path

    _delete_files(new_json, new_txt)


# ── two_saved_reports ─────────────────────────────────────────────────────────

@pytest.fixture
def two_saved_reports():
    """
    Run `lure run --save` on /usr/bin/ls and /usr/bin/echo in sequence.
    Yield (ls_json_path, echo_json_path).  Delete all created files after
    the test.

    Either path may be None if the corresponding save produced no JSON.
    """
    before_json, before_txt = _snapshot_reports()

    subprocess.run(
        ['lure', 'run', '--save', '/usr/bin/ls'],
        capture_output=True, text=True, timeout=90,
    )
    subprocess.run(
        ['lure', 'run', '--save', '/usr/bin/echo'],
        capture_output=True, text=True, timeout=90,
    )

    new_json, new_txt = _new_files_since(before_json, before_txt)

    ls_json = next(
        (f for f in sorted(new_json)
         if os.path.basename(f).startswith('ls_')),
        None,
    )
    echo_json = next(
        (f for f in sorted(new_json)
         if os.path.basename(f).startswith('echo_')),
        None,
    )

    yield ls_json, echo_json

    _delete_files(new_json, new_txt)
