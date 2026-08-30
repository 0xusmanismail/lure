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
arm64_elf          str  — path to a minimal ARM64 ELF binary (exit(0));
                          built from raw bytes (no cross-compiler required),
                          cached at a fixed temp path across sessions
saved_report       str  — path to the .json written by `lure run --save /usr/bin/ls`;
                          both .json and .txt are deleted after the test
two_saved_reports  tuple[str,str]  — (ls_json, echo_json) from --save runs;
                          cleaned up after the test
"""

import glob
import os
import struct
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

# Fixed temp path for the ARM64 ELF fixture. Built once from raw bytes —
# no cross-compiler needed. The binary is a minimal ELF that exits with
# code 0 via the ARM64 exit syscall (movz x8,#93 / movz x0,#0 / svc #0).
_ARM64_ELF_PATH = Path('/tmp/lure_test_arm64_exit')

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


# ── arm64_elf ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope='session')
def arm64_elf():
    """
    Build a minimal ARM64 ELF binary (132 bytes) using Python's struct
    module only — no gcc or cross-compiler required.

    The binary is a complete, valid ELF64 executable for AArch64:
      - ELF header (64 bytes): e_machine=183 (EM_AARCH64), e_type=ET_EXEC
      - PT_LOAD program header (56 bytes): load at 0x400000, PF_R|PF_X
      - ARM64 machine code (12 bytes): exit(0) via the Linux syscall interface
          movz x8, #93    ; syscall number: exit (AArch64 Linux)
          movz x0, #0     ; exit code: 0
          svc  #0         ; invoke the syscall

    Instruction encoding (little-endian):
      0xa8 0x0b 0x80 0xd2  — movz x8, #93
      0x00 0x00 0x80 0xd2  — movz x0, #0
      0x01 0x00 0x00 0xd4  — svc  #0

    Uses a fixed path (/tmp/lure_test_arm64_exit) so the binary is created
    once and reused across test sessions.
    """
    if not _ARM64_ELF_PATH.exists():
        # ARM64 exit(0) machine code
        code = bytes([
            0xa8, 0x0b, 0x80, 0xd2,   # movz x8, #93  (exit syscall number)
            0x00, 0x00, 0x80, 0xd2,   # movz x0, #0   (exit code)
            0x01, 0x00, 0x00, 0xd4,   # svc  #0       (invoke syscall)
        ])

        # ELF64 layout:
        #   offset 0x00 (64 bytes): ELF header
        #   offset 0x40 (56 bytes): PT_LOAD program header
        #   offset 0x78 (12 bytes): ARM64 code
        LOAD_ADDR   = 0x400000
        EHDR_SIZE   = 64
        PHDR_SIZE   = 56
        CODE_OFFSET = EHDR_SIZE + PHDR_SIZE   # 0x78
        ENTRY_ADDR  = LOAD_ADDR + CODE_OFFSET  # entry point
        total_size  = CODE_OFFSET + len(code)  # 132 bytes

        # ELF identification bytes (e_ident, 16 bytes)
        e_ident = bytes([
            0x7f, 0x45, 0x4c, 0x46,   # EI_MAG: \x7fELF
            0x02,                      # EI_CLASS:   ELFCLASS64
            0x01,                      # EI_DATA:    ELFDATA2LSB (little-endian)
            0x01,                      # EI_VERSION: EV_CURRENT
            0x00,                      # EI_OSABI:   ELFOSABI_NONE
            0x00, 0x00, 0x00, 0x00,   # EI_ABIVERSION + padding
            0x00, 0x00, 0x00, 0x00,   # padding
        ])

        # ELF64 header fields (48 bytes): '<HHIQQQIHHHHHH'
        ehdr = struct.pack(
            '<HHIQQQIHHHHHH',
            2,             # e_type:      ET_EXEC
            183,           # e_machine:   EM_AARCH64 (= 0xB7)
            1,             # e_version:   EV_CURRENT
            ENTRY_ADDR,    # e_entry:     virtual address of entry point
            EHDR_SIZE,     # e_phoff:     program header table offset
            0,             # e_shoff:     no section header table
            0,             # e_flags:     no processor-specific flags
            EHDR_SIZE,     # e_ehsize:    ELF header size
            PHDR_SIZE,     # e_phentsize: size of one program header entry
            1,             # e_phnum:     one program header (PT_LOAD)
            64,            # e_shentsize: section header entry size (unused)
            0,             # e_shnum:     no section headers
            0,             # e_shstrndx:  no section name string table
        )

        # ELF64 program header (56 bytes): '<IIQQQQQQ'
        phdr = struct.pack(
            '<IIQQQQQQ',
            1,             # p_type:   PT_LOAD
            5,             # p_flags:  PF_R | PF_X (read + execute)
            0,             # p_offset: load from start of file
            LOAD_ADDR,     # p_vaddr:  virtual load address
            LOAD_ADDR,     # p_paddr:  physical address (same as virtual)
            total_size,    # p_filesz: bytes to map from file
            total_size,    # p_memsz:  bytes to reserve in memory
            0x1000,        # p_align:  page alignment (4 KiB)
        )

        data = e_ident + ehdr + phdr + code
        assert len(data) == 132, f'unexpected ARM64 ELF size: {len(data)}'

        _ARM64_ELF_PATH.write_bytes(data)
        _ARM64_ELF_PATH.chmod(0o755)

    return str(_ARM64_ELF_PATH)


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
