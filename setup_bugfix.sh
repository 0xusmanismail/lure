#!/usr/bin/env bash
# FILE: setup_bugfix.sh
#
# Combined bugfix for issues found after Tasks 15 and 16.
#
# Touches:
#   lure/inspector.py          rewrite (Problems 1, 2, 3-inspector)
#   lure/runner.py             idempotent patch (Problem 2-runner)
#   tests/test_edge_cases.py   targeted patch (Problems 3, 4-test)
#   lure/__init__.py           idempotent version bump (Problem 4)
#   lure/main.py               idempotent version bump (Problem 4)
#   pyproject.toml             idempotent version bump (Problem 4)
#
# Does NOT touch: ci.yml, conftest.py, test_inspect.py, test_run.py,
#                 test_diff.py, requirements.txt, lure/diff.py, lure/runner.py*
#   (* runner.py only patched if Task 16 exit-code fixes weren't applied yet)
#
# PROBLEM 1 — Sections panel crash
#   inspector.py passed raw values to Rich Table add_row(); if the pyelftools
#   sh_type enum is unknown it returns an int, and on some library versions
#   sh_size was passed raw. Fix: wrap ALL four values in str().
#
# PROBLEM 2 — Exit codes still zero on validation errors
#   inspector.py printed an error and returned (exit 0).
#   runner.py did the same (if Task 16 was not yet applied).
#   Fix: sys.exit(1) after every error print.
#
# PROBLEM 3 — Wrong JSON key in test
#   The user's inspector.py produces {"elf": {"arch": "x86-64", ...}}.
#   Task 15's test checked 'architecture' in data — wrong key.
#   Fix: test_inspect_json_has_keys → assert 'elf' in data; assert 'arch' in data['elf']
#   inspector.py is rewritten to match this schema consistently.
#
# PROBLEM 4 — Version not bumped to 0.6.0
#   All four locations: __init__.py, main.py click option, pyproject.toml,
#   test_edge_cases.py version assertion.
#   Patches are idempotent: 0.5.1→0.6.0 only if 0.5.1 is still present.
#
# Usage: ./setup_bugfix.sh   (run from the repo root)

set -euo pipefail
cd "$(dirname "$0")"

# ─────────────────────────────────────────────────────────────────────────────
# PART 1 — lure/inspector.py: complete rewrite
#   • JSON schema: data['elf']['arch']  (was: data['architecture'])
#   • Sections add_row: str() on all four values  (was: only sec['size'])
#   • All error paths: sys.exit(1) via _err()    (was: return / no exit)
# ─────────────────────────────────────────────────────────────────────────────

echo "==> Rewriting lure/inspector.py..."
cat > lure/inspector.py << 'LURE_INSPECTOR_EOF'
# FILE: lure/inspector.py
"""
Lure inspector — static ELF analysis without execution.

Public interface
----------------
NOT_ELF_ERROR           str  — standard error text for non-ELF inputs
is_elf_file(path)       bool — True iff the file starts with the ELF magic bytes
run_inspect(...)        None — entry point called by `lure inspect`

All validation errors call sys.exit(1) so `lure inspect` exits non-zero
on bad input, matching the contract of `lure run`.

JSON output schema (--json flag)
---------------------------------
{
    "binary":     str,
    "full_path":  str,
    "size_bytes": int,
    "hashes":     {"md5": str, "sha256": str},
    "elf": {
        "arch":   str,   # "x86-64", "ARM64", …
        "type":   str,   # "ET_DYN", "ET_EXEC", …
        "endian": str    # "little" | "big"
    },
    "security": {
        "nx":     bool,
        "pie":    bool,
        "relro":  str,   # "full" | "partial" | "none"
        "canary": bool
    },
    "libraries": [str],
    "sections":  [...],  # only when --sections
    "strings":   [str]   # only when --strings
}
"""

import hashlib
import json
import os
import sys
from pathlib import Path

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

NOT_ELF_ERROR = (
    'Error: not a valid ELF binary \u2014 '
    'lure can only analyse ELF files'
)


# ── low-level helpers ─────────────────────────────────────────────────────────

def is_elf_file(path: str) -> bool:
    """Return True if *path* is a readable file whose first 4 bytes are the
    ELF magic number (0x7f 'E' 'L' 'F')."""
    try:
        with open(path, 'rb') as fh:
            return fh.read(4) == b'\x7fELF'
    except OSError:
        return False


def _file_hashes(path: str) -> dict:
    md5    = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            md5.update(chunk)
            sha256.update(chunk)
    return {'md5': md5.hexdigest(), 'sha256': sha256.hexdigest()}


def _human_size(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f'{n} {unit}'
        n //= 1024
    return f'{n} TB'


# ── ELF attribute extractors ──────────────────────────────────────────────────

def _get_arch(elf: ELFFile) -> str:
    raw = elf.get_machine_arch()
    return {
        'x64':       'x86-64',
        'x86':       'x86',
        'AArch64':   'ARM64',
        'ARM':       'ARM',
        'MIPS':      'MIPS',
        'PowerPC64': 'PPC64',
        'IBM S/390': 'S/390',
    }.get(raw, raw)


def _get_security(elf: ELFFile) -> dict:
    """Detect NX, PIE, partial/full RELRO, and stack canary."""
    nx     = True            # assumed enabled; cleared if PT_GNU_STACK has PF_X
    pie    = elf['e_type'] == 'ET_DYN'
    relro  = 'none'
    canary = False

    for seg in elf.iter_segments():
        pt = seg['p_type']
        if pt == 'PT_GNU_STACK':
            # PF_X = 0x1 — if the execute bit is set, the stack is executable
            nx = not bool(seg['p_flags'] & 0x1)
        elif pt == 'PT_GNU_RELRO':
            relro = 'partial'

    for sec in elf.iter_sections():
        if isinstance(sec, DynamicSection):
            for tag in sec.iter_tags():
                d_tag = tag.entry.d_tag
                d_val = tag.entry.d_val
                # DF_BIND_NOW (DT_FLAGS bit 3) or DF_1_NOW (DT_FLAGS_1 bit 0)
                # both mean full RELRO when combined with PT_GNU_RELRO.
                if d_tag == 'DT_FLAGS'   and (d_val & 0x8):
                    relro = 'full'
                if d_tag == 'DT_FLAGS_1' and (d_val & 0x1):
                    relro = 'full'
        if isinstance(sec, SymbolTableSection):
            try:
                for sym in sec.iter_symbols():
                    if sym.name == '__stack_chk_fail':
                        canary = True
                        break
            except Exception:
                pass

    return {'nx': nx, 'pie': pie, 'relro': relro, 'canary': canary}


def _get_libraries(elf: ELFFile) -> list:
    libs = []
    for sec in elf.iter_sections():
        if isinstance(sec, DynamicSection):
            for tag in sec.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    libs.append(tag.needed)
    return libs


def _get_sections(elf: ELFFile) -> list:
    """Return a list of dicts; ALL values are pre-converted to str so that
    Rich Table.add_row() never receives a raw int and crashes."""
    return [
        {
            'name':   str(sec.name or '(none)'),
            'type':   str(sec['sh_type']),
            'offset': str(hex(sec['sh_offset'])),
            'size':   str(sec['sh_size']),
        }
        for sec in elf.iter_sections()
    ]


def _get_strings(path: str, min_len: int = 6, cap: int = 200) -> list:
    """Extract printable ASCII strings (>= min_len chars) from the binary."""
    results: list = []
    cur: list     = []
    with open(path, 'rb') as fh:
        for byte in fh.read():
            if 0x20 <= byte <= 0x7E:
                cur.append(chr(byte))
            else:
                if len(cur) >= min_len:
                    s = ''.join(cur)
                    if s not in results:
                        results.append(s)
                        if len(results) >= cap:
                            break
                cur = []
    return results


# ── entry point ───────────────────────────────────────────────────────────────

def run_inspect(
    binary: str,
    output_json: bool,
    show_sections: bool,
    show_strings: bool,
) -> None:
    """
    Entry point for `lure inspect`.  Validates *binary*, parses its ELF
    headers, then renders either a rich multi-panel report or a JSON dict.

    Every validation and parse error calls sys.exit(1) so the CLI exits
    with a non-zero code (the same contract as `lure run`).
    """

    path = os.path.realpath(binary)

    # ── validation ────────────────────────────────────────────────────────────

    if not Path(path).exists():
        _err(output_json, f'Error: {binary} \u2014 file not found')

    if os.path.getsize(path) == 0:
        _err(output_json, f'Error: {binary} \u2014 file is empty')

    if not is_elf_file(path):
        _err(output_json, NOT_ELF_ERROR)

    # ── parse ─────────────────────────────────────────────────────────────────

    try:
        with open(path, 'rb') as fh:
            elf      = ELFFile(fh)
            arch     = _get_arch(elf)
            elf_type = elf['e_type']
            endian   = elf.little_endian
            security = _get_security(elf)
            libs     = _get_libraries(elf)
            sections = _get_sections(elf) if show_sections else []
    except Exception as exc:
        _err(output_json, f'Error: failed to parse ELF: {exc}')

    strings = _get_strings(path) if show_strings else []
    hashes  = _file_hashes(path)
    size    = os.path.getsize(path)

    # ── JSON output ───────────────────────────────────────────────────────────

    if output_json:
        out: dict = {
            'binary':     os.path.basename(path),
            'full_path':  path,
            'size_bytes': size,
            'hashes':     hashes,
            'elf': {
                'arch':   arch,
                'type':   elf_type,
                'endian': 'little' if endian else 'big',
            },
            'security':   security,
            'libraries':  libs,
        }
        if show_sections:
            out['sections'] = sections
        if show_strings:
            out['strings'] = strings
        print(json.dumps(out, indent=2))
        return

    # ── rich display ──────────────────────────────────────────────────────────

    # File metadata
    meta = Table(box=None, show_header=False, padding=(0, 2))
    meta.add_column('k', style='dim', no_wrap=True)
    meta.add_column('v')
    meta.add_row('File',   path)
    meta.add_row('Size',   _human_size(size))
    meta.add_row('MD5',    hashes['md5'])
    meta.add_row('SHA256', hashes['sha256'])
    console.print(Panel(meta, title='[bold]File[/bold]', border_style='dim'))

    # Architecture
    abi = Table(box=None, show_header=False, padding=(0, 2))
    abi.add_column('k', style='dim', no_wrap=True)
    abi.add_column('v')
    abi.add_row('Architecture', arch)
    abi.add_row('ELF type',     elf_type)
    abi.add_row('Endianness',   'Little-endian' if endian else 'Big-endian')
    console.print(Panel(abi, title='[bold]Architecture[/bold]', border_style='dim'))

    # Security features
    def _flag(val: bool, yes: str = 'Enabled', no: str = 'Disabled') -> Text:
        return (
            Text(f'\u2714  {yes}', style='green') if val
            else Text(f'\u2718  {no}', style='red')
        )

    relro_display = {
        'full':    Text('\u2714  Full',    style='green'),
        'partial': Text('~  Partial',     style='yellow'),
        'none':    Text('\u2718  None',    style='red'),
    }.get(security['relro'], Text(security['relro']))

    sec_tbl = Table(box=box.SIMPLE, show_header=True, header_style='bold dim')
    sec_tbl.add_column('Mitigation',   style='bold', no_wrap=True)
    sec_tbl.add_column('Status',       no_wrap=True)
    sec_tbl.add_row('NX',           _flag(security['nx']))
    sec_tbl.add_row('PIE',          _flag(security['pie']))
    sec_tbl.add_row('Stack canary', _flag(security['canary']))
    sec_tbl.add_row('RELRO',        relro_display)
    console.print(Panel(sec_tbl,
                        title='[bold]Security Features[/bold]',
                        border_style='dim'))

    # Linked libraries
    if libs:
        lib_tbl = Table(box=box.SIMPLE, show_header=False)
        lib_tbl.add_column('Library', style='cyan')
        for lib in libs:
            lib_tbl.add_row(lib)
        console.print(Panel(lib_tbl,
                            title='[bold]Linked Libraries[/bold]',
                            border_style='dim'))
    else:
        console.print(Panel('[dim]None \u2014 statically linked[/dim]',
                            title='[bold]Linked Libraries[/bold]',
                            border_style='dim'))

    # Section headers (--sections)
    # All values are str (guaranteed by _get_sections), so no crash on add_row.
    if show_sections and sections:
        s_tbl = Table(box=box.SIMPLE, show_header=True, header_style='bold dim')
        s_tbl.add_column('Name')
        s_tbl.add_column('Type')
        s_tbl.add_column('Offset')
        s_tbl.add_column('Size', justify='right')
        for sec in sections:
            s_tbl.add_row(
                str(sec['name']),
                str(sec['type']),
                str(sec['offset']),
                str(sec['size']),
            )
        console.print(Panel(s_tbl,
                            title='[bold]Section Headers[/bold]',
                            border_style='dim'))

    # Strings (--strings)
    if show_strings and strings:
        shown = strings[:50]
        str_tbl = Table(box=box.SIMPLE, show_header=False)
        str_tbl.add_column('String', style='dim')
        for s in shown:
            str_tbl.add_row(s)
        title = (
            f'[bold]Strings[/bold] '
            f'[dim](top {len(shown)} of {len(strings)})[/dim]'
        )
        console.print(Panel(str_tbl, title=title, border_style='dim'))


# ── internal error helper ─────────────────────────────────────────────────────

def _err(output_json: bool, msg: str) -> None:
    """Print *msg* in the appropriate format and exit with code 1.
    Annotated NoReturn-style: callers need not check the return value."""
    if output_json:
        print(json.dumps({'error': msg}))
    else:
        console.print(f'[red]{msg}[/red]')
    sys.exit(1)
LURE_INSPECTOR_EOF

# ─────────────────────────────────────────────────────────────────────────────
# PART 2 — lure/runner.py: idempotent exit-code patches
#   Applies the five sys.exit(1) fixes and the empty-file guard only when
#   the old `return` patterns are still present.  If Task 16 already ran,
#   every patch is skipped cleanly.
# ─────────────────────────────────────────────────────────────────────────────

echo "==> Patching lure/runner.py (idempotent exit-code fixes)..."
python3 << 'LURE_PATCH_RUNNER_EOF'
import sys
from pathlib import Path

p = Path('lure/runner.py')
c = p.read_text()
original = c
changes  = 0

def try_patch(label, old, new):
    """Replace old→new once if old is present. Skip silently if not found
    (already patched or different code path)."""
    global c, changes
    if old in c:
        c = c.replace(old, new, 1)
        changes += 1
        print(f'  ✔  {label}')
    else:
        # Confirm the already-patched version is present so we can warn
        # if neither old nor new exists.
        already = new if new in c else None
        if already:
            print(f'  –  {label} (already applied)')
        else:
            print(f'  ⚠  {label}: pattern not found — inspect runner.py manually',
                  file=sys.stderr)

# ── 1. bare-name "did you mean ./" ───────────────────────────────────────────
try_patch(
    'bare-name return → sys.exit(1)',
    "            console.print(f'[red]Error:[/red] file not found: {binary}')\n"
    "            console.print(f\"[dim]Tip:[/dim] did you mean './{binary}'?\")\n"
    "            return\n",
    "            console.print(f'[red]Error:[/red] file not found: {binary}')\n"
    "            console.print(f\"[dim]Tip:[/dim] did you mean './{binary}'?\")\n"
    "            sys.exit(1)\n",
)

# ── 2. path not found ─────────────────────────────────────────────────────────
try_patch(
    'path-not-found return → sys.exit(1)',
    "    if not Path(binary_path).exists():\n"
    "        console.print(f'[red]Error:[/red] {binary_path} \u2014 file not found')\n"
    "        return\n",
    "    if not Path(binary_path).exists():\n"
    "        console.print(f'[red]Error:[/red] {binary_path} \u2014 file not found')\n"
    "        sys.exit(1)\n",
)

# ── 3. not executable ─────────────────────────────────────────────────────────
try_patch(
    'not-executable return → sys.exit(1)',
    "        console.print(f'[dim]Tip:[/dim] run chmod +x {binary_path} to make it executable')\n"
    "        return\n",
    "        console.print(f'[dim]Tip:[/dim] run chmod +x {binary_path} to make it executable')\n"
    "        sys.exit(1)\n",
)

# ── 4. insert empty-file guard (only when not yet present) ───────────────────
EMPTY_GUARD = "    if os.path.getsize(binary_path) == 0:\n"
if EMPTY_GUARD not in c:
    # Anchor: closing line of not-executable block (post-patch 3) then ELF check
    anchor_old = (
        "        console.print(f'[dim]Tip:[/dim] run chmod +x {binary_path} "
        "to make it executable')\n"
        "        sys.exit(1)\n"
        "\n"
        "    if not is_elf_file(binary_path):"
    )
    anchor_new = (
        "        console.print(f'[dim]Tip:[/dim] run chmod +x {binary_path} "
        "to make it executable')\n"
        "        sys.exit(1)\n"
        "\n"
        "    if os.path.getsize(binary_path) == 0:\n"
        "        console.print(f'[red]Error:[/red] {binary_path} \u2014 file is empty')\n"
        "        sys.exit(1)\n"
        "\n"
        "    if not is_elf_file(binary_path):"
    )
    if anchor_old in c:
        c = c.replace(anchor_old, anchor_new, 1)
        changes += 1
        print('  ✔  inserted empty-file guard')
    else:
        print('  ⚠  empty-file guard anchor not found — skipping', file=sys.stderr)
else:
    print('  –  empty-file guard (already present)')

# ── 5. not ELF ────────────────────────────────────────────────────────────────
try_patch(
    'not-ELF return → sys.exit(1)',
    "    if not is_elf_file(binary_path):\n"
    "        console.print(f'[red]{NOT_ELF_ERROR}[/red]')\n"
    "        return\n",
    "    if not is_elf_file(binary_path):\n"
    "        console.print(f'[red]{NOT_ELF_ERROR}[/red]')\n"
    "        sys.exit(1)\n",
)

if c != original:
    p.write_text(c)
    print(f'runner.py: {changes} change(s) written.')
else:
    print('runner.py: no changes needed (already up to date).')
LURE_PATCH_RUNNER_EOF

# ─────────────────────────────────────────────────────────────────────────────
# PART 3 — tests/test_edge_cases.py: targeted patches
#   a. Fix test_inspect_json_has_keys assertion  (Problem 3)
#   b. Bump version assertion 0.5.1 → 0.6.0      (Problem 4)
# ─────────────────────────────────────────────────────────────────────────────

echo "==> Patching tests/test_edge_cases.py..."
python3 << 'LURE_PATCH_TESTS_EOF'
import sys
from pathlib import Path

p = Path('tests/test_edge_cases.py')
if not p.exists():
    print('WARNING: tests/test_edge_cases.py not found — skipping', file=sys.stderr)
    sys.exit(0)

c = p.read_text()
original = c
changes  = 0

# ── 3a. Fix the JSON key assertion ───────────────────────────────────────────
# The old assertion checked 'architecture' in data, which matches a flat JSON
# structure. The actual inspector.py produces data['elf']['arch'], so the test
# must check the nested key.

OLD_ASSERTION = (
    "    def test_inspect_json_has_keys(self, binary_ls):\n"
    "        \"\"\"JSON output must include 'architecture' and 'security' keys.\"\"\"\n"
    "        result = _inspect('--json', binary_ls)\n"
    "        assert result.returncode == 0\n"
    "        data = json.loads(result.stdout)\n"
    "        # Minimum viable schema check.\n"
    "        assert 'architecture' in data or 'arch' in data, (\n"
    "            f'Expected architecture key; got keys: {list(data)}'\n"
    "        )\n"
)
NEW_ASSERTION = (
    "    def test_inspect_json_has_keys(self, binary_ls):\n"
    "        \"\"\"JSON output must include 'elf' with nested 'arch'.\"\"\"\n"
    "        result = _inspect('--json', binary_ls)\n"
    "        assert result.returncode == 0\n"
    "        data = json.loads(result.stdout)\n"
    "        assert 'elf' in data, (\n"
    "            f\"Expected 'elf' key in JSON; got: {list(data)}\"\n"
    "        )\n"
    "        assert 'arch' in data['elf'], (\n"
    "            f\"Expected 'arch' inside data['elf']; got: {list(data['elf'])}\"\n"
    "        )\n"
)

if OLD_ASSERTION in c:
    c = c.replace(OLD_ASSERTION, NEW_ASSERTION, 1)
    changes += 1
    print("  ✔  test_inspect_json_has_keys: assertion updated to data['elf']['arch']")
elif "assert 'elf' in data" in c:
    print("  –  test_inspect_json_has_keys: already uses data['elf']['arch']")
else:
    print("  ⚠  test_inspect_json_has_keys: assertion pattern not found — check manually",
          file=sys.stderr)

# ── 3b. Version string 0.5.1 → 0.6.0 ────────────────────────────────────────
if '0.5.1' in c:
    c = c.replace('0.5.1', '0.6.0')
    changes += 1
    print('  ✔  version assertion: 0.5.1 → 0.6.0')
elif '0.6.0' in c:
    print('  –  version assertion: already 0.6.0')
else:
    print('  ⚠  version string not found — check manually', file=sys.stderr)

if c != original:
    p.write_text(c)
    print(f'test_edge_cases.py: {changes} change(s) written.')
else:
    print('test_edge_cases.py: no changes needed.')
LURE_PATCH_TESTS_EOF

# ─────────────────────────────────────────────────────────────────────────────
# PART 4 — version bump 0.5.1 → 0.6.0 in three version files
#   All three patches are idempotent: no-op when already 0.6.0.
# ─────────────────────────────────────────────────────────────────────────────

echo "==> Bumping version to 0.6.0 (idempotent)..."
python3 << 'LURE_PATCH_VERSION_EOF'
from pathlib import Path

files = {
    'lure/__init__.py': ('"0.5.1"',       '"0.6.0"'),
    'lure/main.py':     ("version='0.5.1'", "version='0.6.0'"),
    'pyproject.toml':   ('0.5.1',          '0.6.0'),
}

for fname, (old, new) in files.items():
    p = Path(fname)
    if not p.exists():
        print(f'  ⚠  {fname}: not found — skipping')
        continue
    c = p.read_text()
    if old in c:
        p.write_text(c.replace(old, new))
        print(f'  ✔  {fname}: {old} → {new}')
    elif new in c:
        print(f'  –  {fname}: already {new}')
    else:
        print(f'  ⚠  {fname}: neither {old!r} nor {new!r} found — check manually')
LURE_PATCH_VERSION_EOF

# ─────────────────────────────────────────────────────────────────────────────
# summary
# ─────────────────────────────────────────────────────────────────────────────

echo
echo "Bugfix complete. Files changed:"
echo "  lure/inspector.py        (rewritten: str() fix, sys.exit(1), data['elf']['arch'] JSON)"
echo "  lure/runner.py           (idempotent: sys.exit(1) on all validation errors)"
echo "  tests/test_edge_cases.py (JSON assertion + version 0.6.0)"
echo "  lure/__init__.py         (version 0.6.0)"
echo "  lure/main.py             (version 0.6.0)"
echo "  pyproject.toml           (version 0.6.0)"
echo
echo "Reinstall to pick up the version bump:"
echo "  pip install -e . --break-system-packages"
