# FILE: lure/inspector.py
"""
ELF binary inspection engine for 'lure inspect'.
Parses headers, security mitigations, libraries, and strings
without executing a single byte of code.
"""

import os
import re
import json
import stat
import hashlib
import datetime
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()


# ── ELF validation ────────────────────────────────────────────────────────────

ELF_MAGIC     = b'\x7fELF'
NOT_ELF_ERROR = 'Error: not a valid ELF binary. Lure only supports Linux ELF files.'


def is_elf_file(filepath: str) -> bool:
    """True if the first 4 bytes of `filepath` match the ELF magic number."""
    try:
        with open(filepath, 'rb') as f:
            return f.read(4) == ELF_MAGIC
    except OSError:
        return False


# ── Lookup tables ─────────────────────────────────────────────────────────────

ARCH_MAP = {
    'EM_NONE':    'Unknown',
    'EM_386':     'x86 (32-bit)',
    'EM_X86_64':  'x86-64',
    'EM_ARM':     'ARM (32-bit)',
    'EM_AARCH64': 'ARM64 (AArch64)',
    'EM_MIPS':    'MIPS',
    'EM_PPC':     'PowerPC (32-bit)',
    'EM_PPC64':   'PowerPC (64-bit)',
    'EM_S390':    'IBM S/390',
    'EM_RISCV':   'RISC-V',
    'EM_IA_64':   'Itanium (IA-64)',
    'EM_SPARC':   'SPARC',
}

TYPE_MAP = {
    'ET_NONE': 'Unknown',
    'ET_REL':  'Relocatable Object',
    'ET_EXEC': 'Static Executable',
    'ET_DYN':  'Shared Object/PIE Executable',
    'ET_CORE': 'Core Dump',
}


# ── ELF analysis ──────────────────────────────────────────────────────────────

def _md5(filepath: str) -> str:
    h = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _check_nx(elf) -> bool:
    """NX enabled when PT_GNU_STACK segment lacks the execute bit."""
    for seg in elf.iter_segments():
        if seg.header.p_type == 'PT_GNU_STACK':
            return not bool(seg.header.p_flags & 0x1)   # PF_X = 0x1
    return True   # absent PT_GNU_STACK -> kernel default: NX on


def _check_pie(elf) -> bool:
    """PIE executables are compiled as ET_DYN shared objects."""
    return elf.header.e_type == 'ET_DYN'


def _check_relro(elf) -> str:
    """Classify RELRO protection as 'full', 'partial', or 'none'."""
    has_relro_seg = any(
        seg.header.p_type == 'PT_GNU_RELRO'
        for seg in elf.iter_segments()
    )
    if not has_relro_seg:
        return 'none'

    dyn = elf.get_section_by_name('.dynamic')
    if dyn:
        for tag in dyn.iter_tags():
            d = tag.entry.d_tag
            v = tag.entry.d_val
            if d == 'DT_BIND_NOW':
                return 'full'
            if d == 'DT_FLAGS'   and (v & 0x8):   # DF_BIND_NOW
                return 'full'
            if d == 'DT_FLAGS_1' and (v & 0x1):   # DF_1_NOW
                return 'full'
    return 'partial'


def _check_canary(elf) -> bool:
    """Stack canary present when __stack_chk_fail is imported."""
    targets = {'__stack_chk_fail', '__stack_chk_guard'}
    for sec_name in ('.dynsym', '.symtab'):
        sec = elf.get_section_by_name(sec_name)
        if sec and isinstance(sec, SymbolTableSection):
            for sym in sec.iter_symbols():
                if sym.name in targets:
                    return True
    return False


def _check_stripped(elf) -> bool:
    """Binary is stripped when .symtab is absent or contains only the null entry."""
    sec = elf.get_section_by_name('.symtab')
    if sec is None:
        return True
    return sec.num_symbols() <= 1


def _check_upx(elf, filepath: str) -> bool:
    """Detect UPX packing via section names or the UPX! magic bytes."""
    for sec in elf.iter_sections():
        if 'UPX' in sec.name.upper():
            return True
    try:
        with open(filepath, 'rb') as f:
            data = f.read(65536)
        if b'UPX!' in data:
            return True
    except OSError:
        pass
    return False


def _is_dynamic(elf) -> bool:
    """Dynamically linked binaries have a PT_INTERP segment (the loader path)."""
    return any(seg.header.p_type == 'PT_INTERP' for seg in elf.iter_segments())


def _get_libraries(elf) -> list:
    """Return DT_NEEDED library names from the .dynamic section."""
    libs = []
    dyn = elf.get_section_by_name('.dynamic')
    if dyn:
        for tag in dyn.iter_tags():
            if tag.entry.d_tag == 'DT_NEEDED':
                libs.append(tag.needed)
    return libs


def _get_sections_data(elf) -> list:
    return [
        {
            'name':    sec.name,
            'type':    sec.header.sh_type,
            'address': sec.header.sh_addr,
            'size':    sec.header.sh_size,
        }
        for sec in elf.iter_sections()
        if sec.name
    ]


def _extract_strings(filepath: str, min_len: int = 8) -> list:
    """
    Scan raw bytes for printable ASCII runs and tag each by category.
    Returns up to 200 results sorted by category priority.
    """
    PATTERNS = {
        'url':     re.compile(r'https?://[^\x00\s]{6,}'),
        'ip':      re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'path':    re.compile(r'/[a-zA-Z][a-zA-Z0-9_/.-]{5,}'),
        'shell':   re.compile(
            r'\b(bash|/bin/sh|python3?|perl|ruby|exec|system|'
            r'popen|chmod|chown|wget|curl|ncat|nmap|base64)\b'
        ),
        'env_var': re.compile(r'\b[A-Z][A-Z0-9_]{3,}='),
    }
    results = []
    raw_pat = re.compile(b'[ -~]{' + str(min_len).encode() + b',}')
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        for m in raw_pat.finditer(data):
            s = m.group().decode('ascii', errors='ignore')
            for cat, pat in PATTERNS.items():
                if pat.search(s):
                    results.append({
                        'string':   s,
                        'offset':   m.start(),
                        'category': cat,
                    })
                    break
    except OSError:
        pass
    return results[:200]


# ── Rich helpers ──────────────────────────────────────────────────────────────

def _ok(label: str)       -> Text:
    return Text.assemble(('✔  ', 'bold green'),  (label, 'green'))

def _bad(label: str)      -> Text:
    return Text.assemble(('✘  ', 'bold red'),    (label, 'red'))

def _warn_txt(label: str) -> Text:
    return Text.assemble(('⚠ ', 'bold yellow'), (label, 'yellow'))

def _half(label: str)     -> Text:
    return Text.assemble(('◑  ', 'bold yellow'), (label, 'yellow'))


def _kv_panel(rows: list, title: str, border: str = 'dim white') -> Panel:
    """Two-column key/value table wrapped in a rounded Panel."""
    t = Table(box=None, show_header=False, show_edge=False, padding=(0, 1))
    t.add_column(style='dim', no_wrap=True, min_width=15)
    t.add_column(no_wrap=False)
    for key, val in rows:
        t.add_row(key, val)
    return Panel(
        t,
        title=f'[bold]{title}[/bold]',
        border_style=border,
        box=box.ROUNDED,
        padding=(0, 1),
    )


# ── Panels ────────────────────────────────────────────────────────────────────

def _security_panel(nx: bool, pie: bool, relro: str, canary: bool) -> Panel:
    t = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style='bold dim',
        padding=(0, 2),
        expand=True,
    )
    t.add_column('Feature',     style='white', no_wrap=True,  min_width=16)
    t.add_column('Status',      no_wrap=True,                 min_width=20)
    t.add_column('Description', style='dim',   no_wrap=False)

    t.add_row(
        'NX',
        _ok('Enabled')  if nx else _bad('Disabled'),
        'Stack and heap pages are not executable',
    )
    t.add_row(
        'PIE',
        _ok('Enabled')  if pie else _bad('Disabled'),
        'Binary loads at a randomised base address (ASLR)',
    )
    if relro == 'full':
        t.add_row('RELRO', _ok('Full'),
                  'GOT is fully read-only after initialisation')
    elif relro == 'partial':
        t.add_row('RELRO', _half('Partial'),
                  'GOT partially protected — GOT PLT still writable')
    else:
        t.add_row('RELRO', _bad('None'),
                  'GOT is writable — overwrite attacks possible')
    t.add_row(
        'Stack Canary',
        _ok('Present') if canary else _bad('Absent'),
        'Stack overflow detection via __stack_chk_fail',
    )

    return Panel(
        t,
        title='[bold]Security Features[/bold]',
        border_style='dim white',
        box=box.ROUNDED,
        padding=(0, 1),
    )


def _libraries_panel(libs: list) -> Panel:
    if not libs:
        body = Text(
            '  (statically linked — no shared libraries)',
            style='dim italic',
        )
    else:
        t = Table(box=None, show_header=False, show_edge=False, padding=(0, 1))
        t.add_column()
        for lib in libs:
            t.add_row(Text(f'  {lib}', style='cyan'))
        body = t

    count = f'[bold]{len(libs)}[/bold]'
    return Panel(
        body,
        title=f'[bold]Linked Libraries[/bold] ({count})',
        border_style='dim white',
        box=box.ROUNDED,
        padding=(0, 1),
    )


def _sections_panel(sections: list, bits: int) -> Panel:
    addr_width = 16 if bits == 64 else 8
    t = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style='bold dim',
        padding=(0, 1),
        expand=True,
    )
    t.add_column('Name',    style='cyan',  no_wrap=True, min_width=24)
    t.add_column('Type',    style='white', no_wrap=True, min_width=20)
    t.add_column('Address', style='green', no_wrap=True,
                 min_width=addr_width + 4, justify='right')
    t.add_column('Size',    style='white', no_wrap=True,
                 min_width=10, justify='right')

    for sec in sections:
        addr     = f'0x{sec["address"]:0{addr_width}x}' if sec['address'] else '—'
        sz       = sec['size']
        size_str = f'{sz / 1024:.1f} KB' if sz >= 1024 else f'{sz} B'
        t.add_row(sec['name'], sec['type'], addr, size_str)

    return Panel(
        t,
        title='[bold]ELF Sections[/bold]',
        border_style='dim white',
        box=box.ROUNDED,
        padding=(0, 1),
    )


def _strings_panel(strings: list) -> Panel:
    CAT_STYLE = {
        'url':     ('URL',     'blue'),
        'ip':      ('IP',      'yellow'),
        'path':    ('Path',    'cyan'),
        'shell':   ('Shell',   'red'),
        'env_var': ('Env Var', 'magenta'),
    }
    if not strings:
        body  = Text('  (no interesting strings found)', style='dim italic')
        count = '0'
    else:
        t = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style='bold dim',
            padding=(0, 1),
            expand=True,
        )
        t.add_column('Offset',   style='dim',  no_wrap=True,
                     min_width=12, justify='right')
        t.add_column('Category', no_wrap=True, min_width=10)
        t.add_column('String',   no_wrap=False)

        for item in strings:
            label, color = CAT_STYLE.get(item['category'], ('Other', 'white'))
            t.add_row(
                f'0x{item["offset"]:08x}',
                Text(label, style=f'bold {color}'),
                Text(item['string'][:120], style='white'),
            )
        body  = t
        count = str(len(strings))

    return Panel(
        body,
        title=f'[bold]Interesting Strings[/bold] ([bold]{count}[/bold])',
        border_style='dim white',
        box=box.ROUNDED,
        padding=(0, 1),
    )


# ── Main entry point ──────────────────────────────────────────────────────────

def run_inspect(
    binary:        str,
    output_json:   bool,
    show_sections: bool,
    show_strings:  bool,
) -> None:
    """Full ELF inspection — called by the 'lure inspect' command."""

    filepath = os.path.realpath(binary)
    path     = Path(filepath)

    if not path.exists():
        console.print(f'[red]Error:[/red] file not found: {filepath}')
        return

    if path.stat().st_size == 0:
        console.print('[red]Error: file is empty.[/red]')
        return

    if not is_elf_file(filepath):
        console.print(f'[red]{NOT_ELF_ERROR}[/red]')
        return

    # ── File metadata (no ELF parsing needed yet) ──────────────────────────────
    st          = path.stat()
    size_bytes  = st.st_size
    md5_hash    = _md5(filepath)
    sha256_hash = _sha256(filepath)
    perms       = stat.filemode(st.st_mode)
    octal       = oct(st.st_mode & 0o777)[2:]
    modified    = datetime.datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d  %H:%M')

    # ── Parse ELF (all reads inside the with-block) ────────────────────────────
    try:
        with open(filepath, 'rb') as f:
            elf = ELFFile(f)

            bits     = elf.elfclass
            arch     = ARCH_MAP.get(elf.header.e_machine, elf.header.e_machine)
            elf_type = TYPE_MAP.get(elf.header.e_type,    elf.header.e_type)
            entry    = elf.header.e_entry

            dynamic  = _is_dynamic(elf)
            libs     = _get_libraries(elf)
            nx       = _check_nx(elf)
            pie      = _check_pie(elf)
            relro    = _check_relro(elf)
            canary   = _check_canary(elf)
            stripped = _check_stripped(elf)
            endian   = 'Little Endian' if elf.little_endian else 'Big Endian'
            upx      = _check_upx(elf, filepath)
            sections = _get_sections_data(elf) if show_sections else []

    except Exception:
        console.print(f'[red]{NOT_ELF_ERROR}[/red]')
        return

    strings = _extract_strings(filepath) if show_strings else []

    # ── JSON output ────────────────────────────────────────────────────────────
    if output_json:
        console.print_json(json.dumps({
            'file': {
                'path':        filepath,
                'name':        path.name,
                'size_bytes':  size_bytes,
                'permissions': f'{perms} ({octal})',
                'modified':    modified,
                'md5':         md5_hash,
                'sha256':      sha256_hash,
            },
            'elf': {
                'bits':    bits,
                'arch':    arch,
                'type':    elf_type,
                'entry':   hex(entry),
                'endian':  endian,
                'dynamic': dynamic,
            },
            'security': {
                'nx':       nx,
                'pie':      pie,
                'relro':    relro,
                'canary':   canary,
                'stripped': stripped,
                'upx':      upx,
            },
            'libraries': libs,
            'sections':  sections,
            'strings':   strings,
        }, indent=2))
        return

    # ── Terminal output ────────────────────────────────────────────────────────

    console.print(Panel.fit(
        f'[bold cyan]INSPECT[/bold cyan]  [bold white]{filepath}[/bold white]',
        border_style='cyan',
        box=box.ROUNDED,
    ))

    if upx:
        console.print(Panel(
            Text.assemble(
                ('\n  ⚠   UPX PACKED BINARY DETECTED   ⚠\n\n', 'bold red'),
                ('  Static analysis results will be INCOMPLETE.\n', 'yellow'),
                ('  Sections, imports, and strings may be hidden.\n', 'yellow'),
                ('  Unpack first:  ', 'dim'),
                (f'upx -d {path.name}\n', 'bold white'),
            ),
            border_style='red',
            box=box.HEAVY,
            padding=(0, 1),
        ))

    # ── Side-by-side panels — 7 rows each ─────────────────────────────────────
    addr_fmt  = '0x{:016x}' if bits == 64 else '0x{:08x}'
    entry_str = addr_fmt.format(entry)

    file_rows = [
        ('Name',        path.name),
        ('Path',        str(path.parent)),
        ('Size',        f'{size_bytes / 1024:.1f} KB  ({size_bytes:,} bytes)'),
        ('Permissions', Text(f'{perms}  ({octal})', style='green')),
        ('Modified',    modified),
        ('MD5',         Text(md5_hash, style='dim')),
        ('SHA-256',     Text(sha256_hash[:40] + '...', style='dim')),
    ]
    elf_rows = [
        ('Class',        f'ELF{bits}'),
        ('Architecture', arch),
        ('Endianness',   endian),
        ('Type',         elf_type),
        ('Entry Point',  Text(entry_str, style='bold green')),
        ('Linking',
         Text('Dynamic', style='cyan') if dynamic else Text('Static', style='yellow')),
        ('Stripped',
         _warn_txt('Yes (debug symbols absent)') if stripped
         else _ok('No   (symbols present)')),
    ]

    side = Table(
        box=None, show_header=False, show_edge=False,
        padding=0, expand=True,
    )
    side.add_column(ratio=1)
    side.add_column(ratio=1)
    side.add_row(
        _kv_panel(file_rows, 'File'),
        _kv_panel(elf_rows,  'ELF Header'),
    )
    console.print(side)

    console.print(_security_panel(nx, pie, relro, canary))
    console.print(_libraries_panel(libs))

    if show_sections:
        console.print(_sections_panel(sections, bits))
    if show_strings:
        console.print(_strings_panel(strings))

    mitigations = sum([nx, pie, canary, relro != 'none'])
    if mitigations == 4:
        rating = Text('● Hardened',   style='bold green')
    elif mitigations >= 2:
        rating = Text('◑ Moderate',   style='bold yellow')
    else:
        rating = Text('○ Vulnerable', style='bold red')

    console.print(Panel(
        Text.assemble(
            ('Security Rating  ', 'dim'),
            rating,
            (f'   ({mitigations}/4 mitigations active)', 'dim'),
        ),
        border_style='dim',
        box=box.ROUNDED,
        padding=(0, 1),
    ))
    console.print()
