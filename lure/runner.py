# FILE: lure/runner.py
"""
Sandbox execution engine for 'lure run'.
Combines strace (syscall capture) with unshare
(user + network namespace isolation, no root required).
"""

import os
import re
import json
import time
import shlex
import shutil
import signal
import tempfile
import datetime
import threading
import subprocess
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

def _render_report(binary_path, exit_code, elapsed, timed_out, events, program_output):
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
    t.add_row('Binary',    Path(binary_path).name)
    t.add_row('Full Path', binary_path)
    t.add_row('Exit Code', exit_display)
    t.add_row('Runtime',   f'{elapsed:.3f}s')
    t.add_row('Syscalls',  Text.assemble(
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

def _save_report(binary_path, exit_code, elapsed, timed_out, events, label, triggers):
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

def _execute(binary_path, timeout, binary_args, allow_net, trace_out, tmp_trace, tmp_output, save):
    """Build command, run it, stream live feed, render report, optionally save."""

    binary_argv = shlex.split(binary_args) if binary_args.strip() else []

    strace_base = [
        'strace',
        '-f',                 # follow forks and threads
        '-tt',                # timestamps: hh:mm:ss.usec
        '-T',                 # time spent inside each syscall
        '-e', 'trace=all',    # capture everything for full syscall counts
        '-o', tmp_trace,
        '--',
    ]

    if not allow_net and shutil.which('unshare'):
        cmd = ['unshare', '--user', '--net', '--'] + strace_base + [binary_path] + binary_argv
        iso = '[green]unshare --user --net[/green]'
    else:
        cmd = strace_base + [binary_path] + binary_argv
        iso = ('[yellow]none  (--allow-net)[/yellow]'
               if allow_net else '[red]unshare not found[/red]')

    net_badge = '[red]BLOCKED[/red]' if not allow_net else '[yellow]ALLOWED[/yellow]'

    # ── Header ─────────────────────────────────────────────────────────────────
    console.print(Panel.fit(
        f'[bold yellow]RUN[/bold yellow]  [bold white]{binary_path}[/bold white]\n'
        f'  [dim]timeout[/dim] {timeout}s   '
        f'[dim]network[/dim] {net_badge}   '
        f'[dim]trace →[/dim] {trace_out or "tmp"}',
        border_style='yellow',
        box=box.ROUNDED,
    ))
    console.print(f'  [dim]Isolation  [/dim]{iso}')
    console.print(f'  [dim]Tracer     [/dim][green]strace -f -tt -T[/green]')
    console.print()

    # ── Launch ─────────────────────────────────────────────────────────────────
    # stdout/stderr are captured to a real file (not subprocess.PIPE) so a
    # chatty binary can never deadlock us by filling an unread pipe buffer.
    # stderr is redirected to the same fd as stdout so the two streams stay
    # in true chronological order, exactly like a shell's `2>&1`.
    start_time = time.time()
    try:
        with open(tmp_output, 'wb') as out_f:
            proc = subprocess.Popen(
                cmd,
                stdout=out_f,
                stderr=subprocess.STDOUT,
            )
    except FileNotFoundError as exc:
        console.print(f'[red]Launch failed:[/red] {exc}')
        return

    # ── Live feed thread ───────────────────────────────────────────────────────
    stop_evt    = threading.Event()
    feed_thread = threading.Thread(
        target=_live_tail,
        args=(tmp_trace, start_time, stop_evt),
        daemon=True,
    )
    feed_thread.start()

    # ── Wait for binary ────────────────────────────────────────────────────────
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True

    elapsed   = time.time() - start_time
    exit_code = proc.returncode

    time.sleep(0.25)
    stop_evt.set()
    feed_thread.join(timeout=3)

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
        binary_path, exit_code, elapsed, timed_out, events, tmp_output
    )

    # ── Save report ───────────────────────────────────────────────────────────
    if save:
        result = _save_report(
            binary_path, exit_code, elapsed, timed_out, events, label, triggers
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
