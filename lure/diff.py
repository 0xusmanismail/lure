# FILE: lure/diff.py
"""
Report comparison engine for 'lure diff'.
Compares two JSON reports produced by 'lure run --save' and shows
what changed between the two runs.
"""

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


# ── Loading ───────────────────────────────────────────────────────────────────

def _load_report(path):
    """Load and parse a JSON report. Returns (data, error_message)."""
    p = Path(path)
    if not p.exists():
        return None, f'file not found: {path}'
    try:
        with open(p, 'r') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        return None, f'invalid JSON report — {exc}'
    return data, None


# ── Panels ────────────────────────────────────────────────────────────────────

def _list_panel(title, items, style):
    if not items:
        body = Text('  (none)', style='dim italic')
    else:
        body = Text()
        for item in items:
            body.append(f'  • {item}\n', style=style)
    return Panel(
        body,
        title=f'[bold]{title}[/bold] ({len(items)})',
        border_style='dim white',
        box=box.ROUNDED,
        padding=(0, 1),
    )


# ── Main entry point ──────────────────────────────────────────────────────────

def run_diff(report1_path, report2_path):
    """Full report comparison — called by the 'lure diff' command."""

    r1, err1 = _load_report(report1_path)
    if err1:
        console.print(f'[red]Error:[/red] {report1_path} — {err1}')
        return

    r2, err2 = _load_report(report2_path)
    if err2:
        console.print(f'[red]Error:[/red] {report2_path} — {err2}')
        return

    console.print(Panel.fit(
        f'[bold magenta]DIFF[/bold magenta]  '
        f'[white]{Path(report1_path).name}[/white] '
        f'[dim]→[/dim] [white]{Path(report2_path).name}[/white]',
        border_style='magenta',
        box=box.ROUNDED,
    ))

    # ── Files ──────────────────────────────────────────────────────────────────
    files1 = set(r1.get('files_accessed', []))
    files2 = set(r2.get('files_accessed', []))
    new_files     = sorted(files2 - files1)
    removed_files = sorted(files1 - files2)

    console.print(_list_panel('New Files',     new_files,     'green'))
    console.print(_list_panel('Removed Files', removed_files, 'red'))

    # ── Network ────────────────────────────────────────────────────────────────
    net1 = {(n['ip'], n['port']) for n in r1.get('network_attempts', [])}
    net2 = {(n['ip'], n['port']) for n in r2.get('network_attempts', [])}
    new_conns = sorted(f'{ip}:{port}' for ip, port in (net2 - net1))

    console.print(_list_panel('New Connections', new_conns, 'cyan'))

    # ── Verdict ────────────────────────────────────────────────────────────────
    verdict1 = r1.get('verdict', '?')
    verdict2 = r2.get('verdict', '?')

    if verdict1 != verdict2:
        verdict_text = Text.assemble(
            (verdict1, 'bold'), ('  →  ', 'dim'), (verdict2, 'bold'),
        )
    else:
        verdict_text = Text.assemble((verdict2, 'bold'), ('  (unchanged)', 'dim'))

    console.print(Panel(
        verdict_text,
        title='[bold]Verdict[/bold]',
        border_style='dim white',
        box=box.ROUNDED,
        padding=(0, 1),
    ))

    # ── Syscalls ───────────────────────────────────────────────────────────────
    sc1   = r1.get('syscall_total', 0)
    sc2   = r2.get('syscall_total', 0)
    delta = sc2 - sc1
    sign  = '+' if delta >= 0 else ''

    console.print(Panel(
        Text(f'  {sign}{delta} syscalls  ({sc1} → {sc2})'),
        title='[bold]Syscall Count[/bold]',
        border_style='dim white',
        box=box.ROUNDED,
        padding=(0, 1),
    ))
    console.print()
