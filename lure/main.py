# FILE: lure/main.py
"""
Lure CLI — entry point and subcommand definitions.
"""

import click
from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()

BANNER = (
    '\n'
    '  [bold cyan]lure[/bold cyan]\n'
    '  [dim]----------------------------------------------[/dim]\n'
    '  [dim]local binary analysis · zero cloud · zero root[/dim]\n'
)


def print_banner():
    console.print(BANNER)


CONTEXT_SETTINGS = dict(help_option_names=['--help', '-h'])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version='0.1.0', prog_name='lure')
def cli():
    """
    \b
    Lure — local Linux binary analysis tool.

    \b
    Runs untrusted ELF binaries and shows exactly what they did.
    Files accessed. Network attempts. Processes spawned.
    Zero cloud upload. Zero root. Zero cost.
    """


# ── inspect ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument('binary', type=click.Path(exists=True, readable=True))
@click.option('--json', 'output_json', is_flag=True, default=False,
              help='Emit results as JSON instead of a rich table.')
@click.option('--sections', 'show_sections', is_flag=True, default=False,
              help='Include the full ELF section header table.')
@click.option('--strings', 'show_strings', is_flag=True, default=False,
              help='Print interesting printable strings found in the binary.')
def inspect(binary, output_json, show_sections, show_strings):
    """Parse and inspect an ELF binary without executing it.

    \b
    BINARY  Path to the ELF binary to inspect.

    \b
    Reads ELF headers, architecture, security mitigations, imported
    libraries, and suspicious strings — without executing a single
    byte of code.

    \b
    Examples:
    \b
      lure inspect /bin/ls
      lure inspect ./crackme --sections --strings
      lure inspect ./crackme --json
    """
    from lure.inspector import run_inspect
    if not output_json:
        print_banner()
    run_inspect(binary, output_json, show_sections, show_strings)


# ── run ────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument('binary', type=click.Path(exists=True, readable=True))
@click.option('--timeout', '-t', default=30, show_default=True, metavar='SECS',
              help='Maximum wall-clock seconds to let the binary run.')
@click.option('--args', 'binary_args', default='', metavar="'ARG ...'",
              help='Arguments to pass to the binary (quote the whole string).')
@click.option('--allow-net', is_flag=True, default=False,
              help='Allow outbound network access inside the sandbox (off by default).')
@click.option('--out', 'trace_out', default=None, metavar='FILE',
              type=click.Path(dir_okay=False),
              help="Save the raw strace log to FILE for later use with 'lure report'.")
@click.option('--save', 'save_report', is_flag=True, default=False,
              help='Save the full rendered report to ~/.lure/reports/<binary>_<timestamp>.txt')
def run(binary, timeout, binary_args, allow_net, trace_out, save_report):
    """Execute a binary in an isolated sandbox and capture its behaviour.

    \b
    BINARY  Path to the ELF binary to execute.

    \b
    Uses strace + Linux namespaces (unshare) for lightweight isolation.
    Captures every syscall, streams a live event feed, then renders a
    full six-section report. Network is blocked by default. No root required.

    \b
    Examples:
    \b
      lure run /bin/ls
      lure run /bin/ls --save
      lure run ./suspicious --timeout 10
      lure run ./suspicious --args '-v --port 9999'
      lure run ./suspicious --out run.trace
      lure run ./suspicious --allow-net --out run.trace
    """
    from lure.runner import run_binary
    print_banner()
    run_binary(binary, timeout, binary_args, allow_net, trace_out, save_report)


# ── report ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument('trace_file', type=click.Path(exists=True, readable=True))
@click.option('--format', 'fmt',
              type=click.Choice(['terminal', 'json', 'html'], case_sensitive=False),
              default='terminal', show_default=True, help='Output format.')
@click.option('--filter', 'event_filter',
              type=click.Choice(['all', 'files', 'network', 'processes', 'signals'],
                                case_sensitive=False),
              default='all', show_default=True, help='Show only this event category.')
@click.option('--out', 'output_file', default=None, metavar='FILE',
              type=click.Path(dir_okay=False),
              help='Write the report to FILE (required for --format json/html).')
def report(trace_file, fmt, event_filter, output_file):
    """Render a human-readable report from a saved strace trace file.

    \b
    TRACE_FILE  Path to a .trace file produced by 'lure run --out'.

    \b
    Examples:
    \b
      lure report run.trace
      lure report run.trace --filter network
      lure report run.trace --format json --out report.json
      lure report run.trace --format html  --out report.html
    """
    print_banner()
    console.print(Panel.fit(
        f'[bold green]REPORT[/bold green]  [white]{trace_file}[/white]\n'
        f'  [dim]format[/dim] {fmt}   [dim]filter[/dim] {event_filter}   '
        f'[dim]out →[/dim] {output_file or "stdout"}',
        border_style='green', box=box.ROUNDED,
    ))
    console.print('  [yellow]→ Report command coming soon.[/yellow]\n')


if __name__ == '__main__':
    cli()
