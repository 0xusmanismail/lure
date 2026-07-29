# FILE: lure/main.py
"""
Lure CLI — entry point and subcommand definitions.
"""

import click
from rich.console import Console

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
@click.version_option(version='0.2.0', prog_name='lure')
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
              help='Save the raw strace log to FILE for later inspection.')
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


# ── diff ───────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument('report1', type=click.Path(exists=True, readable=True))
@click.argument('report2', type=click.Path(exists=True, readable=True))
def diff(report1, report2):
    """Compare two saved JSON reports and show what changed between runs.

    \b
    REPORT1  Path to the earlier .json report (produced by 'lure run --save').
    REPORT2  Path to the later .json report.

    \b
    Examples:
    \b
      lure diff ~/.lure/reports/a.json ~/.lure/reports/b.json
    """
    from lure.diff import run_diff
    print_banner()
    run_diff(report1, report2)


if __name__ == '__main__':
    cli()
