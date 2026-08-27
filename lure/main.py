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


class OrderedGroup(click.Group):
    """Lists subcommands in the order they were defined, not alphabetically."""
    def list_commands(self, ctx):
        return list(self.commands)


@click.group(cls=OrderedGroup, context_settings=CONTEXT_SETTINGS)
@click.version_option(
    version='0.6.0', prog_name='lure', help='Show version and exit.'
)
def cli():
    """
    \b
    Lure — local Linux binary analysis.
    Zero cloud. Zero root. Zero cost.
    """


# ── inspect ────────────────────────────────────────────────────────────────────

@cli.command(short_help='Analyse an ELF binary without running it.')
@click.argument('binary', type=click.Path())
@click.option('--json', 'output_json', is_flag=True, default=False,
              help='Emit results as JSON instead of a rich table.')
@click.option('--sections', 'show_sections', is_flag=True, default=False,
              help='Include the full ELF section header table.')
@click.option('--strings', 'show_strings', is_flag=True, default=False,
              help='Print interesting printable strings found in the binary.')
def inspect(binary, output_json, show_sections, show_strings):
    """Analyse an ELF binary without running it.

    \b
    BINARY  Path to the ELF binary to inspect.

    \b
    Reads ELF headers, architecture, security mitigations, linked
    libraries, and file hashes — without executing a single byte
    of code.

    \b
    Example: lure inspect /bin/ls
    """
    from lure.inspector import run_inspect
    if not output_json:
        print_banner()
    run_inspect(binary, output_json, show_sections, show_strings)


# ── run ────────────────────────────────────────────────────────────────────────

@cli.command(short_help='Execute a binary in an isolated sandbox.')
@click.argument('binary', type=click.Path())
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
              help='Save the full report to ~/.lure/reports/ as both .txt and .json')
def run(binary, timeout, binary_args, allow_net, trace_out, save_report):
    """Execute a binary in an isolated sandbox.

    \b
    BINARY  Path to the ELF binary to execute.

    \b
    Uses strace + Linux namespaces (unshare) for lightweight isolation.
    Captures every syscall, streams a live event feed, then renders a
    full behavioral report. Network is blocked by default. No root required.

    \b
    Example: lure run --save ./suspicious_binary
    """
    from lure.runner import run_binary
    print_banner()
    run_binary(binary, timeout, binary_args, allow_net, trace_out, save_report)


# ── diff ───────────────────────────────────────────────────────────────────────

@cli.command(short_help='Compare two saved execution reports.')
@click.argument('report1', type=click.Path())
@click.argument('report2', type=click.Path())
def diff(report1, report2):
    """Compare two saved execution reports.

    \b
    REPORT1  Path to the earlier .json report (produced by 'lure run --save').
    REPORT2  Path to the later .json report.

    \b
    Example: lure diff report1.json report2.json
    """
    from lure.diff import run_diff
    print_banner()
    run_diff(report1, report2)


if __name__ == '__main__':
    cli()
