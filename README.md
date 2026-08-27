# lure

> Local Linux binary analysis. Zero cloud. Zero root. Zero cost.

**lure** is a local Linux ELF analysis and sandboxing tool for security researchers, reverse engineers, and CTF players.

It provides three complementary workflows:

- **Static analysis** with `lure inspect` — inspect an ELF without executing it.
- **Behavioral analysis** with `lure run` — execute an ELF under Linux namespaces, `strace`, and a seccomp-bpf policy, then produce a readable report.
- **Report comparison** with `lure diff` — compare two saved behavioral reports.

Everything is processed locally. No sample or report is uploaded to a cloud service.

> **Alpha software:** lure is still under active development. Test it in an environment appropriate for security research and do not treat this sandbox as a replacement for a dedicated malware-analysis VM.

## Features

### Static ELF inspection

`lure inspect` reports:

- ELF architecture and type
- Endianness
- File size
- MD5 and SHA-256 hashes
- NX
- PIE
- RELRO status
- Stack-canary presence
- Linked libraries
- ELF section headers with `--sections`
- Printable ASCII strings with `--strings`

The inspected file is not executed.

### Sandboxed execution

`lure run` combines:

- Linux user namespaces
- A network namespace
- A mount namespace
- A PID namespace
- `strace` syscall tracing
- A seccomp-bpf syscall policy applied to the guest
- A minimal sandbox filesystem
- A timeout (30 seconds by default)
- Optional network access with `--allow-net`
- Optional raw `strace` output
- Optional TXT + JSON reports
- Best-effort cgroups v2 resource limits when available

Network access is blocked by default.

The seccomp policy uses an allow-list, an explicit deny-list, a default `EPERM` action, an architecture check, and a `socket()` family check. The exact syscall policy is an implementation detail and may change between releases.

### Report comparison

`lure diff` compares two JSON reports and shows:

- New files
- Removed files
- New network connections
- Verdict changes
- Syscall-count changes

## Installation

### From PyPI

The package name on PyPI is **`lure-analyze`**, while the installed command is **`lure`**.

```bash
python -m pip install lure-analyze
```

Then verify:

```bash
lure --version
```

For the `v0.6.0` release:

```text
lure, version 0.6.0
```

### From source

```bash
git clone https://github.com/0xusmanismail/lure.git
cd lure
python -m pip install -e .
```

If your Linux distribution enforces PEP 668 for the system Python, use an appropriate virtual environment or your distribution's recommended packaging workflow rather than forcing installation into the system interpreter.

### Development dependencies

```bash
python -m pip install -e ".[dev]"
```

## System requirements

- Linux
- Python 3.9+
- `strace`
- `unshare` (provided by `util-linux` on common Linux distributions)

Install the required system tools with your distribution's package manager.

### Arch Linux

```bash
sudo pacman -S strace util-linux
```

### Debian / Ubuntu / Kali

```bash
sudo apt install strace util-linux
```

### Fedora

```bash
sudo dnf install strace util-linux
```

## Quick start

### Inspect an ELF

```bash
lure inspect /bin/ls
```

JSON output:

```bash
lure inspect --json /bin/ls
```

Include section headers:

```bash
lure inspect --sections /bin/ls
```

Extract printable strings:

```bash
lure inspect --strings /bin/ls
```

Combine options:

```bash
lure inspect --json --sections --strings /bin/ls
```

### Run an ELF

```bash
lure run /bin/ls
```

Set a timeout:

```bash
lure run --timeout 10 ./sample
```

Pass arguments to the guest:

```bash
lure run --args '--help' ./sample
```

Allow outbound network access:

```bash
lure run --allow-net ./sample
```

> Network access is disabled by default. Only enable it when you understand the risk and your analysis environment permits it.

Save the raw `strace` log:

```bash
lure run --out trace.log ./sample
```

Save the full report:

```bash
lure run --save ./sample
```

Saved reports are written under:

```text
~/.lure/reports/
```

A saved run produces a human-readable `.txt` transcript and a structured `.json` report.

### Compare reports

```bash
lure diff report1.json report2.json
```

For example:

```bash
lure diff ~/.lure/reports/run-a.json ~/.lure/reports/run-b.json
```

## Isolation model

The execution path is designed as **layered isolation**, not as a single security boundary.

### Normal path

The runner uses:

1. A user namespace
2. A network namespace
3. A mount namespace
4. A PID namespace
5. A minimal sandbox filesystem
6. `strace` for observation
7. A seccomp-bpf filter for the guest process
8. Best-effort cgroups v2 resource limits when the host permits them

The guest is not given host root privileges. The sandbox uses read-only filesystem mounts where appropriate.

### Seccomp

The seccomp policy is deliberately separate from `strace`: the filter is installed for the guest wrapper and guest binary so tracing can continue.

The policy includes:

- an allow-list
- an explicit deny-list that produces `SIGSYS`
- a default `EPERM` action
- an architecture check
- a `socket()` family check

The current implementation contains 178 allowed syscall numbers plus a separate explicit deny-list. This is an implementation detail and may change between releases.

### Resource limits

When cgroups v2 are available and delegated for use, lure attempts to apply:

- **512 MiB** memory maximum
- **64** processes maximum
- swap disabled

These limits are best-effort. If cgroups are unavailable, the run continues and the report records that resource limits were not active.

### Fallback behavior

If parts of the isolation stack are unavailable, lure can fall back to a weaker configuration rather than claiming full isolation.

In particular, the runner can fall back when:

- mount-namespace setup is unavailable, or
- the seccomp wrapper/filter cannot be used.

The reported isolation mode should be checked for security-sensitive analysis. When stronger containment is required, use an external isolation boundary such as a dedicated VM.

## CLI reference

### `lure`

```text
lure [OPTIONS] COMMAND [ARGS]...
```

### `lure inspect`

```text
lure inspect [OPTIONS] BINARY
```

Options:

```text
--json
--sections
--strings
```

### `lure run`

```text
lure run [OPTIONS] BINARY
```

Options:

```text
-t, --timeout SECS
--args 'ARG ...'
--allow-net
--out FILE
--save
```

### `lure diff`

```text
lure diff REPORT1 REPORT2
```

## Reports

A saved JSON report contains structured data including:

```text
binary
full_path
timestamp
runtime_seconds
exit_code
isolation
resource_limits
verdict
verdict_triggers
files_accessed
network_attempts
processes_spawned
syscall_total
```

The behavioral verdict is one of:

```text
CLEAN
SUSPICIOUS
DANGEROUS
```

The JSON report is intended to make runs easy to archive, inspect, and compare.

## Error handling

`lure inspect` rejects invalid or non-ELF input and exits non-zero on validation failures.

`lure run` validates that the target exists, is executable, is non-empty, and is an ELF before attempting execution. It also requires `strace`.

The test suite covers inspection, execution, diffing, flags, timeouts, report schemas, and edge cases.

## Development

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the test suite:

```bash
python -m pytest
```

The project uses pytest for automated tests.

When changing sandbox behavior, update the tests and documentation together. Security-sensitive changes should be tested on the Linux environments they are intended to support.

## Project layout

```text
lure/
├── lure/
│   ├── main.py
│   ├── inspector.py
│   ├── runner.py
│   └── diff.py
├── tests/
│   ├── test_inspect.py
│   ├── test_run.py
│   ├── test_diff.py
│   └── test_edge_cases.py
├── assets/
├── pyproject.toml
├── requirements.txt
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

## Versioning

The `v0.6.0` release corresponds to package version `0.6.0`.

The Python package is published as:

```text
lure-analyze
```

The CLI command is:

```text
lure
```

## Limitations

- Linux-only.
- The sandbox depends on kernel and namespace capabilities available on the host.
- Isolation can fall back when required kernel features or the seccomp wrapper are unavailable.
- Resource limits depend on cgroups v2 availability and delegation.
- `lure inspect` currently targets ELF files.
- The project is Alpha software and should not be considered a complete malware-analysis environment.

## Contributing

Issues and pull requests are welcome.

For development setup and contribution guidelines, see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

MIT — see [`LICENSE`](LICENSE).

## Links

- [Repository](https://github.com/0xusmanismail/lure)
- [Issues](https://github.com/0xusmanismail/lure/issues)
- [PyPI](https://pypi.org/project/lure-analyze/)
