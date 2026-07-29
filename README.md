# lure

> Local Linux binary analysis. Zero cloud. Zero root. Zero cost.

⚠️ **Early development (v0.2.0).** Core features (`inspect`, `run`,
`diff`) work end to end on x86_64 Linux. This is a young project —
expect rough edges, limited error handling on unusual inputs, and
missing features. Bug reports, feedback, and contributions are very
welcome.

![Lure dangerous verdict](assets/dangerous-3.png)

## What it does

Lure runs an untrusted Linux binary inside an isolated sandbox
(Linux namespaces + strace) and tells you exactly what it did —
which files it touched, what network connections it tried, what
processes it spawned — then gives you a plain verdict:
**CLEAN**, **SUSPICIOUS**, or **DANGEROUS**.

Everything happens on your machine. Nothing is uploaded anywhere.

## Why

- **Privacy** — sensitive or client samples never leave your machine
- **Zero setup** — no VM, no Docker, no Cuckoo install process
- **Readable** — structured reports instead of raw strace noise
- **Free** — MIT licensed, runs on tools already on Kali Linux

## Install

```bash
git clone https://github.com/0xusmanismail/lure.git
cd lure
pip install -e . --break-system-packages
```

The `--break-system-packages` flag is required on Arch Linux and on
recent Debian/Ubuntu releases, which restrict installing into the
system Python environment by default (PEP 668).

Requires `strace` and `unshare` installed.

## Usage

### Inspect a binary

```bash
lure inspect /bin/ls
```

Reads ELF headers, architecture, security mitigations, linked libraries, and file hashes — without executing a single byte of code.

![inspect](assets/inspect-1.png)

### Run a binary in the sandbox

```bash
lure run ./suspicious_binary
```

Live feed of file access, network attempts, and spawned processes, followed by a full behavioral report.

![run live feed](assets/run-1.png)

![run report](assets/run-2.png)

### Catch suspicious behavior

```bash
lure run ./demo_dangerous
```

Sensitive file access combined with network activity trips a DANGEROUS verdict, with the exact triggers listed.

![dangerous analysis](assets/dangerous-1.png)

![dangerous report](assets/dangerous-2.png)

![dangerous verdict](assets/dangerous-3.png)

### Compare two runs with lure diff

```bash
lure run --save /bin/ls
lure run --save /bin/echo
lure diff report1.json report2.json
```

Shows new/removed files, new connections, verdict changes, and syscall count differences between two saved runs.

![diff output](assets/diff-1.png)

### Save a report

```bash
lure run --save ./binary
```

Saves the full report to `~/.lure/reports/` as both a plain-text `.txt` file and a structured `.json` file.

## Status & Roadmap

**Working now:**
- ELF inspection with security mitigation detection
- Sandboxed execution via `unshare` + `strace`
- Live event feed during execution
- Full behavioral report with CLEAN/SUSPICIOUS/DANGEROUS verdict
- Verdict shows exact triggering files and IPs
- Report saving (plain text + JSON)
- Report comparison via `lure diff`
- Non-ELF file detection with clean error messages
- Works on Arch Linux, Kali, Debian, Ubuntu

**Planned:**
- Demo GIF showing live execution
- PyPI package (`pip install lure-analyze`)
- Packaged releases

## License

MIT — see [LICENSE](LICENSE)
