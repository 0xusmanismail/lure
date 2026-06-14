# lure

> Local Linux binary analysis. Zero cloud. Zero root. Zero cost.

⚠️ **Early development (v0.1).** Core features (`inspect`, `run`)
work end to end on x86_64 Linux. This is a young project — expect
rough edges, limited error handling on unusual inputs, and missing
features. Bug reports, feedback, and contributions are very welcome.

![Lure run demo](assets/run-1.png)

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
pip install -e .
```

Requires `strace` and `unshare` (included on Kali/Debian by default).

## Usage

### Inspect a binary

```bash
lure inspect /bin/ls
```

Reads ELF headers, architecture, security mitigations (NX, PIE,
RELRO, stack canary), linked libraries, file hashes, and packer
detection — without executing a single byte of code.

![Lure inspect part 1](assets/inspect-1.png)
![Lure inspect part 2](assets/inspect-2.png)

### Run a binary in the sandbox

```bash
lure run /bin/ls
```

Live feed of file access, network attempts, and spawned processes
during execution, followed by a full report: execution summary,
files accessed, network activity, process tree, syscall breakdown,
and a CLEAN / SUSPICIOUS / DANGEROUS verdict.

![Lure run part 1](assets/run-1.png)
![Lure run part 2](assets/run-2.png)
![Lure run part 3](assets/run-3.png)

### Save the report

```bash
lure run --save /bin/ls
```

Saves the full report to `~/.lure/reports/`.

## Status & Roadmap

This is a v0.1 release built and tested on Kali Linux (x86_64).

**Working now:**
- ELF inspection with security mitigation detection
- Sandboxed execution via `unshare` + `strace`
- Live event feed during execution
- Full behavioral report with verdict
- Report saving

**Planned:**
- Better edge-case handling (invalid binaries, missing args, etc.)
- Report comparison (`lure diff`)
- Refined verdict heuristics
- Packaged releases (no manual `pip install -e .`)

Issues and pull requests are welcome — this project is actively
developed.

## License

MIT — see [LICENSE](LICENSE)
