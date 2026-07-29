# Contributing to Lure

Thanks for your interest in improving Lure — a local, zero-upload
ELF binary analysis tool. Contributions are very welcome.

## Setup

```bash
git clone https://github.com/0xusmanismail/lure.git
cd lure
pip install -e . --break-system-packages
```

`--break-system-packages` is required on Arch/recent Debian/Ubuntu
due to PEP 668. Requires `strace` (`unshare` ships with `util-linux`).

## Running it locally

```bash
lure inspect /bin/ls
lure run /bin/ls --save
lure diff ~/.lure/reports/a.json ~/.lure/reports/b.json
```

Test changes against a few real binaries (static, dynamic, one that
touches a file or the network) to make sure verdicts still hold up.

## Where help is needed
- Edge-case handling for malformed/unusual binaries
- Verdict heuristic tuning (fewer false positives on legit tools)
- Support for architectures beyond x86_64
- Packaging (so `pip install -e .` isn't required)
- Tests — there currently are none

## Opening an issue

Open an issue on GitHub with the command you ran, what you expected,
and what happened instead — a saved `.json` report or `--json`
inspect output helps a lot.
