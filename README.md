# portkill (`pk`)

> Inspect first. Kill with intent.

**portkill** is a lightweight, blazing-fast CLI for inspecting and freeing ports on macOS, Linux, and Windows. It shows you exactly *what* is squatting on a port before you decide what to do it —[...]

[![Crates.io](https://img.shields.io/crates/v/portkill-cli.svg)](https://crates.io/crates/portkill-cli)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/unknownman/portKiller/release.yml?branch=main)](https://github.com/unknownman/portKiller/actions)

## Demo

![portkill demo](./assets/demo.gif)

## Features

- **Inspect first, action second** — running `pk <port>` only *shows* you what's there. Nothing gets killed.
- **Kill with intent** — terminating a process requires an explicit `--kill` / `-k` flag. No accidental carnage.
- **Escalating kill sequence** — sends `SIGTERM`, verifies the port actually freed, and escalates to `SIGKILL` only if needed.
- **Force kill** — jump straight to `SIGKILL` with `--force` for the truly stubborn processes.
- **Beautiful, scannable tables** — PID, process name, full command, user, and uptime, rendered with care.
- **JSON output** — `--json` for scripts, `jq`, CI pipelines, and shell completion.
- **Multiple ports & ranges** — `pk 3000 8080 9000-9005` in a single call.
- **Cross-platform** — works identically on macOS, Linux, and Windows.
- **Ridiculously fast** — a single native binary, zero runtime dependencies, built with Rust.

## Why `portkill`?

`lsof -i`, `killport`, and `fkill` have been around for years — and they're all missing the same thing:

| | `portkill` | `lsof -i` | `killport` | `fkill` |
|---|---|---|---|---|
| Is default action **read-only** | ✅ | ✅ | ❌ kills immediately | ✅ (but kills too easily) |
| Explicit kill intent required | ✅ | n/a | ❌ | ⚠️ one keystroke away |
| Escalates SIGTERM → SIGKILL | ✅ | ❌ | ❌ | ❌ |
| Verifies the port is actually free | ✅ | ❌ | ❌ | ❌ |
| JSON for scripting | ✅ | ❌ | ❌ | ❌ |
| Port ranges (`9000-9005`) | ✅ | ❌ | ❌ | ❌ |
| Works on macOS/Linux/Windows | ✅ | ⚠️ | ⚠️ | ⚠️ |

`lsof` is a wonderful firehose — but it dumps a wall of raw sockets at you. `killport` and `fkill` solve the "kill" part while dancing dangerously close to destroying whatever you were incubatin[...]

**portkill's philosophy:** a port-freedom tool should be boring about killing things and delightful about showing you what's going on.

## Installation

### Cargo (recommended for Rusta-lovers)

```bash
cargo install portkill
```

### Pre-compiled binaries

Grab the latest release for your platform from the [GitHub Releases](https://github.com/unknownman/portKiller/releases) page. Each release bundles checksums and universal (fat) binaries for macOS, per[...]

Quick macOS/Linux one-liner:

```bash
# Replace VERSION with the latest release tag
curl -fsSL https://github.com/unknownman/portKiller/releases/latest/download/pk-$(uname -s)-$(uname -m).tar.gz \
  | tar -xz -C /usr/local/bin
```

Alternatively, verify the binary after any install:

```bash
pk --version
```

## Usage

> 💡 **`pk` inspects by default.** To actually terminate a process you must pass `--kill` (or `--force`). There is no world where `pk 3000` kills anything.

### Inspect a port (default behavior)

```bash
pk 3000
```

```text
Port 3000 — in use

PORT   PID    PROCESS  COMMAND           USER      UPTIME
3000   44122  node     node server.js    alijoder  1h 2m 13s
3000   51204  vite     vite --port 3000  alijoder  12m 44s

2 process(es) on port 3000; inspect only — run `pk --kill 3000` to free them.
```

Empty port?

```bash
pk 3000
```

```text
✨ Port 3000 is free.
```

### Kill a port

```bash
pk --kill 8080
# or, shorter:
pk -k 8080
```

`pk --kill` shows you what it's about to do, asks for confirmation, then sends `SIGTERM` and **verifies** the port was released. If the process ignores `SIGTERM`, portkill escalates to `SIGKILL` [...]

```text
$ pk --kill 8080
Port 8080 — in use

PORT   PID    PROCESS  COMMAND       USER      UPTIME
8080   53811  rails    rails server  alijoder  3h 11m 5s

Proceed with termination? [y/N] y

Port 8080 — in use

PORT   PID    PROCESS  COMMAND       USER      UPTIME     STATUS
8080   53811  rails    rails server  alijoder  3h 11m 5s  Terminated (SIGTERM)

✓ Port 8080 is now free.
```

The `STATUS` column records exactly how each process ended — `Terminated (SIGTERM)` for a graceful kill, or `Killed (SIGKILL)` if it had to be escalated. Decline the prompt and nothing is touch[...]

### Force kill (skip SIGTERM)

```bash
pk --force 5432
```

`--force` implies kill intent and jumps straight to `SIGKILL` (no confirmation prompt) — for processes that never listen to polite signals. Use it on Windows (where `SIGTERM` behaves differentl[...]

```text
$ pk --force 5432

Port 5432 — in use

PORT   PID   PROCESS   COMMAND                        USER      UPTIME     STATUS
5432   4011  postgres  postgres -D /usr/local/var/pg  alijoder  2d 4h 13m  Killed (SIGKILL)

✓ Port 5432 is now free.
```

### Multiple ports & ranges

```bash
pk 3000 8080 9000-9005
```

Inspects each port (and every port in the range), rendering one table per port:

```bash
pk --kill 3000 8080 9000-9005
```

Kills each. Ranges and lists combine freely, and every port gets the same inspect-first table + verification.

### JSON output (for scripts, `jq`, CI)

```bash
pk --json 3000
```

```json
{
  "ports": [
    {
      "port": 3000,
      "protocol": "tcp",
      "free": false,
      "error": null,
      "processes": [
        {
          "pid": 44122,
          "name": "node",
          "command": "node server.js",
          "user": "alijoder",
          "uptime_seconds": 3724,
          "cwd": null,
          "status": "info",
          "signal": null,
          "error": null
        }
      ],
      "killed": false,
      "kill_signal": null
    }
  ]
}
```

Pipe it anywhere:

```bash
pk --json 3000 | jq '.ports[].processes[].name'   # → "node"
pk --json 8000 | jq -c 'select(.ports[].free == false)'  # fail-safe in CI
```

> **Note:** On Windows, `kill_signal` reports `"SIGTERM"` or `"SIGKILL"` as logical intents, even though both map directly to `TerminateProcess` under the hood.

`--json` stays machine-stable: field names are guaranteed, unknown fields are never added in patch releases, and `killed`/`kill_signal` only describe the current invocation (they're `false`/`null[...]

### Full CLI reference

```text
pk [OPTIONS] <PORT> [PORT...]

ARGS:
  <PORT>...   One or more ports, or ranges like 9000-9005

OPTIONS:
  -k, --kill      Gracefully kill processes (SIGTERM, verify, escalate to SIGKILL)
  -f, --force     Skip SIGTERM; go straight to SIGKILL. Implies --kill (alias -y)
      --dry-run   Show what --kill would do, without sending any signals
      --json      Output machine-readable JSON
  -h, --help      Print help
  -V, --version   Print version
```

## Safety & Reliability

portkill treats "I freed a port" as a **claim that must be verified**, not an assumption.

1. **Inspect-only default** — no kill path is reachable without an explicit flag.
2. **SIGTERM first** — a graceful shutdown gives applications one chance to clean up (flush, close sockets, save state).
3. **Verification loop** — after signaling, portkill re-checks the port. If it's still bound, it escalates to `SIGKILL` and verifies again.
4. **Cross-platform honest** — on Windows, termination uses `TerminateProcess` semantics (no side-effect-free `SIGTERM` available); `--force` is the recommended path there. Crash-only signals a[...]
5. **Evidentiary output** — every kill logs *what* was sent, to *which* PID, and the final free/not-free verdict so you can trust the result.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success — all ports inspected and/or freed as requested |
| `1` | Nothing to do — none of the requested ports were in use |
| `2` | Failure — a kill failed (permission denied, escalation exhausted, port still occupied) |
| `3` | Usage error or internal error |

### FAQ

**"Shouldn't it be named `killport`?"** — No. Naming it for the safe default reinforces the philosophy: *showing* is the product, *killing* is an explicit choice.

**"Why `--force` on Windows?"** — Windows has no POSIX `SIGTERM`. A "graceful" signal would be a no-op illusion; `--force` is fast, real, and honest.

**"Can I use this in CI?"** — Yes. `pk --json 8080 | jq -e '.ports[0].free'` fails the pipeline when a port is occupied.

**"What about privileged ports (e.g. `80`)"?** — Inspecting is always possible. Killing a root-owned process may require appropriate privileges; portkill will report the exact reason if it can'[...]

## Contributing

Contributions are warmly welcomed — bugs, docs, cross-platform edge cases, and UI polish all count. Please open an issue first for any non-trivial change.

- **Code of conduct:** Be excellent to each other.
- **Development:** `cargo build`, `cargo test`, `cargo clippy -- -D warnings`.
- **Style:** `rustfmt` default, commit messages in conventional format.

## License

[MIT](LICENSE) © portkill contributors.
