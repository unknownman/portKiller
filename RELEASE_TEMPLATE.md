# Release Template — [`portkill` `vX.Y.Z`](https://github.com/OWNER/portkill/releases/tag/vX.Y.Z)

<!--
How to use this template
------------------------
1. Set the exact version in the heading (e.g. portkill `v0.4.2`) and link it to the release tag.
2. Update the changelog sections below. Only keep sections that have entries.
3. Start with a one-line description of what this release is *about* — the emotional, user-facing
   summary. Then follow with changes grouped by the section headings.
4. Each entry: imperative mood, present tense, focused on user value.
   Good:  "pk --json now streams directly to stdout in strict order."
   Avoid: "Refactored the JSON printer internals and fixed some stuff."
5. Paste the release notes into the GitHub Release body. Prepend a short tagline if helpful.
-->

**Summary line** — One sentence: what does this release let users do better?

Full binary checksums are in `SHA256SUMS` and the release artifacts are attached below.

---

<!--
This toggle is only used for the very first release or major restructures. Delete the
"Breaking changes" section on every minor/patch release unless behavior actually changed.
-->

## ⚠ Breaking Changes

- **`<Option>`** — `<what changed, and exactly what the user must do to migrate>`. Example: *`--kill` now requires answering a confirmation prompt for processes with multiple listeners before escalation. To retain the old single-shot behavior, run `pk --force`.*

---

## 🚀 Features

*Focus on UX and capabilities: what can users do now that they couldn't before?*

- **`pk <port>` is now read-only by default** — first full pass at the inspect-first philosophy; a beautiful, colorized table (PID, process, command, user, uptime) with zero risk of accidental kills.
- **Port ranges** — `pk 9000-9005` inspects or kills every port in the range in one call.
- **Multi-port support** — `pk 3000 8080 9000-9005` — list and range arguments in any combination.
- **`--json` output** — stable, scriptable JSON for `jq`, CI pipelines, and shell completion.
- **`--force`** — jump straight to `SIGKILL` for the stubborn ones (also the recommended path on Windows).
- **Windows support** — first-class behavior across macOS, Linux, and Windows.

## 🐛 Bug Fixes

*User-visible fixes. Link an issue/PR where useful: `(#123`).*

- **`(owner)`** — `<what was broken: symptom>`, now `<what happens instead>`. Example: **`( `--json` with a port range would emit `null` for already-free ports; these now consistently report `"free": true`.)`
- **`(** — `pk --kill` on a port with no listener now exits `1` with a clear message instead of panicking “no processes to signal”.
- **`(** — long commands are truncated gracefully in the table instead of overflowing the column width.
- **`(** — uptime now renders correctly across time zones after a system clock change (macOS).

## 🛡️ Safety & Reliability

*Process-killing edge cases, cross-platform quirks, verification improvements. This is the heart
of portkill — call out every behavioral hardening explicitly. Builds trust.*

- **Escalation & verification** — kill sequence is now *always* `SIGTERM` → verify → `SIGKILL` → verify. The port is re-checked after every signal, and the final “✓ free” verdict is only printed from a confirmed observation, never from assumption.
- **Graceful-permissive handling** — a process that exited but left a closed TIME_WAIT socket is reported as effectively free without a spurious re-kill.
- **Windows `TerminateProcess`** — termination is now explicit and honest; `--force` is fast, real, and the recommended path on Windows.
- **Privileged-port diagnostics** — when a kill is denied for lack of privileges, `pk` now prints the exact reason and exits `2` rather than silently claiming success.
- **No double-kills** — a range that overlaps the same PID kills it exactly once.

## 📖 Documentation

*Docs, examples, and onboarding improvements.*

- **New README structure** — demo section, comparison table against `lsof`/`killport`/`fkill`, and an expanded full CLI reference.
- **Added exit-code table** — script authors now know precisely what `0/1/2/3` mean.
- **JSON schema documented** with a stable-field guarantee in the README.
- **Homebrew tap placeholder** — install instructions updated to point at Cargo/pre-built binaries until the tap ships.

---

### Thanks

Shout-outs to first-time contributors and anyone who filed sharp issues:

- @`contributor` — `<what they fixed/added>`

### Install

```bash
cargo install portkill
```

Pre-built binaries and checksums are attached to this release.