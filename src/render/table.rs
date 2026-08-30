//! Human-readable table rendering.
//!
//! [`render_table`] turns a slice of [`PortResult`] into one formatted string
//! destined for stdout. It is **pure**: the same input always yields the same
//! output, so it is unit-testable without a PTY, and it makes no OS calls.
//!
//! # Style
//!
//! The look is deliberately minimal in the spirit of `eza`, `bat`, and
//! `ripgrep`: **no box-drawing borders**, just whitespace-aligned columns with
//! colored, bold headers. `comfy-table` does the column measuring/alignment and
//! per-cell ANSI styling; `colored` tints the accent lines around the tables
//! (free-port confirmation, warnings, verdicts). Both libraries only emit ANSI
//! codes when stdout is a terminal, so `pk > file` stays clean and grep-able.

use comfy_table::presets::NOTHING;
use comfy_table::{Attribute, Cell, CellAlignment, Color, Table};

use colored::Colorize;

use super::types::{PortResult, ProcessResult, ProcessStatus, RunMode, SignalKind, TableOptions};

/// Longest acceptable DETAILS cell before the value is elided with `…`.
const DETAILS_MAX_WIDTH: usize = 64;

/// Render the full human-facing document: free-port confirmations, one table
/// per occupied port (grouping every process sharing that port), warning lines
/// for ports that could not be inspected, and mode-specific footers.
pub fn render_table(results: &[PortResult], opts: &TableOptions) -> String {
    let mut out = String::new();
    let mut any_occupied = false;

    for port in results {
        if port.is_error() {
            out.push_str(&render_port_error(port));
        } else if port.is_free() {
            out.push_str(&render_free(port));
        } else {
            any_occupied = true;
            out.push_str(&render_port(port, opts));
        }
    }

    if any_occupied {
        match opts.mode {
            RunMode::DryRun => {
                out.push_str(&"Dry run — no signals were sent.\n".yellow().to_string())
            }
            RunMode::Aborted => out.push_str(
                &"Aborted — no processes were terminated.\n"
                    .yellow()
                    .to_string(),
            ),
            RunMode::Inspect | RunMode::Kill | RunMode::Confirming => {}
        }
    }

    out
}

/// A single occupied port: header line, its table (one row per process), and a
/// verdict line that depends on the invocation mode.
fn render_port(port: &PortResult, opts: &TableOptions) -> String {
    let mut s = format!("Port {} — in use\n", port.port.to_string().cyan().bold());
    s.push_str(&format!("{}\n", build_table(port, opts)));
    s.push_str(&port_verdict(port, opts));
    s.push('\n');
    s
}

fn port_verdict(port: &PortResult, opts: &TableOptions) -> String {
    match opts.mode {
        RunMode::Inspect => {
            let n = port.processes.len();
            format!(
                "{n} process(es) on port {}; inspect only — run `{}` to free them.\n",
                port.port,
                format!("pk --kill {}", port.port).yellow(),
            )
        }
        RunMode::DryRun => format!(
            "Dry run: would terminate {} process(es) on port {}.\n",
            port.processes.len(),
            port.port,
        )
        .yellow()
        .to_string(),
        RunMode::Kill => {
            let failed: Vec<&ProcessResult> = port
                .processes
                .iter()
                .filter(|p| p.status == ProcessStatus::Failed)
                .collect();
            if failed.is_empty() {
                format!(
                    "✓ Port {} is now free.\n",
                    port.port.to_string().green().bold()
                )
            } else {
                let mut out = String::new();
                for failure in failed {
                    let reason = failure
                        .error
                        .as_deref()
                        .unwrap_or("the signal was delivered but the port stayed bound");
                    out.push_str(&format!(
                        "✗ Failed to free port {} (PID {}): {}\n",
                        port.port,
                        failure.pid,
                        reason.red(),
                    ));
                }
                out
            }
        }
        RunMode::Aborted => String::new(),
        // Already in the kill flow: print the table as-is, but skip the
        // "inspect only — run `pk --kill`" hint that would be confusing.
        RunMode::Confirming => String::new(),
    }
}

/// Build (and immediately stringify) the `NOTHING`-preset table for one port.
fn build_table(port: &PortResult, opts: &TableOptions) -> String {
    let mut table = Table::new();
    table.load_style(NOTHING);
    table.set_header(header_cells(opts));
    for process in &port.processes {
        table.add_row(row_cells(port, process, opts.show_status()));
    }
    table.trim_fmt()
}

fn header_cells(opts: &TableOptions) -> Vec<Cell> {
    let mut cells = vec![
        header_cell("PORT", Color::Cyan).set_alignment(CellAlignment::Right),
        header_cell("PID", Color::Yellow).set_alignment(CellAlignment::Right),
        header_cell("PROCESS", Color::Green),
        header_cell("USER", Color::Grey),
        header_cell("DETAILS", Color::Grey),
    ];
    if opts.show_status() {
        cells.push(header_cell("STATUS", Color::White));
    }
    cells
}

fn header_cell(label: &str, color: Color) -> Cell {
    Cell::new(label).fg(color).add_attribute(Attribute::Bold)
}

fn row_cells(port: &PortResult, process: &ProcessResult, show_status: bool) -> Vec<Cell> {
    let mut cells = vec![
        Cell::new(port.port.to_string())
            .fg(Color::Cyan)
            .set_alignment(CellAlignment::Right),
        Cell::new(process.pid.to_string())
            .fg(Color::Yellow)
            .set_alignment(CellAlignment::Right),
        Cell::new(sanitize(&process.name)).fg(Color::Green),
        Cell::new(user_text(process)).fg(Color::Grey),
        Cell::new(details_text(process)).fg(Color::White),
    ];
    if show_status {
        cells.push(status_cell(process));
    }
    cells
}

/// The STATUS cell for a process row. Only ever rendered when an action was
/// taken or simulated (guaranteed by [`TableOptions::show_status`]).
fn status_cell(process: &ProcessResult) -> Cell {
    match process.status {
        ProcessStatus::Info => Cell::new("—").fg(Color::Grey),
        ProcessStatus::DryRun => {
            let signal = process.signal.unwrap_or(SignalKind::Sigterm).name();
            Cell::new(format!("[Dry Run] Would send {signal}")).fg(Color::Yellow)
        }
        ProcessStatus::Terminated => {
            let signal = process.signal.unwrap_or(SignalKind::Sigterm).name();
            Cell::new(format!("Terminated ({signal})")).fg(Color::Green)
        }
        ProcessStatus::Killed => {
            let signal = process.signal.unwrap_or(SignalKind::Sigkill).name();
            Cell::new(format!("Killed ({signal})")).fg(Color::Green)
        }
        ProcessStatus::Failed => Cell::new("Failed")
            .fg(Color::Red)
            .add_attribute(Attribute::Bold),
    }
}

fn user_text(process: &ProcessResult) -> String {
    process
        .user
        .clone()
        .unwrap_or_else(|| "unknown".to_string())
}

/// DETAILS prefers a full command line, falls back to uptime, then CWD — and
/// always stays a single truncated line so the table never wraps.
fn details_text(process: &ProcessResult) -> String {
    if let Some(command) = &process.command {
        return truncate(&sanitize(command), DETAILS_MAX_WIDTH);
    }
    if let Some(secs) = process.uptime_secs {
        return format!("up {}", human_duration(secs));
    }
    if let Some(cwd) = &process.cwd {
        return truncate(&sanitize(cwd), DETAILS_MAX_WIDTH);
    }
    "—".to_string()
}

/// Human-friendly uptime in the README's `1h 2m 13s` shape.
fn human_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let secs = secs % 60;
    match (hours, minutes) {
        (0, 0) => format!("{secs}s"),
        (0, _) => format!("{minutes}m {secs}s"),
        _ => format!("{hours}h {minutes}m {secs}s"),
    }
}

/// Elide strings longer than `max_chars` with a `…`.
fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let head: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{head}…")
}

/// Collapse control characters (newlines, tabs) in free-form OS data so a
/// logical line stays a single table cell.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn render_free(port: &PortResult) -> String {
    format!(
        "✨ {}\n",
        format!("Port {} is free.", port.port).green().bold()
    )
}

/// A port that could not be inspected renders as a highly visible warning
/// (never as an empty or fake table row).
fn render_port_error(port: &PortResult) -> String {
    let reason = port.error.as_deref().unwrap_or("unknown error");
    format!(
        "⚠ {}\n",
        format!("could not inspect port {}: {reason}", port.port).yellow()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessInfo;
    use colored::control::set_override;

    fn no_color() {
        // Keep assertions byte-exact regardless of the environment.
        set_override(false);
    }

    fn bare(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo::bare(pid, name.into())
    }

    fn rich(pid: u32, name: &str, command: &str) -> ProcessInfo {
        let mut p = bare(pid, name);
        p.command = Some(command.into());
        p.user = Some("alijoder".into());
        p.uptime_secs = Some(3724);
        p.cwd = Some("/workspace/portKiller".into());
        p
    }

    fn occupied(port: u16, procs: Vec<ProcessInfo>) -> PortResult {
        PortResult::occupied(port, procs)
    }

    #[test]
    fn free_port_prints_friendly_message_not_a_table() {
        no_color();
        let out = render_table(&[PortResult::free(3000)], &TableOptions::default());
        assert_eq!(out, "✨ Port 3000 is free.\n");
    }

    #[test]
    fn inspect_mode_table_has_no_status_column() {
        no_color();
        let out = render_table(
            &[occupied(3000, vec![rich(44122, "node", "node server.js")])],
            &TableOptions::default(),
        );
        for header in ["PORT", "PID", "PROCESS", "USER", "DETAILS"] {
            assert!(out.contains(header), "missing header {header}:\n{out}");
        }
        assert!(
            !out.contains("STATUS"),
            "inspect mode must hide STATUS:\n{out}"
        );
        assert!(out.contains("44122"));
        assert!(out.contains("node server.js"));
        assert!(out.contains("alijoder"));
        assert!(out.contains("Port 3000 — in use"));
        assert!(
            out.contains("pk --kill 3000"),
            "should suggest the kill command:\n{out}"
        );
    }

    #[test]
    fn dry_run_stamps_a_would_send_status() {
        no_color();
        let mut result = occupied(3000, vec![bare(44122, "node")]);
        result.processes[0].status = ProcessStatus::DryRun;
        result.processes[0].signal = Some(SignalKind::Sigterm);
        let out = render_table(&[result], &TableOptions::new(RunMode::DryRun));
        assert!(out.contains("STATUS"), "dry run must show STATUS column");
        assert!(
            out.contains("[Dry Run] Would send SIGTERM"),
            "missing badge:\n{out}"
        );
        assert!(out.contains("Dry run — no signals were sent."));
        assert!(!out.contains("was sent SIGTERM"));
    }

    #[test]
    fn kill_mode_verdict_confirmations() {
        no_color();
        let mut ok = occupied(3000, vec![bare(44122, "node")]);
        ok.processes[0].status = ProcessStatus::Terminated;
        ok.processes[0].signal = Some(SignalKind::Sigterm);
        let out = render_table(&[ok], &TableOptions::new(RunMode::Kill));
        assert!(out.contains("Terminated (SIGTERM)"));
        assert!(out.contains("✓ Port 3000 is now free."));

        let mut killed = occupied(5432, vec![bare(99, "postgres")]);
        killed.processes[0].status = ProcessStatus::Killed;
        killed.processes[0].signal = Some(SignalKind::Sigkill);
        let out = render_table(&[killed], &TableOptions::new(RunMode::Kill));
        assert!(out.contains("Killed (SIGKILL)"));
    }

    #[test]
    fn failed_kill_is_flagged_below_the_table() {
        no_color();
        let mut result = occupied(3000, vec![bare(44122, "node")]);
        result.processes[0].status = ProcessStatus::Failed;
        result.processes[0].error = Some("permission denied".into());
        let out = render_table(&[result], &TableOptions::new(RunMode::Kill));
        assert!(out.contains("Failed"));
        assert!(!out.contains("now free"));
        assert!(out.contains("✗ Failed to free port 3000 (PID 44122): permission denied"));
    }

    #[test]
    fn multiple_processes_share_one_port_grouping() {
        no_color();
        let out = render_table(
            &[occupied(
                8080,
                vec![bare(1001, "worker-a"), bare(1002, "worker-b")],
            )],
            &TableOptions::default(),
        );
        assert!(out.contains("1001"));
        assert!(out.contains("1002"));
        assert!(out.contains("worker-a"));
        assert!(out.contains("worker-b"));
        // The port header appears exactly once — grouping, not repetition.
        assert_eq!(out.matches("Port 8080 — in use").count(), 1);
    }

    #[test]
    fn long_command_lines_are_truncated_with_ellipsis() {
        no_color();
        let long = "vite --host 0.0.0.0 --port 3000 --strictPort --config ./vite.config.ts --mode development";
        let out = render_table(
            &[occupied(3000, vec![rich(5, "vite", long)])],
            &TableOptions::default(),
        );
        assert!(!out.contains(long), "long command must be elided");
        assert!(out.contains('…'), "ellipsis expected");
    }

    #[test]
    fn missing_command_falls_back_to_uptime_then_cwd() {
        no_color();
        let out = render_table(
            &[occupied(3000, vec![bare(5, "node")])],
            &TableOptions::default(),
        );
        assert!(out.contains("—"), "no details should render a placeholder");

        let mut with_uptime = occupied(3000, vec![bare(5, "node")]);
        with_uptime.processes[0].uptime_secs = Some(3724);
        let out = render_table(&[with_uptime], &TableOptions::default());
        assert!(out.contains("up 1h 2m 4s"), "uptime fallback:\n{out}");
    }

    #[test]
    fn inspection_errors_render_as_warnings() {
        no_color();
        let err = PortResult::inspection_error(
            80,
            crate::process::Protocol::Tcp,
            "requires elevated privileges",
        );
        let out = render_table(&[err], &TableOptions::default());
        assert!(out.contains("⚠"));
        assert!(out.contains("could not inspect port 80"));
        assert!(out.contains("requires elevated privileges"));
    }

    #[test]
    fn abort_footer_only_after_an_aborted_confirmation() {
        no_color();
        let result = occupied(3000, vec![bare(5, "node")]);
        let out = render_table(&[result], &TableOptions::new(RunMode::Aborted));
        assert!(out.contains("Aborted — no processes were terminated."));
        assert!(!out.contains("STATUS"));
    }

    #[test]
    fn confirming_mode_shows_table_but_omits_inspect_footer() {
        no_color();
        let result = occupied(3000, vec![rich(44122, "node", "node server.js")]);
        let out = render_table(&[result], &TableOptions::new(RunMode::Confirming));
        assert!(out.contains("Port 3000 — in use"));
        assert!(out.contains("44122"));
        assert!(out.contains("node server.js"));
        assert!(
            !out.contains("inspect only"),
            "must not show the inspect-only verdict during confirmation:\n{out}"
        );
        assert!(
            !out.contains("pk --kill 3000"),
            "must not suggest the kill command during confirmation:\n{out}"
        );
        assert!(!out.contains("STATUS"));
    }
}
