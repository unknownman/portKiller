//! macOS port → process discovery (via `lsof`).
//!
//! ## Approach: shell out to `lsof`
//!
//! macOS ships `lsof` which (unlike Linux's `/proc`) can match a port directly:
//!
//! ```text
//! lsof -n -P -iTCP:3000 -sTCP:LISTEN
//! ```
//!
//! `-n` and `-P` disable hostname/port name resolution for speed and
//! machine-friendly output. Each row names the owning process.
//!
//! ## IO / parsing separation
//!
//! * **IO** (`run_lsof`) invokes the binary and captures stdout.
//! * **Parsing** (`parse_lsof_listen`) consumes the raw text into rows and is
//!   exhaustively unit-tested against mock `lsof` output.

use std::process::Command;

use crate::error::AppError;
use crate::process::ProcessInfo;

const LSOF: &str = "lsof";

/// One parsed `lsof` output row (one open file per process row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsofRow {
    pub command: String,
    pub pid: u32,
    pub user: Option<String>,
    pub name: String, // the `NAME` column (socket/file path)
}

/// Parse raw `lsof` output into rows, skipping the header and blank lines.
/// Malformed rows are skipped rather than fatal.
///
/// Column layout: `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME`.
/// `NAME` (the socket path) may itself contain spaces, so we split all tokens
/// with `split_whitespace` (which collapses runs of whitespace) and reattach
/// every token from column 7 onward as the NAME.
pub fn parse_lsof_listen(output: &str) -> Vec<LsofRow> {
    let mut rows = Vec::new();
    for line in output.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        // Need at least: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE
        if tokens.len() < 8 {
            continue;
        }
        let Ok(pid) = tokens[1].parse::<u32>() else {
            continue;
        };
        rows.push(LsofRow {
            command: tokens[0].to_string(),
            pid,
            user: Some(tokens[2].to_string()),
            name: tokens[7..].join(" "),
        });
    }
    rows
}

/// Run `lsof` for the given port and return its raw stdout.
///
/// `lsof` exits `1` when nothing matches — that is "port free", not an error —
/// so we normalise exit code 1 to empty output.
fn run_lsof(port: u16) -> Result<String, AppError> {
    let output = Command::new(LSOF)
        .args(["-n", "-P", "-iTCP", "-sTCP:LISTEN"])
        .arg(format!("-iTCP:{port}"))
        .output()
        .map_err(|e| AppError::OsCommandFailed {
            command: LSOF,
            message: format!("could not spawn `{LSOF}`: {e}"),
        })?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else if output.status.code() == Some(1) {
        Ok(String::new())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(AppError::OsCommandFailed {
            command: LSOF,
            message: stderr.trim().to_string(),
        })
    }
}

/// Return the processes bound to `port` (TCP, LISTEN). Empty vec when free.
pub fn get_processes_on_port(port: u16) -> Result<Vec<ProcessInfo>, AppError> {
    let raw = run_lsof(port)?;
    let rows = parse_lsof_listen(&raw);
    Ok(rows.into_iter().map(process_from_row).collect())
}

/// Report whether nothing is bound to `port` (TCP, LISTEN).
pub fn is_port_free(port: u16) -> Result<bool, AppError> {
    let raw = run_lsof(port)?;
    Ok(parse_lsof_listen(&raw).is_empty())
}

/// Convert one lsof row into a `ProcessInfo`.
///
/// `lsof`'s `COMMAND` column is the short process name (not a full command
/// line); full cmdline enrichment is deferred to later phases.
fn process_from_row(row: LsofRow) -> ProcessInfo {
    ProcessInfo {
        pid: row.pid,
        name: row.command,
        command: None,
        user: row.user,
        uptime_secs: None,
        cwd: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOCK_LSOF: &str = r#"COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
node    44122 alijoder   21u  IPv4  12345      0t0  TCP 127.0.0.1:3000 (LISTEN)
vite    51204 alijoder   12u  IPv6  54321      0t0  TCP [::1]:3000 (LISTEN)
"#;

    #[test]
    fn parses_pid_command_user_and_skips_header() {
        let rows = parse_lsof_listen(MOCK_LSOF);
        assert_eq!(rows.len(), 2);

        assert_eq!(rows[0].pid, 44122);
        assert_eq!(rows[0].command, "node");
        assert_eq!(rows[0].user.as_deref(), Some("alijoder"));
        assert!(rows[0].name.contains("127.0.0.1:3000"));

        assert_eq!(rows[1].pid, 51204);
        assert_eq!(rows[1].command, "vite");
    }

    #[test]
    fn skips_header_blank_and_garbled_rows() {
        let out = parse_lsof_listen(
            "COMMAND  PID USER FD DEVICE SIZE/OFF NODE NAME\n\
             \n\
             NOT_DATA\n\
             node 9999 alijoder 3u IPv4 1 0t0 TCP 1.2.3.4:80 (LISTEN)\n",
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pid, 9999);
    }

    #[test]
    fn empty_output_returns_no_rows() {
        assert!(parse_lsof_listen("").is_empty());
        assert!(parse_lsof_listen("COMMAND PID USER FD DEVICE SIZE/OFF NODE NAME\n").is_empty());
    }

    #[test]
    fn multiple_processes_sharing_a_port_are_both_parsed() {
        let rows = parse_lsof_listen(MOCK_LSOF);
        let pids: Vec<u32> = rows.iter().map(|r| r.pid).collect();
        assert!(pids.contains(&44122));
        assert!(pids.contains(&51204));
    }

    #[test]
    fn row_with_non_numeric_pid_is_skipped() {
        let out = parse_lsof_listen(
            "COMMAND PID USER FD DEVICE SIZE/OFF NODE NAME\nnode abc alijoder 3u IPv4 1\n",
        );
        assert!(out.is_empty());
    }
}
