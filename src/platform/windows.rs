//! Windows port → process discovery (via `netstat`).
//!
//! ## Approach: shell out to `netstat`
//!
//! Windows ships `netstat` whose `-ano` flags emit the owning PID:
//!
//! ```text
//! netstat -ano -p TCP
//! ```
//!
//! The final column is the PID. The `Foreign Address` column shows
//! `0.0.0.0:0`/`[::]:0` or `127.0.0.1:0` when a listener, but matching by PID
//! alone is unreliable (ephemeral ports), so we filter against the local port
//! *and* `LISTENING` state.
//!
//! ## IO / parsing separation
//!
//! * **IO** (`run_netstat`) invokes the binary.
//! * **Parsing** (`parse_netstat`) consumes raw text into rows, unit-tested.
//!
//! Enrichment (user/cmdline/uptime) on Windows is deferred; we surface the PID
//! with a fallback name so identification remains sound.

use std::process::Command;

use crate::error::AppError;
use crate::process::ProcessInfo;

const NETSTAT: &str = "netstat";

/// One parsed `netstat -ano` row that is in `LISTENING` state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetstatRow {
    pub pid: u32,
    pub local_port: u16,
}

/// Parse raw `netstat -ano` output, keeping only `LISTENING` rows for the
/// given port. Tolerates the header, blank lines, and malformed rows.
///
/// Row shape (`-p TCP` on modern Windows):
/// `TCP 0.0.0.0:3000 0.0.0.0:0 LISTENING 44122`
pub fn parse_netstat(output: &str, port: u16) -> Vec<NetstatRow> {
    let mut rows = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Expect: TCP <local> <foreign> <state> <pid>
        if fields.len() != 5 {
            continue;
        }
        let state_ok = fields[3].eq_ignore_ascii_case("LISTENING");
        let Some(local_port) = port_of(&fields[1]) else {
            continue;
        };
        let Some(pid) = fields[4].parse::<u32>().ok() else {
            continue;
        };
        if state_ok && local_port == port {
            rows.push(NetstatRow { pid, local_port });
        }
    }
    rows
}

/// Extract the port from a `host:port` (or `[host]:port`) local address.
fn port_of(local_address: &str) -> Option<u16> {
    if local_address.starts_with('[') {
        // [::1]:3000
        let rest = local_address.rsplit(']').next()?.strip_prefix(':')?;
        rest.parse().ok()
    } else if let Some(idx) = local_address.rfind(':') {
        local_address[idx + 1..].parse().ok()
    } else {
        None
    }
}

/// Run `netstat -ano -p TCP` and return raw stdout, or an actionable error.
fn run_netstat() -> Result<String, AppError> {
    let output = Command::new(NETSTAT)
        .args(["-ano", "-p", "TCP"])
        .output()
        .map_err(|e| AppError::OsCommandFailed {
            command: NETSTAT,
            message: format!("could not spawn `{NETSTAT}`: {e}"),
        })?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(AppError::OsCommandFailed {
            command: NETSTAT,
            message: stderr.trim().to_string(),
        })
    }
}

/// Return the processes bound to `port` (TCP, LISTENING). Empty vec when free.
pub fn get_processes_on_port(port: u16) -> Result<Vec<ProcessInfo>, AppError> {
    let raw = run_netstat()?;
    let rows = parse_netstat(&raw, port);
    Ok(rows
        .into_iter()
        .map(|r| ProcessInfo::bare(r.pid, format!("pid-{}", r.pid)))
        .collect())
}

/// Report whether nothing is bound to `port` (TCP, LISTENING).
pub fn is_port_free(port: u16) -> Result<bool, AppError> {
    let raw = run_netstat()?;
    Ok(parse_netstat(&raw, port).is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOCK_NETSTAT: &str = r#"Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:3000           0.0.0.0:0              LISTENING       44122
  TCP    [::]:3000              [::]:0                 LISTENING       51204
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       99999
  TCP    127.0.0.1:3000         127.0.0.1:54321         ESTABLISHED     77777
  TCP    0.0.0.0:3000           0.0.0.0:0              LISTENING       12345
"#;

    #[test]
    fn keeps_only_listening_rows_for_target_port() {
        let rows = parse_netstat(MOCK_NETSTAT, 3000);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].pid, 44122);
        assert_eq!(rows[2].pid, 12345);
    }

    #[test]
    fn ignores_established_and_other_ports() {
        let rows = parse_netstat(MOCK_NETSTAT, 3000);
        assert!(!rows.iter().any(|r| r.pid == 77777)); // ESTABLISHED
        assert!(!rows.iter().any(|r| r.pid == 99999)); // port 8080
    }

    #[test]
    fn parses_ipv6_bracketed_addresses() {
        assert_eq!(port_of("[::]:3000"), Some(3000));
        assert_eq!(port_of("0.0.0.0:8080"), Some(8080));
        assert_eq!(port_of("127.0.0.1:3000"), Some(3000));
        assert_eq!(port_of("garbage"), None);
    }

    #[test]
    fn empty_and_header_only_output_yields_nothing() {
        assert!(parse_netstat("", 3000).is_empty());
        assert!(parse_netstat("Proto  Local Address  Foreign  State  PID\n", 3000).is_empty());
    }
}
