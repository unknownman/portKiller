//! macOS port → process discovery (via `lsof` + `netstat`).
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
//! ## Hidden-owner escape hatch: `netstat`
//!
//! `lsof` only reports processes **we** are permitted to see. When a privileged
//! daemon (e.g. `root`) owns the port, `lsof` silently exits `1` with no output,
//! which naively looks like "port free". That would violate our
//! *trust-through-verification* principle — we must never tell a user a port is
//! free when it is merely *hidden* from us.
//!
//! `netstat -an -p tcp` lists **every** bound port regardless of owning user, so
//! it is the cross-check: if `lsof` shows nothing but `netstat` reports the port
//! as `LISTEN`, the port is occupied yet unidentifiable → we return
//! [`AppError::AccessDenied`]. Only when `netstat` agrees it is unbound do we
//! report it free.
//!
//! ## IO / parsing separation
//!
//! * **IO** (`run_lsof`, `run_netstat`) invoke the binaries and capture stdout.
//! * **Parsing** (`parse_lsof_listen`, `parse_mac_netstat_listening`) consume
//!   the raw text and are exhaustively unit-tested against mock output.

use std::process::Command;

use crate::error::AppError;
use crate::process::ProcessInfo;

const LSOF: &str = "lsof";

const NETSTAT: &str = "netstat";

/// One parsed `lsof` row that is a LISTENing socket on the target port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsofRow {
    pub command: String,
    pub pid: u32,
    pub user: Option<String>,
    pub name: String, // the `NAME` column (socket path, e.g. `TCP 127.0.0.1:3000 (LISTEN)`)
}

/// Parse raw `lsof` output, keeping **only** rows that are a listening socket
/// on `port`. Skips the header, blank lines, and every other open-file row
/// (`cwd`, `txt`, `REG`, `DIR`, established sockets, etc.).
///
/// ## Why this filter matters
///
/// `lsof -iTCP:<port>` lists *every* open file of a process that has a socket
/// referencing that port — including outbound connections and unrelated
/// descriptors. Without filtering we would report `rapportd`, `cwd`, `txt`
/// rows, etc. as process (false positives), which this tool must never do.
///
/// Column layout: `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME`. The
/// `NAME` column (from token 7 onward) holds any spaces, so it is rejoined.
/// We keep a row only when its `TYPE` is `IPv4`/`IPv6`, its `NAME` reports
/// `(LISTEN)`, and the name contains the target port.
pub fn parse_lsof_listen(output: &str, port: u16) -> Vec<LsofRow> {
    let port_spec = format!(":{port}");
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
        let socket_type = tokens[4];
        if socket_type != "IPv4" && socket_type != "IPv6" {
            continue; // not a network socket descriptor (cwd, txt, REG, ...)
        }
        let name = tokens[7..].join(" ");
        if !name.contains("(LISTEN)") || !name.contains(&port_spec) {
            continue; // established/outbound socket, or a different port
        }
        rows.push(LsofRow {
            command: tokens[0].to_string(),
            pid,
            user: Some(tokens[2].to_string()),
            name,
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
        .args(["-n", "-P", format!("-iTCP:{port}").as_str(), "-sTCP:LISTEN"])
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
///
/// When `lsof` finds nothing we cross-check with `netstat`: a port that is
/// occupied but invisible to us (a privileged owner) must surface as
/// [`AppError::AccessDenied`], not as "free".
///
/// A single process binding the same port over both IPv4 and IPv6 produces one
/// `lsof` row per family; those are collapsed to one [`ProcessInfo`] per PID so
/// the CLI never shows the same process twice.
pub fn get_processes_on_port(port: u16) -> Result<Vec<ProcessInfo>, AppError> {
    let raw = run_lsof(port)?;
    let rows = parse_lsof_listen(&raw, port);
    if rows.is_empty() {
        ensure_not_hidden(port)?;
    }
    let procs: Vec<ProcessInfo> = rows.into_iter().map(process_from_row).collect();
    Ok(dedup_by_pid(procs))
}

/// Collapse a list into one [`ProcessInfo`] per PID, preserving first-seen order.
///
/// `lsof` emits one row per (process, address family). When a process listens on
/// both IPv4 and IPv6 for the same port it appears twice; keeping one entry per
/// PID prevents duplicate CLI rows.
fn dedup_by_pid(procs: Vec<ProcessInfo>) -> Vec<ProcessInfo> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(procs.len());
    for p in procs {
        if seen.insert(p.pid) {
            out.push(p);
        }
    }
    out
}

/// Report whether nothing is bound to `port` (TCP, LISTEN).
///
/// As with [`get_processes_on_port`], a port that is merely hidden (found by
/// `netstat` but invisible to `lsof`) is reported as [`AppError::AccessDenied`]
/// rather than free.
pub fn is_port_free(port: u16) -> Result<bool, AppError> {
    let raw = run_lsof(port)?;
    if !parse_lsof_listen(&raw, port).is_empty() {
        return Ok(false);
    }
    ensure_not_hidden(port)?;
    Ok(true)
}

/// Verify a port that `lsof` reported empty is not merely hidden from us.
///
/// `lsof` sees only the processes our user can inspect; `netstat` lists every
/// bound port regardless of owner. If `netstat` shows the port as `LISTEN`
/// while `lsof` saw nothing, a process we cannot see holds it — claiming it
/// free would be a lie, so we escalate to `AccessDenied`.
fn ensure_not_hidden(port: u16) -> Result<(), AppError> {
    let netstat = run_netstat()?;
    if parse_mac_netstat_listening(&netstat, port) {
        return Err(AppError::AccessDenied { port });
    }
    Ok(())
}

/// Run `netstat` and return its raw stdout.
///
/// `netstat -an -p tcp` reveals all listening ports system-wide and needs no
/// privileges, which is exactly what makes it the right cross-check when `lsof`
/// (user-scoped) comes up empty.
fn run_netstat() -> Result<String, AppError> {
    let output = Command::new(NETSTAT)
        .args(["-an", "-p", "tcp"])
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

/// Return whether `netstat` output reports `port` as a bound `LISTEN` socket.
///
/// Parses `netstat -an -p tcp` output. A row counts when its protocol is `tcp*`,
/// its state is `LISTEN`, and its `Local Address` ends with `.<port>` (e.g.
/// `*.80`, `127.0.0.1.80`, `[::1].80`). Any other row — established sockets,
/// TIME_WAIT, non-tcp protocols, or a different port — is ignored.
pub fn parse_mac_netstat_listening(output: &str, port: u16) -> bool {
    let suffix = format!(".{port}");
    output.lines().any(|line| {
        let mut tokens = line.split_whitespace();
        let Some(proto) = tokens.next() else {
            return false;
        };
        if !proto.starts_with("tcp") {
            return false;
        }
        // Remaining fields, in order: Recv-Q Send-Q Local-Address Foreign-Address State
        let mut fields: Vec<&str> = tokens.collect();
        let Some(state) = fields.pop() else {
            return false;
        };
        if state != "LISTEN" {
            return false;
        }
        if fields.len() < 3 {
            return false;
        }
        fields[2].ends_with(&suffix)
    })
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
        let rows = parse_lsof_listen(MOCK_LSOF, 3000);
        assert_eq!(rows.len(), 2);

        assert_eq!(rows[0].pid, 44122);
        assert_eq!(rows[0].command, "node");
        assert_eq!(rows[0].user.as_deref(), Some("alijoder"));
        assert!(rows[0].name.contains("127.0.0.1:3000"));

        assert_eq!(rows[1].pid, 51204);
        assert_eq!(rows[1].command, "vite");
    }

    // Regression: the smoke test surfaced a false-positive bug where every open
    // file (cwd, txt, established sockets, unrelated processes) of a process
    // referencing the port was reported as an occupant. Only actual LISTEN
    // sockets on the exact port may count.
    #[test]
    fn rejects_non_listen_and_unrelated_rows() {
        let messy = r#"COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
rapportd   447 alijoder  cwd   DIR    1,4      258   481 /System
stable     464 alijoder    3u  IPv4  99998      0t0  TCP 127.0.0.1:3000        (ESTABLISHED)
ControlCe  481 alijoder  txt   REG    1,4   379664   314 /usr/bin/foo
outbound   512 alijoder    7u  IPv4  99997      0t0  TCP 1.2.3.4:3000          (ESTABLISHED)
offport    555 alijoder   11u  IPv4  99996      0t0  TCP 127.0.0.1:8080         (LISTEN)
real       600 alijoder    5u  IPv6  99995      0t0  TCP [::1]:3000             (LISTEN)
"#;
        let rows = parse_lsof_listen(messy, 3000);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 600);
        assert_eq!(rows[0].command, "real");
    }

    #[test]
    fn skips_header_blank_and_garbled_rows() {
        let out = parse_lsof_listen(
            "COMMAND  PID USER FD DEVICE SIZE/OFF NODE NAME\n\
             \n\
             NOT_DATA\n\
             node 9999 alijoder 3u IPv4 1 0t0 TCP 1.2.3.4:3000 (LISTEN)\n",
            3000,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pid, 9999);
    }

    #[test]
    fn empty_output_returns_no_rows() {
        assert!(parse_lsof_listen("", 3000).is_empty());
        assert!(
            parse_lsof_listen("COMMAND PID USER FD DEVICE SIZE/OFF NODE NAME\n", 3000).is_empty()
        );
    }

    #[test]
    fn multiple_processes_sharing_a_port_are_both_parsed() {
        let rows = parse_lsof_listen(MOCK_LSOF, 3000);
        let pids: Vec<u32> = rows.iter().map(|r| r.pid).collect();
        assert!(pids.contains(&44122));
        assert!(pids.contains(&51204));
    }

    #[test]
    fn matching_a_different_port_keeps_only_matching_listeners() {
        // Same raw output, but searching port 8080 must ignore the two 3000
        // listeners entirely.
        let (a, b) = (
            parse_lsof_listen(MOCK_LSOF, 8080).is_empty(),
            parse_lsof_listen(MOCK_LSOF, 3000).len(),
        );
        assert!(a);
        assert_eq!(b, 2);
    }

    #[test]
    fn row_with_non_numeric_pid_is_skipped() {
        let out = parse_lsof_listen(
            "COMMAND PID USER FD DEVICE SIZE/OFF NODE NAME\nnode abc alijoder 3u IPv4 1\n",
            3000,
        );
        assert!(out.is_empty());
    }

    // ------------------------------------------------------------------
    // parse_mac_netstat_listening
    // ------------------------------------------------------------------

    // Realistic macOS `netstat -an -p tcp` output with one privileged hijacked
    // port (80) plus other unrelated sockets.
    const MOCK_NETSTAT: &str = r#"Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  127.0.0.1.80           *.*                    LISTEN
tcp4       0      0  127.0.0.1.3000         *.*                    LISTEN
tcp6       0      0  ::1.80                *.*                    LISTEN
tcp4       0      0  10.0.0.5.53338        10.0.0.1.443            ESTABLISHED
tcp4       0      0  *.22                  *.*                    LISTEN
"#;

    #[test]
    fn netstat_detects_ipv4_listen_on_target_port() {
        assert!(parse_mac_netstat_listening(MOCK_NETSTAT, 80));
        assert!(parse_mac_netstat_listening(MOCK_NETSTAT, 3000));
    }

    #[test]
    fn netstat_detects_ipv6_listen_on_target_port() {
        assert!(parse_mac_netstat_listening(MOCK_NETSTAT, 80));
    }

    #[test]
    fn netstat_detects_wildcard_listener() {
        assert!(parse_mac_netstat_listening(MOCK_NETSTAT, 22));
    }

    #[test]
    fn netstat_ignores_unrelated_ports() {
        assert!(!parse_mac_netstat_listening(MOCK_NETSTAT, 8080));
        assert!(!parse_mac_netstat_listening(MOCK_NETSTAT, 443));
    }

    #[test]
    fn netstat_ignores_established_and_non_listen_rows() {
        // Port 443 is only an *outbound* established connection here — it must
        // not count as bound, and the foreign address `.443` must not be
        // confused with a local listener.
        assert!(!parse_mac_netstat_listening(MOCK_NETSTAT, 443));
        assert!(!parse_mac_netstat_listening(MOCK_NETSTAT, 53338));
    }

    #[test]
    fn netstat_empty_or_header_only_is_free() {
        assert!(!parse_mac_netstat_listening("", 80));
        assert!(!parse_mac_netstat_listening(
            "Active Internet connections (including servers)\nProto Recv-Q Send-Q Local Address Foreign Address (state)\n",
            80,
        ));
    }

    #[test]
    fn netstat_port_suffix_must_match_exactly() {
        // `.80` must not match `.8001` or `.180`; the port is a whole suffix.
        let out = "tcp4 0 0 127.0.0.1.8001 *.* LISTEN\ntcp4 0 0 127.0.0.1.180 *.* LISTEN\n";
        assert!(!parse_mac_netstat_listening(out, 80));
    }

    #[test]
    fn netstat_non_tcp_protocol_rows_are_ignored() {
        let out = "tcp4 0 0 127.0.0.1.80 *.* LISTEN\nudp4 0 0 127.0.0.1.80 *.*\n";
        assert!(parse_mac_netstat_listening(out, 80));
    }

    #[test]
    fn lsof_empty_but_netstat_occupied_is_access_denied() {
        // A `root`-owned port: lsof sees nothing, netstat proves it is bound.
        // This is the exact misreport the fix prevents.
        let raw_lsof = "COMMAND PID USER FD DEVICE SIZE/OFF NODE NAME\n";
        assert!(parse_lsof_listen(raw_lsof, 80).is_empty());
        assert!(parse_mac_netstat_listening(MOCK_NETSTAT, 80));
    }

    // Regression: one process binding the same port on both IPv4 and IPv6 yields
    // two lsof rows for the same PID, which must collapse to a single entry.
    #[test]
    fn ipv4_and_ipv6_listeners_for_same_pid_deduplicate() {
        let dual = r#"COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
node    44122 alijoder   21u  IPv4  12345      0t0  TCP 0.0.0.0:3000 (LISTEN)
node    44122 alijoder   22u  IPv6  54321      0t0  TCP [::]:3000 (LISTEN)
"#;
        let rows = parse_lsof_listen(dual, 3000);
        assert_eq!(rows.len(), 2, "both address families must be parsed");

        let procs: Vec<ProcessInfo> = rows.into_iter().map(process_from_row).collect();
        let deduped = dedup_by_pid(procs);
        assert_eq!(deduped.len(), 1, "same PID across IPv4/IPv6 must collapse");
        assert_eq!(deduped[0].pid, 44122);
        assert_eq!(deduped[0].name, "node");
    }
}
