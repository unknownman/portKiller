//! Linux port → process discovery.
//!
//! ## Approach: `/proc` inode matching
//!
//! Linux exposes TCP/UDP socket tables in `/proc/net/tcp` (and `tcp6`). Each
//! row describes one socket and carries its **inode** (a per-socket kernel
//! identifier). Separately, every process's already-open file descriptors are
//! listed under `/proc/<pid>/fd/` as symlinks whose targets look like
//! `socket:[<inode>]`. Cross-referencing the two lets us map a bound port to
//! its owning PID with no external commands and no `libc` privileges.
//!
//! ```text
//! /proc/net/tcp  ──(match port)→ inode  ──┐
//!                                        ├─(match inode)→ pid ──(enrich)→ ProcessInfo
//! /proc/<pid>/fd ─────(read links)───────┘
//! ```
//!
//! ## IO / parsing separation
//!
//! * **IO** (`read_proc_net_*`, `pids_with_inode`, `read_enrichment_*`) touches
//!   the filesystem only.
//! * **Parsing** (`parse_proc_net_tcp`, `parse_status_name`, `parse_cmdline`)
//!   are pure functions over `&str`/`&[u8]`, exhaustively unit-tested against
//!   mock `/proc` output.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use crate::error::AppError;
use crate::process::ProcessInfo;

// ---------------------------------------------------------------------------
// Parsing (pure, unit-tested)
// ---------------------------------------------------------------------------

/// One parsed row of `/proc/net/tcp` (or `tcp6`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcNetEntry {
    pub local_port: u16,
    pub state: u8,
    pub inode: u64,
}

/// Parse the contents of `/proc/net/tcp` or `/proc/net/tcp6`.
///
/// Column layout (whitespace split):
///
/// ```text
///   sl  local_address        rem_address  st  ...  uid  timeout  inode
///    0: 0100007F:0BB8        00000000:0  0A  ...  1000       0  12345
/// ```
///
/// * `local_address` = `ip:PORT_HEX`, where the port is the trailing 4 hex
///   digits (`0BB8` → 3000).
/// * `st` = state nibble; `0A` (10) means `TCP_LISTEN`.
/// * `inode` = decimal socket inode (field index 9).
///
/// Malformed rows are **skipped**, never fatal: real `/proc` data is reliable
/// but not guaranteed, and one corrupt line should not orphan the whole scan.
pub fn parse_proc_net_tcp(contents: &str) -> Vec<ProcNetEntry> {
    let mut out = Vec::new();
    for line in contents.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(entry) = parse_proc_net_line(line) else {
            continue; // tolerate malformed rows
        };
        out.push(entry);
    }
    out
}

fn parse_proc_net_line(line: &str) -> Option<ProcNetEntry> {
    let mut fields = line.split_whitespace();
    let _sl = fields.next()?; // "0:"
    let local_address = fields.next()?; // "0100007F:0BB8"
    let _remote_address = fields.next()?;
    let state = fields.next()?; // "0A"
    for _ in 0..5 {
        // tx_queue:rx_queue, tr:tm->when, retrnsmt, uid, timeout
        fields.next()?;
    }
    let inode = fields.next()?; // decimal inode

    let local_port = port_from_address(local_address)?;
    let state = u8::from_str_radix(state, 16).ok()?;
    let inode = inode.parse::<u64>().ok()?;

    Some(ProcNetEntry {
        local_port,
        state,
        inode,
    })
}

/// Extract the port from `ip:PORT_HEX` (works for both v4 and v6 row formats by
/// taking the substring after the final `:`).
fn port_from_address(local_address: &str) -> Option<u16> {
    let port_hex = local_address.rsplit(':').next()?;
    // The port is exactly 4 hex digits. Reject anything else rather than
    // mis-parsing a shifted column layout.
    if port_hex.len() != 4 {
        return None;
    }
    u16::from_str_radix(port_hex, 16).ok()
}

/// Parse the `Name:` / `Uid:` fields out of `/proc/<pid>/status` into a
/// `ProcessInfo`'s known metadata.
///
/// We only read the `Name:` line (the friendly process name). Returning a map
/// keeps the function pure and let callers decide what to apply.
pub fn parse_status_name(status: &str) -> Option<String> {
    for line in status.lines() {
        if let Some(name) = line.strip_prefix("Name:") {
            let name = name.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Parse a `/proc/<pid>/cmdline` byte buffer into a command string.
///
/// `/proc/<pid>/cmdline` stores arguments as NUL-separated bytes. We replace
/// the NUL separators with spaces and trim trailing NULs.
pub fn parse_cmdline(cmdline: &[u8]) -> String {
    if cmdline.is_empty() {
        return String::new();
    }
    let trimmed = cmdline.strip_suffix(b"\0").unwrap_or(cmdline);
    String::from_utf8_lossy(trimmed).replace('\0', " ")
}

// ---------------------------------------------------------------------------
// IO (thin, calls into parsers)
// ---------------------------------------------------------------------------

const PORT_IN_KERNEL: u8 = 0x0A; // TCP_LISTEN

/// Read both `/proc/net/tcp` and `/proc/net/tcp6` and collect the LISTEN-ing
/// socket inodes bound to `port`. Returns an empty vec when nothing is bound.
///
/// v1.0 inspects TCP only. UDP shares the same `/proc/net/udp` shape, but its
/// state nibble differs and it is deliberately out of scope for now.
fn tcp_inodes_for_port(port: u16) -> Result<Vec<u64>, AppError> {
    const PROC_TABLES: &[&str] = &["/proc/net/tcp", "/proc/net/tcp6"];
    let mut inodes = Vec::new();
    for table in PROC_TABLES {
        // A missing table (e.g. an old kernel without IPv6) is not fatal —
        // read what exists; only a hard IO failure propagates.
        let contents = match fs::read_to_string(table) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(AppError::io(*table, e)),
        };
        inodes.extend(
            parse_proc_net_tcp(&contents)
                .into_iter()
                .filter(|e| e.local_port == port && e.state == PORT_IN_KERNEL)
                .map(|e| e.inode),
        );
    }
    Ok(inodes)
}

/// Collect every PID whose open fd set includes the given socket inode.
/// Returns an empty set when no process holds that socket (e.g. it vanished).
fn pids_holding_inode(inode: u64, max_pid: u32) -> HashSet<u32> {
    let mut pids = HashSet::new();
    for pid in 1..=max_pid {
        let fd_dir = PathBuf::from(format!("/proc/{pid}/fd"));
        let Ok(entries) = fs::read_dir(&fd_dir) else {
            continue; // no such pid, or permission — skip
        };
        for entry in entries.flatten() {
            let link = match fs::read_link(entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let link = link.to_string_lossy();
            if link == format!("socket:[{inode}]") {
                pids.insert(pid);
            }
        }
    }
    pids
}

/// Highest PID on the system, read from `/proc/sys/kernel/pid_max`.
fn max_pid() -> u32 {
    fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(4194304) // safe Linux default upper bound
}

fn enrich(pid: u32) -> ProcessInfo {
    let proc_root = format!("/proc/{pid}");
    let status = fs::read_to_string(format!("{proc_root}/status")).ok();
    let name = status
        .as_deref()
        .and_then(parse_status_name)
        .unwrap_or_else(|| pid.to_string());

    let cmdline = fs::read(format!("{proc_root}/cmdline")).ok();
    let command = cmdline
        .as_deref()
        .map(parse_cmdline)
        .filter(|c| !c.is_empty());

    let cwd = fs::read_link(format!("{proc_root}/cwd"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    ProcessInfo {
        pid,
        name,
        command,
        user: None,
        uptime_secs: None,
        cwd,
    }
}

/// Resolve owning PIDs for a set of inodes, guarding against the silent
/// "impossibly free port" trap.
///
/// * Empty `inodes` → port is genuinely free → empty PID set.
/// * Non-empty `inodes` but no resolvable PIDs → the port is verifiably in use
///   yet unreadable under our privileges; return [`AppError::AccessDenied`].
/// * Otherwise → the resolved PID set.
///
/// `holding` yields the PIDs that hold one inode; it is injected so this
/// decision is unit-testable without a real `/proc`.
fn pids_or_access_denied(
    port: u16,
    inodes: &[u64],
    mut holding: impl FnMut(u64) -> HashSet<u32>,
) -> Result<HashSet<u32>, AppError> {
    if inodes.is_empty() {
        return Ok(HashSet::new()); // port free
    }
    let mut pids = HashSet::new();
    for inode in inodes {
        pids.extend(holding(*inode));
    }
    if pids.is_empty() {
        // Port is in use but every owning pid was unreadable under our
        // privileges. Crucially *not* an empty result.
        return Err(AppError::AccessDenied { port });
    }
    Ok(pids)
}

/// Look up every process bound to `port` on TCP (LISTEN state).
pub fn get_processes_on_port(port: u16) -> Result<Vec<ProcessInfo>, AppError> {
    let inodes = tcp_inodes_for_port(port)?;
    let top = max_pid();
    let pids = pids_or_access_denied(port, &inodes, |inode| pids_holding_inode(inode, top))?;
    Ok(pids.into_iter().map(enrich).collect())
}

/// Report whether nothing is LISTEN-bound on `port`.
pub fn is_port_free(port: u16) -> Result<bool, AppError> {
    let inodes = tcp_inodes_for_port(port)?;
    Ok(inodes.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOCK_TCP: &str = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 54321 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0BB8 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000 100 0 0 10 0
   3: 0100007F:0BB9 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 77777 1 0000000000000000 100 0 0 10 0
"#;

    #[test]
    fn parses_hex_port_and_inode() {
        let entries = parse_proc_net_tcp(MOCK_TCP);
        assert_eq!(entries.len(), 4);

        // 0BB8 -> 3000, LISTEN(0A), inode 12345
        assert_eq!(entries[0].local_port, 3000);
        assert_eq!(entries[0].state, 0x0A);
        assert_eq!(entries[0].inode, 12345);

        // 1F90 -> 8080
        assert_eq!(entries[1].local_port, 8080);

        // non-LISTEN row still parsed (state 01) — filter is the caller's job
        assert_eq!(entries[2].local_port, 3000);
        assert_eq!(entries[2].state, 0x01);
        assert_eq!(entries[2].inode, 99999);

        // different port
        assert_eq!(entries[3].local_port, 3001);
    }

    #[test]
    fn skips_empty_and_header_lines() {
        let out = parse_proc_net_tcp("");
        assert!(out.is_empty());

        let header_only = "  sl  local_address rem_address   st ...\n";
        assert!(parse_proc_net_tcp(header_only).is_empty());
    }

    #[test]
    fn tolerates_malformed_rows_without_panicking() {
        // Header + garbage + one valid row.
        let messy = format!(
            "  sl  local_address rem_address   st ...\n\
             NOT-A-ROW\n\
             9: ::0BB8:ZZZZ 00000000:0000 0A 0000 0000 00 0000 0000  0  0 0000\n\
             {}\n",
            "11: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 4242 1"
        );
        let out = parse_proc_net_tcp(&messy);
        // Only the final valid row survives.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].inode, 4242);
    }

    #[test]
    fn port_from_address_handles_v4_and_v6_shapes() {
        assert_eq!(port_from_address("0100007F:0BB8"), Some(3000));
        assert_eq!(
            port_from_address("00000000000000000000000000000000:1F90"),
            Some(8080)
        );
        assert_eq!(port_from_address("0100007F"), None); // no colon
        assert_eq!(port_from_address("0100007F:0BBB8"), None); // 5 hex digits
    }

    #[test]
    fn status_name_parsing() {
        let status = "Name:\tnode\nUmask:\t0022\nState:\tS (sleeping)\n";
        assert_eq!(parse_status_name(status), Some("node".into()));

        let no_name = "State:\tS (sleeping)\n";
        assert_eq!(parse_status_name(no_name), None);
    }

    #[test]
    fn cmdline_parsing_replaces_nul_separators() {
        let bytes = b"node\0server.js\0--port\0 3000";
        assert_eq!(parse_cmdline(bytes), "node server.js --port  3000");

        assert_eq!(parse_cmdline(b""), "");
        assert_eq!(parse_cmdline(b"node\0"), "node");
    }

    #[test]
    fn max_pid_has_sane_fallback() {
        // Never panics and always returns a positive bound.
        assert!(max_pid() > 0);
    }

    #[test]
    fn no_inodes_means_port_is_free() {
        let pids = pids_or_access_denied(3000, &[], |_| HashSet::new()).unwrap();
        assert!(pids.is_empty());
    }

    #[test]
    fn occupied_port_with_unresolvable_pids_is_access_denied_not_free() {
        // Matching inodes exist (port is verifiably in use) but no PID can be
        // resolved — the silent "free port" trap when inspecting root-owned
        // ports. This MUST error, never return an empty list.
        let err = pids_or_access_denied(80, &[12345, 54321], |_| HashSet::new()).unwrap_err();
        assert!(matches!(err, AppError::AccessDenied { port: 80 }));
    }

    #[test]
    fn resolves_pids_across_all_inodes() {
        // Multiple inodes (e.g. v4 + v6 sockets for the same port) contribute
        // PIDs that are unioned together.
        let pids = pids_or_access_denied(3000, &[100, 200], |inode| match inode {
            100 => [7, 8].into_iter().collect(),
            200 => [8, 9].into_iter().collect(),
            _ => HashSet::new(),
        })
        .unwrap();
        assert_eq!(pids, [7, 8, 9].into_iter().collect());
    }

    #[test]
    fn parses_full_ipv6_tcp_listen_row_shape() {
        // A realistic `/proc/net/tcp6` row: 32-hex v6 local address then :PORT.
        let tcp6 = r#"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 424242 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777777 1 0000000000000000 100 0 0 10 0
"#;
        let entries = parse_proc_net_tcp(tcp6);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].local_port, 8080);
        assert_eq!(entries[0].state, 0x0A);
        assert_eq!(entries[0].inode, 424242);
        assert_eq!(entries[1].local_port, 3000);
        assert_eq!(entries[1].inode, 777777);
    }
}
