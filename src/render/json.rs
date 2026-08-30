//! Machine-readable (`--json`) output.
//!
//! [`render_json`] serializes the same [`PortResult`] slice the human renderer
//! consumes into a stable, well-formed `serde_json` document matching the
//! README's `{ "ports": [...] }` contract. Every failure a run can produce —
//! a failed kill, a permission-denied inspection — travels **inside** the
//! payload as a `status`/`error` field, so scripts never have to parse raw
//! stderr, and a partial failure can never break the JSON structure.

use serde::Serialize;

use super::types::{PortResult, ProcessResult, ProcessStatus, SignalKind};
use crate::process::Protocol;

/// The top-level document. Wrap is thin on purpose: the README guarantees
/// `ports` as the root key, so scripts can `jq '.ports[0]'` blindly.
#[derive(Debug, Serialize)]
struct ReportDoc<'a> {
    ports: Vec<PortDoc<'a>>,
}

/// One port's machine-facing shape.
#[derive(Debug, Serialize)]
struct PortDoc<'a> {
    port: u16,
    protocol: Protocol,
    /// `null` when an inspection error (e.g. access denied) left occupancy unknown.
    free: Option<bool>,
    /// Inspection-level error message, if the port could not be queried.
    error: Option<&'a str>,
    /// Every process found on this port (empty when free or unqueryable).
    processes: &'a [ProcessResult],
    /// True when at least one process on this port was terminated successfully.
    killed: bool,
    /// The signal that would be / was used, or `null` on a pure inspect run.
    kill_signal: Option<SignalKind>,
}

impl<'a> From<&'a PortResult> for PortDoc<'a> {
    fn from(port: &'a PortResult) -> Self {
        let killed = port
            .processes
            .iter()
            .any(|p| matches!(p.status, ProcessStatus::Terminated | ProcessStatus::Killed));
        let kill_signal = port.processes.iter().find_map(|p| match p.status {
            ProcessStatus::Terminated | ProcessStatus::Killed | ProcessStatus::DryRun => p.signal,
            _ => None,
        });
        Self {
            port: port.port,
            protocol: port.protocol,
            free: port.free,
            error: port.error.as_deref(),
            processes: &port.processes,
            killed,
            kill_signal,
        }
    }
}

/// Serialize a full run report as pretty-printed JSON. Never panics: every
/// constituent is a plain `Serialize` value, so serialization cannot fail.
pub fn render_json(results: &[PortResult]) -> String {
    let doc = ReportDoc {
        ports: results.iter().map(PortDoc::from).collect(),
    };
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessInfo;
    use serde_json::Value;

    fn bare(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo::bare(pid, name.into())
    }

    fn parse(out: &str) -> Value {
        serde_json::from_str(out).expect("render_json must always emit valid JSON")
    }

    #[test]
    fn free_port_serializes_free_null_error_and_empty_processes() {
        let v = parse(&render_json(&[PortResult::free(3000)]));
        let port = &v["ports"][0];
        assert_eq!(port["port"], 3000);
        assert_eq!(port["protocol"], "tcp");
        assert_eq!(port["free"], true);
        assert_eq!(port["error"], Value::Null);
        assert_eq!(port["processes"], serde_json::json!([]));
        assert_eq!(port["killed"], false);
        assert_eq!(port["kill_signal"], Value::Null);
    }

    #[test]
    fn occupied_inspect_run_has_full_process_objects() {
        let mut info = bare(44122, "node");
        info.command = Some("node server.js".into());
        info.user = Some("alijoder".into());
        info.uptime_secs = Some(3724);
        let v = parse(&render_json(&[PortResult::occupied(3000, vec![info])]));
        let port = &v["ports"][0];
        assert_eq!(port["free"], false);
        assert_eq!(port["killed"], false);
        assert_eq!(port["kill_signal"], Value::Null);
        let proc_doc = &port["processes"][0];
        for key in [
            "pid",
            "name",
            "command",
            "user",
            "uptime_secs",
            "cwd",
            "status",
            "signal",
            "error",
        ] {
            assert!(
                proc_doc.get(key).is_some(),
                "missing field {key}: {proc_doc}"
            );
        }
        assert_eq!(proc_doc["pid"], 44122);
        assert_eq!(proc_doc["status"], "info");
    }

    #[test]
    fn successful_kill_is_represented() {
        let mut result = PortResult::occupied(3000, vec![bare(44122, "node")]);
        result.processes[0].status = ProcessStatus::Terminated;
        result.processes[0].signal = Some(SignalKind::Sigterm);
        let v = parse(&render_json(&[result]));
        let port = &v["ports"][0];
        assert_eq!(port["killed"], true);
        assert_eq!(port["kill_signal"], "SIGTERM");
        assert_eq!(port["processes"][0]["status"], "terminated");
        assert_eq!(port["processes"][0]["error"], Value::Null);
    }

    #[test]
    fn force_kill_and_dry_run_signal_are_distinguishable() {
        let mut killed = PortResult::occupied(5432, vec![bare(99, "postgres")]);
        killed.processes[0].status = ProcessStatus::Killed;
        killed.processes[0].signal = Some(SignalKind::Sigkill);
        let v = parse(&render_json(&[killed]));
        assert_eq!(v["ports"][0]["kill_signal"], "SIGKILL");
        assert_eq!(v["ports"][0]["processes"][0]["status"], "killed");

        let mut dry = PortResult::occupied(3000, vec![bare(7, "vite")]);
        dry.processes[0].status = ProcessStatus::DryRun;
        dry.processes[0].signal = Some(SignalKind::Sigterm);
        let v = parse(&render_json(&[dry]));
        assert_eq!(v["ports"][0]["killed"], false, "dry run never kills");
        assert_eq!(v["ports"][0]["kill_signal"], "SIGTERM");
    }

    #[test]
    fn failed_kill_carries_error_instead_of_breaking_json() {
        let mut result = PortResult::occupied(3000, vec![bare(44122, "node")]);
        result.processes[0].status = ProcessStatus::Failed;
        result.processes[0].error = Some("port 3000 still bound after SIGKILL to PID 44122".into());
        let v = parse(&render_json(&[result]));
        let proc_doc = &v["ports"][0]["processes"][0];
        assert_eq!(proc_doc["status"], "failed");
        assert!(proc_doc["error"].as_str().unwrap().contains("still bound"));
        assert_eq!(v["ports"][0]["killed"], false);
    }

    #[test]
    fn inspection_error_is_encoded_into_the_payload() {
        let err = PortResult::inspection_error(80, Protocol::Tcp, "requires elevated privileges");
        let v = parse(&render_json(&[err]));
        let port = &v["ports"][0];
        assert_eq!(port["free"], Value::Null, "occupancy unknown, not a guess");
        assert_eq!(port["error"], "requires elevated privileges");
        assert_eq!(port["processes"], serde_json::json!([]));
    }

    #[test]
    fn mixed_run_keeps_every_port_in_input_order() {
        let cases = [
            PortResult::free(8080),
            PortResult::occupied(3000, vec![bare(1, "node")]),
            PortResult::inspection_error(80, Protocol::Tcp, "denied"),
        ];
        let v = parse(&render_json(&cases));
        let ports = v["ports"].as_array().unwrap();
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0]["port"], 8080);
        assert_eq!(ports[1]["port"], 3000);
        assert_eq!(ports[2]["port"], 80);
    }
}
