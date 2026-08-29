//! Core domain models that flow through the rest of the application.
//!
//! These types are deliberately **dumb data**. They do not know how to talk to
//! the OS, how to render themselves, or how to parse anything. Their only jobs
//! are to be constructed (`pub` fields), cloned, debug-printed, and serialized
//! to JSON. Separation of concerns: the `platform` layer *produces* them, the
//! `render` layer *consumes* them, and nothing in between cares where they came
//! from.

use serde::Serialize;

/// The network-layer protocol a process is bound to.
///
/// Kept as an enum (not a bool) so the JSON output and future features (e.g.
/// UDP inspection) remain unambiguous and stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Metadata describing a single process occupying a port.
///
/// Every field except [`pid`] and [`name`] is optional because not all
/// platforms can reliably report command/user/uptime/cwd for every process —
/// and a disciplined inspector would rather show `unknown` than crash or lie.
///
/// [`pid`]: ProcessInfo::pid
/// [`name`]: ProcessInfo::name
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessInfo {
    /// Operating-system process identifier (guaranteed present on all platforms).
    pub pid: u32,
    /// Short, human-friendly process name (e.g. `node`, `vite`, `com.docker`).
    pub name: String,
    /// Full command line with arguments, if the platform can recover it.
    pub command: Option<String>,
    /// Username of the process owner, if recoverable.
    pub user: Option<String>,
    /// Process uptime in whole seconds, if recoverable.
    pub uptime_secs: Option<u64>,
    /// Current working directory of the process, if recoverable.
    pub cwd: Option<String>,
}

impl ProcessInfo {
    /// Construct a process that carries only the guaranteed fields, leaving
    /// every piece of enrichable metadata as `None`.
    ///
    /// This is the canonical constructor for the "we found the PID but know
    /// nothing else" path; callers may then `.fill_metadata(...)` on top.
    pub fn bare(pid: u32, name: String) -> Self {
        Self {
            pid,
            name,
            command: None,
            user: None,
            uptime_secs: None,
            cwd: None,
        }
    }
}

/// A single port bound on the local machine, along with the process occupying it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortInfo {
    /// The bound port number.
    pub port: u16,
    /// Which protocol family binds this port.
    pub protocol: Protocol,
    /// The process occupying the port, if one could be identified.
    ///
    /// When a single port is shared by several processes (e.g. `SO_REUSEPORT`),
    /// the discovery layer emits one `PortInfo` per `(protocol, pid)` pair so a
    /// human or script never conflates distinct owners.
    pub process: Option<ProcessInfo>,
}

impl PortInfo {
    /// Create a `PortInfo` that reports the port as bound but with no known owner.
    pub fn occupied_unknown(port: u16, protocol: Protocol) -> Self {
        Self {
            port,
            protocol,
            process: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_info_bare_leaves_metadata_none() {
        let p = ProcessInfo::bare(4242, "node".into());
        assert_eq!(p.pid, 4242);
        assert_eq!(p.name, "node");
        assert!(p.command.is_none());
        assert!(p.user.is_none());
        assert!(p.uptime_secs.is_none());
        assert!(p.cwd.is_none());
    }

    #[test]
    fn process_info_serializes_to_expected_shape() {
        let p = ProcessInfo {
            pid: 44122,
            name: "node".into(),
            command: Some("node server.js".into()),
            user: Some("alijoder".into()),
            uptime_secs: Some(3724),
            cwd: Some("/Users/alijoder/proj".into()),
        };
        let json = serde_json::to_value(&p).unwrap();
        let obj = json.as_object().unwrap();
        // Field names are the machine-stable contract promised in the README.
        for key in ["pid", "name", "command", "user", "uptime_secs", "cwd"] {
            assert!(obj.contains_key(key), "missing serialized field {key}");
        }
    }

    #[test]
    fn protocol_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Protocol::Tcp).unwrap(), r#""tcp""#);
        assert_eq!(serde_json::to_string(&Protocol::Udp).unwrap(), r#""udp""#);
    }
}
