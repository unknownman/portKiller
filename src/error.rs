//! Unified error type for `pk`.
//!
//! Every error carries a message that is **actionable** for the user: it states
//! *what* went wrong and, where possible, *what to do about it*. These messages
//! are surfaced verbatim on the CLI's error path, so they read like guidance,
//! not like a stack trace.
//!
//! The enum deliberately has a small, semantic surface area rather than one
//! variant per raw OS failure. Lower-level failures are normalised into these
//! variants at the platform boundary so the rest of the codebase stays
//! platform-agnostic.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// Ports are 1-65535; rejecting anything else at the boundary prevents
    /// garbage values from ever reaching the platform layer.
    #[error("invalid port `{raw}`: {reason}")]
    InvalidPort { raw: String, reason: String },

    /// The OS refused to let us inspect the port — most commonly a privileged
    /// port (<1024) owned by another user / root.
    #[error(
        "port {port} requires elevated privileges to inspect or is protected by the system. \
         Try running `pk` with `sudo` (on macOS/Linux)."
    )]
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    // constructed only by the unix providers / unix signal impl
    AccessDenied { port: u16 },

    /// A platform command (e.g. `lsof`, `netstat`) exited non-zero.
    #[error("the system command `{command}` failed: {message}")]
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    // constructed only by the macos/windows providers
    OsCommandFailed {
        command: &'static str,
        message: String,
    },

    /// The raw bytes a platform produced could not be understood.
    #[error("failed to interpret operating-system output for port {port}: {reason}")]
    #[allow(dead_code)] // constructed by the linux provider, dormant on non-Linux hosts
    UnparseableOutput { port: u16, reason: String },

    /// Filesystem reads that are not access-control related (e.g. `/proc` races
    /// where a process vanished mid-scan).
    #[error("could not read {path}: {source}")]
    #[allow(dead_code)] // constructed by the linux provider, dormant on non-Linux hosts
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// A raw OS API call returned an unexpected status that is not a denied
    /// access. Kept generic; the platform module attaches context.
    #[error("operating-system API error: {message}")]
    #[allow(dead_code)] // reserved for platform code that is dormant on this host
    OsApi { message: String },

    /// A requested kill could not be delivered or the port refused to free.
    #[error("{message}")]
    KillFailed { message: String },

    /// Usage or internal invariant violated — the "this is our fault" bucket.
    #[error("{message}")]
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    // constructed only by the unix signal impl
    Internal { message: String },
}

impl AppError {
    /// Convenience constructor for the internal/bug bucket.
    #[cfg_attr(target_os = "windows", allow(dead_code))] // constructed only by the unix signal impl
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Convenience constructor for the kill bucket.
    pub fn kill_failed(message: impl Into<String>) -> Self {
        Self::KillFailed {
            message: message.into(),
        }
    }

    /// Convenience constructor for the I/O bucket that embeds the offending
    /// `path`, so callers can write `AppError::io(path, e)?` without building
    /// the variant by hand.
    #[allow(dead_code)] // used by the linux provider, dormant on non-Linux hosts
    pub fn io(path: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_user_actionable() {
        let err = AppError::AccessDenied { port: 80 };
        let msg = err.to_string();
        assert!(msg.contains("80"), "message should name the port");
        assert!(msg.contains("sudo"), "message should suggest sudo");
    }

    #[test]
    fn invalid_port_includes_reason() {
        let err = AppError::InvalidPort {
            raw: "abc".into(),
            reason: "not a number".into(),
        };
        assert!(err.to_string().contains("abc"));
        assert!(err.to_string().contains("not a number"));
    }

    #[test]
    fn io_variant_carries_path_and_source() {
        let underlying = std::io::Error::new(std::io::ErrorKind::NotFound, "boom");
        let err = AppError::io("/proc/9999/status", underlying);
        let msg = err.to_string();
        assert!(msg.contains("/proc/9999/status"));
        assert!(msg.contains("boom"));
    }
}
