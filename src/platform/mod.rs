//! Cross-platform OS interaction layer.
//!
//! This is the **only** module allowed to touch the operating system directly.
//! Everything above it (CLI orchestration, kill sequencing, rendering) is
//! platform-agnostic and talks exclusively to the [`PlatformProvider`] trait.
//!
//! # Architecture rule: separate IO from parsing
//!
//! Each platform module (`linux`, `macos`, `windows`) is split into:
//!
//! * **IO functions** — read files, run `lsof`/`netstat`, call syscalls. These
//!   are thin, untested (they exercise real OS state) and never do string
//!   munging.
//! * **Pure parse functions** — take `&str` / `&[u8]` input, return structured
//!   data, and are exhaustively unit-tested against mock OS output.
//!
//! The `cfg` routing below picks exactly one concrete provider at compile time.

// `linux` is the compile-time default and is therefore compiled on *every*
// platform, but it is only reached on non-macOS/non-Windows hosts. On macOS and
// Windows the whole module is legitimately dormant (no call site reaches it), so
// we scope the allowance to exactly those platforms; on Linux the allow vanishes
// and genuinely unused items are still caught.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
use crate::error::AppError;
use crate::process::ProcessInfo;

/// Anything that can ask the operating system "who is on this port?" and
/// answer "is it free now?".
///
/// The trait is object-safe (`&self`, owned return types) so a single concrete
/// provider can be constructed once and shared, and so tests can substitute a
/// mock for the real OS.
pub trait PlatformProvider {
    /// Identify every process occupying `port` on TCP (LISTEN state).
    ///
    /// Returns an **empty** vec when the port is free or has no identifiable
    /// owner. Returns a multi-element vec when several processes share the port
    /// (e.g. `SO_REUSEPORT`). Distinguishing "free" from "occupied but
    /// unidentifiable" is the caller's job via [`is_port_free`].
    ///
    /// [`is_port_free`]: PlatformProvider::is_port_free
    fn get_processes_on_port(&self, port: u16) -> Result<Vec<ProcessInfo>, AppError>;

    /// Report whether `port` is currently free (nothing bound, LISTENING).
    ///
    /// This backs the "verify the port is actually free" post-kill claim and is
    /// deliberately independent of process identification so the kill loop can
    /// confirm success even when it cannot name the offending process.
    fn is_port_free(&self, port: u16) -> Result<bool, AppError>;

    /// Report whether `target_pid` is no longer occupying `port`.
    ///
    /// Unlike [`is_port_free`] — which is a *global* check and returns `false`
    /// as long as *any* process (e.g. a second `SO_REUSEPORT` worker) still
    /// holds the port — this verifies **this specific pid** dropped off. That is
    /// the correct post-kill claim for a shared port, where killing one worker
    /// must not be misreported as a failure just because a sibling still runs.
    ///
    /// The default does a port-wide free check first (fast path), then lists the
    /// occupants and treats the target as gone as long as it is absent from that
    /// list.
    ///
    /// [`is_port_free`]: PlatformProvider::is_port_free
    fn is_process_gone_from_port(&self, port: u16, target_pid: u32) -> Result<bool, AppError> {
        // Fast path: no one is on the port, so the target is certainly gone.
        if self.is_port_free(port)? {
            return Ok(true);
        }
        // Port still bound: succeed iff *this* pid no longer holds it.
        let occupants = self.get_processes_on_port(port)?;
        Ok(occupants.iter().all(|p| p.pid != target_pid))
    }
}

/// The single real provider, selected at compile time per `target_os`.
///
/// Constructing this requires no arguments and holds no state, so callers can
/// call [`default_provider`] whenever a platform handle is needed.
pub struct Platform;

impl PlatformProvider for Platform {
    #[cfg(target_os = "macos")]
    fn get_processes_on_port(&self, port: u16) -> Result<Vec<ProcessInfo>, AppError> {
        macos::get_processes_on_port(port)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn get_processes_on_port(&self, port: u16) -> Result<Vec<ProcessInfo>, AppError> {
        linux::get_processes_on_port(port)
    }
    #[cfg(target_os = "windows")]
    fn get_processes_on_port(&self, port: u16) -> Result<Vec<ProcessInfo>, AppError> {
        windows::get_processes_on_port(port)
    }

    #[cfg(target_os = "macos")]
    fn is_port_free(&self, port: u16) -> Result<bool, AppError> {
        macos::is_port_free(port)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn is_port_free(&self, port: u16) -> Result<bool, AppError> {
        linux::is_port_free(port)
    }
    #[cfg(target_os = "windows")]
    fn is_port_free(&self, port: u16) -> Result<bool, AppError> {
        windows::is_port_free(port)
    }
}

/// Convenience accessor returning a handle to the active platform provider.
pub fn default_provider() -> Platform {
    Platform
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_provider_is_constructible() {
        // Sanity: the trait object wires up without panicking.
        let _ = default_provider();
    }

    #[test]
    fn providers_are_object_safe() {
        // Compile-time check that PlatformProvider can be used as `dyn`.
        fn takes_dyn(_p: &dyn PlatformProvider) {}
        takes_dyn(&default_provider());
    }
}
