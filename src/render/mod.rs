//! Presentation layer: turns Phase-2/3 data into polished terminal output.
//!
//! This module is deliberately **pure**. It contains no OS calls and no
//! knowledge of `pk`'s execution flow — it only knows how to draw the
//! [`PortResult`] slice the orchestrator hands it. That makes both renderers
//! trivial to unit-test without a PTY.
//!
//! * [`table::render_table`] — the human view (stdout).
//! * [`json::render_json`] — the machine view (`--json`, also stdout).
//! * [`types`] — the view models and render options shared by both.
//!
//! All fatal string escaping lives here; `crate::app` only decides *what* runs,
//! never *how* it is drawn.

pub mod json;
pub mod table;
pub mod types;

pub use json::render_json;
pub use table::render_table;
pub use types::{PortResult, ProcessStatus, RunMode, SignalKind, TableOptions};
