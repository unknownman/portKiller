//! Port-range parsing.
//!
//! v1.0 accepts single ports (`3000`), multiple ports (`3000 8080`), and
//! ranges (`9000-9005`). This module turns raw user strings into validated
//! `u16` values. Parsing logic lands in a later phase; the public types needed
//! by the platform layer are declared here as placeholders.
