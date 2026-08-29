//! Port-range resolution.
//!
//! v1.0 accepts single ports (`3000`), multiple ports (`3000 8080`), and ranges
//! (`9000-9005`). This module turns raw user strings into a validated, flat
//! list of `u16` ports, rejecting anything out of range or malformed with an
//! actionable message.

use crate::error::AppError;

/// Expand a list of user-supplied port specs (singles and `a-b` ranges) into a
/// flat, de-duplicated `u16` port list.
///
/// * `"3000"` → `[3000]`
/// * `"3000-3002"` → `[3000, 3001, 3002]`
/// * `"80"` `"3000-3001"` → `[80, 3000, 3001]`
///
/// Ports strictly out of `1..=65535` (including range bounds) are rejected
/// before they ever reach the platform layer.
pub fn resolve_ports(specs: &[String]) -> Result<Vec<u16>, AppError> {
    let mut out: Vec<u16> = Vec::new();
    for spec in specs {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(range_error(spec, "empty port spec"));
        }
        if let Some(dash) = spec.find('-') {
            // Range form: `a-b`
            let lo = &spec[..dash];
            let hi = &spec[dash + 1..];
            if lo.is_empty() || hi.is_empty() {
                return Err(range_error(spec, "a range needs both a start and an end"));
            }
            let lo = parse_bound(lo)?;
            let hi = parse_bound(hi)?;
            if lo > hi {
                return Err(range_error(spec, "range start is greater than its end"));
            }
            let span = (hi - lo + 1) as usize;
            if span > 65_536 {
                return Err(range_error(spec, "range is too large"));
            }
            out.extend(lo..=hi);
        } else {
            // Single port
            let p = parse_bound(spec)?;
            out.push(p);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn parse_bound(raw: &str) -> Result<u16, AppError> {
    let value: u32 = raw.parse().map_err(|_| AppError::InvalidPort {
        raw: raw.to_string(),
        reason: "not a number".into(),
    })?;
    if value == 0 || value > u16::MAX as u32 {
        return Err(AppError::InvalidPort {
            raw: raw.to_string(),
            reason: format!("port must be between 1 and {}", u16::MAX),
        });
    }
    Ok(value as u16)
}

fn range_error(raw: &str, reason: &str) -> AppError {
    AppError::InvalidPort {
        raw: raw.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(specs: &[&str]) -> Vec<String> {
        specs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn single_port() {
        assert_eq!(resolve_ports(&v(&["3000"])).unwrap(), vec![3000]);
    }

    #[test]
    fn multiple_ports() {
        assert_eq!(
            resolve_ports(&v(&["3000", "8080"])).unwrap(),
            vec![3000, 8080]
        );
    }

    #[test]
    fn single_range() {
        assert_eq!(
            resolve_ports(&v(&["3000-3002"])).unwrap(),
            vec![3000, 3001, 3002]
        );
    }

    #[test]
    fn mixed_singles_and_ranges() {
        assert_eq!(
            resolve_ports(&v(&["80", "3000-3001", "443"])).unwrap(),
            vec![80, 443, 3000, 3001]
        );
    }

    #[test]
    fn overlapping_input_is_deduplicated() {
        assert_eq!(
            resolve_ports(&v(&["3000", "3000-3001", "3001"])).unwrap(),
            vec![3000, 3001]
        );
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(resolve_ports(&v(&["0"])).is_err());
        assert!(resolve_ports(&v(&["65536"])).is_err());
        assert!(resolve_ports(&v(&["70000"])).is_err());
        assert!(resolve_ports(&v(&["1-70000"])).is_err());
    }

    #[test]
    fn rejects_non_numeric_and_bad_ranges() {
        assert!(resolve_ports(&v(&["abc"])).is_err());
        assert!(resolve_ports(&v(&["3000-"])).is_err());
        assert!(resolve_ports(&v(&["-3000"])).is_err());
        assert!(resolve_ports(&v(&["3002-3000"])).is_err());
        assert!(resolve_ports(&v(&[""])).is_err());
    }

    #[test]
    fn port_one_is_valid() {
        assert_eq!(resolve_ports(&v(&["1"])).unwrap(), vec![1]);
    }
}
