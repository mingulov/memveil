// SPDX-License-Identifier: GPL-3.0-or-later
//! Display-filter resolution over the device catalog.
//!
//! The `--device` option accepts an exact device id or an exact
//! catalog name; rows always carry ids, so a name resolves to
//! its id before any renderer compares. Ids take precedence
//! over names when one device's name equals another's id, and
//! unknown filters pass through to match no rows.

use crate::model::report::Report;
use crate::model::session::DeviceEntry;

/// Map an exact catalog name to its id; ids pass through.
pub fn resolve_device_filter(devices: &[DeviceEntry], filt: &str) -> String {
    if filt.is_empty() {
        return String::new();
    }
    for device in devices {
        if device.device_id == filt {
            return filt.to_string();
        }
    }
    for device in devices {
        if device.name == filt {
            return device.device_id.clone();
        }
    }
    filt.to_string()
}

/// True when the filter would show device rows.
///
/// Empty always resolves. Otherwise the filter must name
/// a catalog id or name, or match an observed metric's
/// device id after catalog resolution: live reports grow
/// rows for devices no catalog entry admits yet.
pub fn device_filter_resolves(rep: &Report, filt: &str) -> bool {
    if filt.is_empty() {
        return true;
    }
    for device in &rep.devices {
        if device.device_id == filt {
            return true;
        }
    }
    for device in &rep.devices {
        if device.name == filt {
            return true;
        }
    }
    let rid = resolve_device_filter(&rep.devices, filt);
    for metric in &rep.metrics {
        if metric.has_device_id && metric.device_id == rid {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::metric::Metric;

    fn catalog() -> Vec<DeviceEntry> {
        vec![
            DeviceEntry {
                device_id: "dev-1".to_string(),
                name: "testdev0".to_string(),
                ..DeviceEntry::default()
            },
            DeviceEntry {
                device_id: "dev-2".to_string(),
                name: "eth1".to_string(),
                ..DeviceEntry::default()
            },
        ]
    }

    #[test]
    fn empty_filter_passes_through() {
        assert_eq!(resolve_device_filter(&catalog(), ""), "");
    }

    #[test]
    fn id_filter_passes_through() {
        assert_eq!(resolve_device_filter(&catalog(), "dev-1"), "dev-1");
    }

    #[test]
    fn name_resolves_to_id() {
        assert_eq!(resolve_device_filter(&catalog(), "testdev0"), "dev-1");
    }

    #[test]
    fn id_takes_precedence_over_name() {
        let devices = vec![
            DeviceEntry {
                device_id: "dev-2".to_string(),
                name: "plain".to_string(),
                ..DeviceEntry::default()
            },
            DeviceEntry {
                device_id: "dev-9".to_string(),
                name: "dev-2".to_string(),
                ..DeviceEntry::default()
            },
        ];
        assert_eq!(resolve_device_filter(&devices, "dev-2"), "dev-2");
    }

    #[test]
    fn unknown_filter_passes_through() {
        assert_eq!(resolve_device_filter(&catalog(), "nope"), "nope");
    }

    #[test]
    fn resolves_empty_id_and_name() {
        let rep = Report {
            devices: catalog(),
            ..Report::default()
        };
        assert!(device_filter_resolves(&rep, ""));
        assert!(device_filter_resolves(&rep, "dev-1"));
        assert!(device_filter_resolves(&rep, "testdev0"));
        assert!(!device_filter_resolves(&rep, "nope"));
    }

    #[test]
    fn resolves_observed_metric_device() {
        let mut rep = Report::default();
        rep.metrics.push(Metric {
            name: "bounce_attempts".to_string(),
            has_device_id: true,
            device_id: "dev-live".to_string(),
            ..Metric::default()
        });
        assert!(device_filter_resolves(&rep, "dev-live"));
        assert!(!device_filter_resolves(&rep, "dev-absent"));
    }
}
