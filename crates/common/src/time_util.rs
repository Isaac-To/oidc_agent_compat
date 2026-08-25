//! Shared time helpers for the relay and central proxies.
//!
//! Both proxies record timestamps in their activity/audit logs using the
//! same `time` crate formatting. These helpers were previously copy-pasted
//! (byte-for-byte) in five files across the two crates; centralizing them
//! here eliminates that duplication and guarantees a single format string.

use time::PrimitiveDateTime;
use time::macros::format_description;

/// The canonical timestamp format used in activity/audit log records:
/// `YYYY-MM-DD HH:MM:SS` (UTC).
const TIMESTAMP_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

/// Returns the current UTC time as a [`PrimitiveDateTime`] (no timezone
/// offset), suitable for sea-orm `TimeDateTime` columns.
#[must_use]
pub fn now_utc() -> PrimitiveDateTime {
    let offset = time::OffsetDateTime::now_utc();
    PrimitiveDateTime::new(offset.date(), offset.time())
}

/// Formats a [`PrimitiveDateTime`] using the canonical log timestamp format.
///
/// Returns an empty string if formatting fails (which only happens if the
/// timestamp is out of the format's representable range — not in practice).
#[must_use]
pub fn format_time(t: &PrimitiveDateTime) -> String {
    t.format(&TIMESTAMP_FORMAT).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_time_roundtrips_expected_shape() {
        let dt = PrimitiveDateTime::new(
            time::Date::from_calendar_date(2026, time::Month::August, 25).unwrap(),
            time::Time::from_hms(13, 14, 15).unwrap(),
        );
        assert_eq!(format_time(&dt), "2026-08-25 13:14:15");
    }

    #[test]
    fn now_utc_is_recent() {
        let now = now_utc();
        // The year should be plausibly current (guard against gross errors).
        assert!(now.year() >= 2026);
    }
}
