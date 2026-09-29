//! Integer-only text formats from docs/tui/PROMPT.md §7.3.

use chrono::{DateTime, Local, TimeZone};

/// Format runtime cost units using the existing million-units-per-dollar scale.
pub fn cost(value: u64) -> String {
    let rounded = value.saturating_add(50) / 100;
    if value > 0 && rounded == 0 {
        return "<$0.0001".into();
    }
    format!("${}.{:04}", rounded / 10_000, rounded % 10_000)
}

/// Format an unpriced model's cost.
pub fn cost_unpriced() -> &'static str {
    "cost n/a"
}

/// Format token counts with integer half-up rounding.
pub fn tokens(n: u64) -> String {
    if n < 1_000 {
        n.to_string()
    } else if n < 999_950 {
        let tenths = n.saturating_add(50) / 100;
        format!("{}.{:01}k", tenths / 10, tenths % 10)
    } else {
        let tenths = n.saturating_add(50_000) / 100_000;
        format!("{}.{:01}M", tenths / 10, tenths % 10)
    }
}

/// Format elapsed milliseconds as tenths of a second, seconds, or minutes.
pub fn duration(ms: u64) -> String {
    let tenths = ms.saturating_add(50) / 100;
    if tenths < 100 {
        format!("{}.{:01}s", tenths / 10, tenths % 10)
    } else {
        let seconds = ms.saturating_add(500) / 1_000;
        if seconds < 60 {
            format!("{seconds}s")
        } else {
            format!("{}m {:02}s", seconds / 60, seconds % 60)
        }
    }
}

/// Format a local timestamp as HH:MM.
pub fn time_of_day(time: DateTime<Local>) -> String {
    time.format("%H:%M").to_string()
}

/// Format a local activity timestamp as HH:MM:SS.
pub fn activity_time(time: DateTime<Local>) -> String {
    time.format("%H:%M:%S").to_string()
}

/// Format an instant using the host's local timezone.
pub fn local_time(timestamp: i64, with_seconds: bool) -> Option<String> {
    Local.timestamp_opt(timestamp, 0).single().map(|time| {
        if with_seconds {
            activity_time(time)
        } else {
            time_of_day(time)
        }
    })
}

/// Format relative recency in whole units, flooring each interval.
pub fn recency(seconds: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    const WEEK: u64 = 7 * DAY;
    const YEAR: u64 = 52 * WEEK;
    if seconds < MINUTE {
        "now".into()
    } else if seconds < HOUR {
        format!("{}m", seconds / MINUTE)
    } else if seconds < DAY {
        format!("{}h", seconds / HOUR)
    } else if seconds < WEEK {
        format!("{}d", seconds / DAY)
    } else if seconds < YEAR {
        format!("{}w", seconds / WEEK)
    } else {
        format!("{}y", seconds / YEAR)
    }
}

/// Return the short display form of a session ID.
pub fn short_session_id(id: &str) -> &str {
    let short = id.strip_prefix("session-").unwrap_or(id);
    let end = short.char_indices().nth(8).map_or(short.len(), |(i, _)| i);
    &short[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_rounds_integer_units() {
        assert_eq!(cost(0), "$0.0000");
        assert_eq!(cost(49), "<$0.0001");
        assert_eq!(cost(50), "$0.0001");
        assert_eq!(cost(12_345_678), "$12.3457");
        assert_eq!(cost_unpriced(), "cost n/a");
    }

    #[test]
    fn token_boundaries_and_rounding() {
        assert_eq!(tokens(999), "999");
        assert_eq!(tokens(1_000), "1.0k");
        assert_eq!(tokens(18_250), "18.3k");
        assert_eq!(tokens(999_949), "999.9k");
        assert_eq!(tokens(999_950), "1.0M");
        assert_eq!(tokens(1_250_000), "1.3M");
    }

    #[test]
    fn duration_boundaries_and_rounding() {
        assert_eq!(duration(0), "0.0s");
        assert_eq!(duration(3_950), "4.0s");
        assert_eq!(duration(59_499), "59s");
        assert_eq!(duration(59_500), "1m 00s");
        assert_eq!(duration(125_000), "2m 05s");
    }

    #[test]
    fn recency_floors_intervals() {
        assert_eq!(recency(59), "now");
        assert_eq!(recency(60), "1m");
        assert_eq!(recency(3_599), "59m");
        assert_eq!(recency(604_800), "1w");
        assert_eq!(recency(31_449_600), "1y");
    }

    #[test]
    fn short_id_drops_prefix_and_limits_to_eight_chars() {
        assert_eq!(
            short_session_id("session-01J8ZK4QX2M7C9RT5VWEHN3B6D"),
            "01J8ZK4Q"
        );
        assert_eq!(short_session_id("abcdefghi"), "abcdefgh");
        assert_eq!(short_session_id("short"), "short");
    }
}
