//! The one date format Signature Version 4 uses, ISO 8601 basic format in UTC: `20130524T000000Z`.

use std::time::{SystemTime, UNIX_EPOCH};

/// A point in time with a resolution of one second, as seconds since 1970-01-01T00:00:00Z.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub i64);

/// Days from 1970-01-01 to the given day of the proleptic Gregorian calendar (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146097 + day_of_era - 719468
}

/// The year, month and day for a number of days since 1970-01-01 (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719468;
    let era = days.div_euclid(146097);
    let day_of_era = days - era * 146097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = if month_part < 10 { month_part + 3 } else { month_part - 9 };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        _ => 28,
    }
}

impl Timestamp {
    /// The current time.
    pub fn now() -> Self {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(after) => Self(after.as_secs() as i64),
            Err(before) => Self(-(before.duration().as_secs() as i64)),
        }
    }

    /// `YYYYMMDDTHHMMSSZ`, the value of `X-Amz-Date` and `x-amz-date`.
    pub fn amz_date(self) -> String {
        let (year, month, day) = civil_from_days(self.0.div_euclid(86400));
        let seconds = self.0.rem_euclid(86400);
        format!("{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z", seconds / 3600, seconds % 3600 / 60, seconds % 60)
    }

    /// `YYYYMMDD`, the date in a credential scope.
    pub fn date(self) -> String {
        let (year, month, day) = civil_from_days(self.0.div_euclid(86400));
        format!("{year:04}{month:02}{day:02}")
    }

    /// Reads `YYYYMMDDTHHMMSSZ`. Returns `None` for anything else, including a date that does not exist.
    pub fn parse_amz_date(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 16 || bytes[8] != b'T' || bytes[15] != b'Z' {
            return None;
        }
        let number = |range: std::ops::Range<usize>| -> Option<i64> {
            let digits = &bytes[range];
            if !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            Some(digits.iter().fold(0, |value, digit| value * 10 + i64::from(digit - b'0')))
        };
        let (year, month, day) = (number(0..4)?, number(4..6)?, number(6..8)?);
        let (hour, minute, second) = (number(9..11)?, number(11..13)?, number(13..15)?);
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) || hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        Some(Self(days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second))
    }
}
