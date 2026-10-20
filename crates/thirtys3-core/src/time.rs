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

    /// `YYYY-MM-DDTHH:MM:SS.000Z`, the form of `LastModified` and the other timestamps in S3 results.
    pub fn iso8601(self) -> String {
        let (year, month, day) = civil_from_days(self.0.div_euclid(86400));
        let seconds = self.0.rem_euclid(86400);
        format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z", seconds / 3600, seconds % 3600 / 60, seconds % 60)
    }

    /// Reads `YYYY-MM-DDTHH:MM:SS`, then optionally a fraction of a second (dropped), then `Z` or an offset `+HH:MM` or `-HH:MM`. Both the form of
    /// the examples in the S3 documentation (`2019-12-11T23:32:47+00:00`) and the form S3 sends (`2009-10-12T17:50:30.000Z`) are read.
    pub fn parse_iso8601(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if !text.is_ascii() || bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' || bytes[13] != b':' || bytes[16] != b':' {
            return None;
        }
        let compact = format!("{}{}{}T{}{}{}Z", &text[0..4], &text[5..7], &text[8..10], &text[11..13], &text[14..16], &text[17..19]);
        let base = Self::parse_amz_date(&compact)?;
        let mut rest = &text[19..];
        if let Some(fraction) = rest.strip_prefix('.') {
            let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                return None;
            }
            rest = &fraction[digits..];
        }
        match rest {
            "Z" => Some(base),
            offset if offset.len() == 6 && matches!(offset.as_bytes()[0], b'+' | b'-') && offset.as_bytes()[3] == b':' => {
                let hours: i64 = offset[1..3].parse().ok()?;
                let minutes: i64 = offset[4..6].parse().ok()?;
                if hours > 23 || minutes > 59 {
                    return None;
                }
                let shift = hours * 3600 + minutes * 60;
                Some(Self(if offset.starts_with('+') { base.0 - shift } else { base.0 + shift }))
            }
            _ => None,
        }
    }

    /// `Fri, 24 May 2013 00:00:00 GMT`, the HTTP date of RFC 9110 (the form of `Date`, `Last-Modified` and `Expires`).
    pub fn http_date(self) -> String {
        let days = self.0.div_euclid(86400);
        let (year, month, day) = civil_from_days(days);
        let seconds = self.0.rem_euclid(86400);
        // 1970-01-01 was a Thursday.
        let weekday = WEEKDAYS[(days + 3).rem_euclid(7) as usize];
        format!("{weekday}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT", MONTHS[(month - 1) as usize], seconds / 3600, seconds % 3600 / 60, seconds % 60)
    }

    /// Reads an HTTP date in any of the three forms RFC 9110 says a recipient has to accept: `Sun, 06 Nov 1994 08:49:37 GMT`,
    /// `Sunday, 06-Nov-94 08:49:37 GMT` (a two-digit year below 70 is 20xx, otherwise 19xx) and `Sun Nov  6 08:49:37 1994`. The day of the week has to be
    /// a real one but is not checked against the date.
    pub fn parse_http_date(text: &str) -> Option<Self> {
        let text = text.trim();
        if !text.is_ascii() {
            return None;
        }
        let month = |name: &str| MONTHS.iter().position(|candidate| *candidate == name).map(|index| index as i64 + 1);
        let number = |digits: &str, length: usize| -> Option<i64> {
            (digits.len() == length && digits.bytes().all(|byte| byte.is_ascii_digit())).then(|| digits.parse().ok()).flatten()
        };
        let clock = |time: &str| -> Option<(i64, i64, i64)> {
            let parts: Vec<&str> = time.split(':').collect();
            let [hour, minute, second] = parts[..] else { return None };
            Some((number(hour, 2)?, number(minute, 2)?, number(second, 2)?))
        };
        let (year, month, day, (hour, minute, second)) = if let Some((weekday, rest)) = text.split_once(", ") {
            let fields: Vec<&str> = rest.split(' ').collect();
            if WEEKDAYS.contains(&weekday) {
                // Sun, 06 Nov 1994 08:49:37 GMT
                let [day, month_name, year, time, "GMT"] = fields[..] else { return None };
                (number(year, 4)?, month(month_name)?, number(day, 2)?, clock(time)?)
            } else if LONG_WEEKDAYS.contains(&weekday) {
                // Sunday, 06-Nov-94 08:49:37 GMT
                let [date, time, "GMT"] = fields[..] else { return None };
                let parts: Vec<&str> = date.split('-').collect();
                let [day, month_name, year] = parts[..] else { return None };
                let year = number(year, 2)?;
                (if year < 70 { 2000 + year } else { 1900 + year }, month(month_name)?, number(day, 2)?, clock(time)?)
            } else {
                return None;
            }
        } else {
            // Sun Nov  6 08:49:37 1994
            let fields: Vec<&str> = text.split(' ').filter(|field| !field.is_empty()).collect();
            let [weekday, month_name, day, time, year] = fields[..] else { return None };
            if !WEEKDAYS.contains(&weekday) {
                return None;
            }
            let day = if day.len() == 1 { number(&format!("0{day}"), 2)? } else { number(day, 2)? };
            (number(year, 4)?, month(month_name)?, day, clock(time)?)
        };
        if day < 1 || day > days_in_month(year, month) || hour > 23 || minute > 59 || second > 60 {
            return None;
        }
        // A leap second (60) is read as the second it is after.
        Some(Self(days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second))
    }
}

const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const LONG_WEEKDAYS: [&str; 7] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
