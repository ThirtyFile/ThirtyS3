//! HTTP dates, as the `Date` header and `Last-Modified` have them.

use thirtys3_core::Timestamp;

#[test]
fn http_dates_are_written_as_rfc_9110_says() {
    assert_eq!(Timestamp(784_111_777).http_date(), "Sun, 06 Nov 1994 08:49:37 GMT");
    // The date the S3 documentation uses in its examples, and the weekday it gives.
    assert_eq!(Timestamp(1_369_353_600).http_date(), "Fri, 24 May 2013 00:00:00 GMT");
    assert_eq!(Timestamp(0).http_date(), "Thu, 01 Jan 1970 00:00:00 GMT");
    assert_eq!(Timestamp(-1).http_date(), "Wed, 31 Dec 1969 23:59:59 GMT");
    assert_eq!(Timestamp(1_709_208_000).http_date(), "Thu, 29 Feb 2024 12:00:00 GMT");
}

#[test]
fn the_three_http_date_forms_are_read() {
    let expected = Some(Timestamp(784_111_777));
    assert_eq!(Timestamp::parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), expected);
    assert_eq!(Timestamp::parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), expected);
    assert_eq!(Timestamp::parse_http_date("Sun Nov  6 08:49:37 1994"), expected);
    assert_eq!(Timestamp::parse_http_date("  Sun, 06 Nov 1994 08:49:37 GMT  "), expected);
    // Two-digit years: below 70 is 20xx.
    assert_eq!(Timestamp::parse_http_date("Friday, 24-May-13 00:00:00 GMT"), Some(Timestamp(1_369_353_600)));
    assert_eq!(Timestamp::parse_http_date("Thursday, 01-Jan-70 00:00:00 GMT"), Some(Timestamp(0)));
    assert_eq!(Timestamp::parse_http_date("Sun Nov 16 08:49:37 1994"), Some(Timestamp(784_111_777 + 10 * 86400)));
}

#[test]
fn http_dates_round_trip() {
    let mut seconds = -3_000_000_000_i64;
    while seconds < 7_000_000_000 {
        let time = Timestamp(seconds);
        assert_eq!(Timestamp::parse_http_date(&time.http_date()), Some(time), "{seconds}");
        seconds += 86_399;
    }
}

#[test]
fn text_that_is_not_an_http_date_is_refused() {
    for text in [
        "",
        "Sun, 06 Nov 1994",
        "Sun, 06 Nov 1994 08:49:37",
        "Sun, 06 Nov 1994 08:49:37 UTC",
        "Sun, 06 Nov 1994 08:49:37 +0000",
        "Sun, 6 Nov 1994 08:49:37 GMT",
        "Xyz, 06 Nov 1994 08:49:37 GMT",
        "Sun, 06 Nxv 1994 08:49:37 GMT",
        "Sun, 31 Nov 1994 08:49:37 GMT",
        "Sun, 30 Feb 2024 08:49:37 GMT",
        "Sun, 06 Nov 1994 24:00:00 GMT",
        "Sun, 06 Nov 1994 08:60:00 GMT",
        "Sun, 06 Nov 94 08:49:37 GMT",
        "Sunday, 06-Nov-1994 08:49:37 GMT",
        "Sun Nov  6 08:49:37",
        "2013-05-24T00:00:00Z",
        "20130524T000000Z",
        "Sun, 06 Nov 1994 08:49:37 GMT extra",
        "Sün, 06 Nov 1994 08:49:37 GMT",
        "Sun, 06 Nov 1994 08:49:3é GMT",
    ] {
        assert_eq!(Timestamp::parse_http_date(text), None, "{text:?}");
    }
}
