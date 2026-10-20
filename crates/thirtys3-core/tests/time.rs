//! `YYYYMMDDTHHMMSSZ` dates.

use thirtys3_core::Timestamp;

#[test]
fn known_instants() {
    assert_eq!(Timestamp(0).amz_date(), "19700101T000000Z");
    assert_eq!(Timestamp(1_369_353_600).amz_date(), "20130524T000000Z");
    assert_eq!(Timestamp(1_369_353_600).date(), "20130524");
    assert_eq!(Timestamp(1_709_208_000).amz_date(), "20240229T120000Z");
    assert_eq!(Timestamp(-1).amz_date(), "19691231T235959Z");
    assert_eq!(Timestamp::parse_amz_date("20130524T000000Z"), Some(Timestamp(1_369_353_600)));
    assert_eq!(Timestamp::parse_amz_date("19700101T000000Z"), Some(Timestamp(0)));
    assert_eq!(Timestamp::parse_amz_date("20991231T235959Z"), Some(Timestamp(4_102_444_799)));
}

#[test]
fn formatting_and_parsing_are_inverse_across_many_years() {
    let mut seconds = -3_000_000_000_i64;
    while seconds < 7_000_000_000 {
        let time = Timestamp(seconds);
        assert_eq!(Timestamp::parse_amz_date(&time.amz_date()), Some(time), "{seconds}");
        assert!(time.amz_date().starts_with(&time.date()));
        seconds += 86_399; // not a whole day, so the time of day changes too
    }
}

#[test]
fn leap_days() {
    assert!(Timestamp::parse_amz_date("20240229T000000Z").is_some());
    assert!(Timestamp::parse_amz_date("20000229T000000Z").is_some());
    assert!(Timestamp::parse_amz_date("19000229T000000Z").is_none());
    assert!(Timestamp::parse_amz_date("20230229T000000Z").is_none());
    assert!(Timestamp::parse_amz_date("20240230T000000Z").is_none());
}

#[test]
fn text_that_is_not_a_date_is_refused() {
    for text in [
        "",
        "20130524",
        "20130524T000000",
        "20130524T000000z",
        "20130524 000000Z",
        "2013-05-24T00:00:00Z",
        "20131324T000000Z",
        "20130024T000000Z",
        "20130500T000000Z",
        "20130532T000000Z",
        "20130524T240000Z",
        "20130524T006000Z",
        "20130524T000060Z",
        "20130524T00000XZ",
        "+0130524T000000Z",
        "20130524T000000Z ",
        "２０１３０５２４T000000Z",
    ] {
        assert_eq!(Timestamp::parse_amz_date(text), None, "{text:?}");
    }
}

#[test]
fn now_is_after_the_year_2025() {
    assert!(Timestamp::now().0 > 1_735_689_600);
}
