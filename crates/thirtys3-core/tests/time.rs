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

#[test]
fn iso_8601_is_the_form_s3_writes() {
    assert_eq!(Timestamp(0).iso8601(), "1970-01-01T00:00:00.000Z");
    assert_eq!(Timestamp(1_255_369_830).iso8601(), "2009-10-12T17:50:30.000Z");
    assert_eq!(Timestamp(-1).iso8601(), "1969-12-31T23:59:59.000Z");
    assert_eq!(Timestamp::parse_iso8601("2009-10-12T17:50:30.000Z"), Some(Timestamp(1_255_369_830)));
}

#[test]
fn iso_8601_reads_the_forms_in_the_documentation_and_offsets() {
    let base = Timestamp::parse_amz_date("20191211T233247Z").unwrap();
    assert_eq!(Timestamp::parse_iso8601("2019-12-11T23:32:47+00:00"), Some(base));
    assert_eq!(Timestamp::parse_iso8601("2019-12-11T23:32:47-00:00"), Some(base));
    assert_eq!(Timestamp::parse_iso8601("2019-12-11T23:32:47Z"), Some(base));
    assert_eq!(Timestamp::parse_iso8601("2019-12-11T23:32:47.123456Z"), Some(base));
    assert_eq!(Timestamp::parse_iso8601("2019-12-12T08:32:47+09:00"), Some(base));
    assert_eq!(Timestamp::parse_iso8601("2019-12-11T18:02:47-05:30"), Some(base));
}

#[test]
fn iso_8601_round_trips() {
    let mut seconds = -3_000_000_000_i64;
    while seconds < 7_000_000_000 {
        let time = Timestamp(seconds);
        assert_eq!(Timestamp::parse_iso8601(&time.iso8601()), Some(time), "{seconds}");
        seconds += 86_399;
    }
}

#[test]
fn text_that_is_not_iso_8601_is_refused() {
    for text in [
        "",
        "2019-12-11",
        "2019-12-11T23:32:47",
        "2019-12-11 23:32:47Z",
        "20191211T233247Z",
        "2019-12-11T23:32:47.Z",
        "2019-12-11T23:32:47+0000",
        "2019-12-11T23:32:47+24:00",
        "2019-12-11T23:32:47+00:60",
        "2019-13-11T23:32:47Z",
        "2019-02-30T23:32:47Z",
        "2019-12-11T24:00:00Z",
        "2019-12-11T23:32:47Zjunk",
        "２０１９-12-11T23:32:47Z",
        "2019-12-11T23:32:4é+00:00",
    ] {
        assert_eq!(Timestamp::parse_iso8601(text), None, "{text:?}");
    }
}
