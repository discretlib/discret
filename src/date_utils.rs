use chrono::{DateTime, Duration, NaiveDateTime, Utc};

///
/// current time in milliseconds since unix epoch
///
pub fn now() -> i64 {
    let dt = Utc::now();
    dt.timestamp_millis()
}

//returns the date without time
pub fn date(date_time: i64) -> i64 {
    let date = DateTime::from_timestamp_millis(date_time).unwrap();
    let ds: NaiveDateTime = date.date_naive().and_hms_opt(0, 0, 0).unwrap();
    ds.timestamp_millis()
}

//returns the next day without time
pub fn date_next_day(date_time: i64) -> i64 {
    let date = DateTime::from_timestamp_millis(date_time).unwrap();
    let date = date + Duration::days(1);
    let ds: NaiveDateTime = date.date_naive().and_hms_opt(0, 0, 0).unwrap();
    ds.timestamp_millis()
}
