use std::time::SystemTime;
use time::OffsetDateTime;

pub fn named<S>(name: S) -> String where S: Into<String> {
    name.into() + "-" + &now()
}

fn now() -> String {
    let now_st = SystemTime::now();
    let now_ot: OffsetDateTime = now_st.into();

    let mut result = now_ot
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
        .replace("-", "")
        .replace(":", "")
        .replace("T", "-");

    result.truncate(15);

    result
}
