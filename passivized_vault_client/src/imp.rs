
/// Get the header value if it's present and valid.
pub(crate) fn header_value(response: &reqwest::Response, header: &str) -> Option<String> {
    if let Some(hv) = response.headers().get(header) {
        match hv.to_str() {
            Ok(s) => Some(s.to_string()),
            // If it's not UTF8 we don't care about it
            Err(_) => None
        }
    }
    else {
        None
    }
}
