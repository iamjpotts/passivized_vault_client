use base64::{DecodeError};

/// Convenience wrapper over base64 crate's breaking changes
pub fn base64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    STANDARD.decode(input)
}
/// Convenience wrapper over base64 crate's breaking changes
pub fn base64_encode<T: AsRef<[u8]>>(input: T) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    STANDARD.encode(input)
}