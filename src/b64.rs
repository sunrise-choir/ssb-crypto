pub(crate) fn decode(mut s: &str, mut buf: &mut [u8], suffix: Option<&str>) -> bool {
    if let Some(suffix) = suffix {
        if let Some(idx) = s.rfind(suffix) {
            s = &s[..idx]
        }
    }

    // encoded byte length is ceil(size_of<T> * 4 / 3)
    // plus enough padding bytes ('=') to make it a multiple of 4
    let bytes = (buf.len() as f64 * 4.0 / 3.0).ceil() as usize;
    let padding = 4 - bytes % 4;

    if s.len() != bytes + padding {
        return false;
    }

    if s.trim_end_matches('=').len() != bytes {
        return false;
    }

    base64::decode_config_slice(s, base64::STANDARD, &mut buf).is_ok()
}
