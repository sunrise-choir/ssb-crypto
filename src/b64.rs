pub(crate) fn decode(mut s: &str, mut buf: &mut [u8], suffix: Option<&str>) -> bool {
    if let Some(suffix) = suffix {
        if let Some(idx) = s.rfind(suffix) {
            s = &s[..idx]
        }
    }

    // encoded byte length is ceil(size_of<T> * 4 / 3)
    // plus enough padding bytes ('=') to make it a multiple of 4
    let bytes = ceil(buf.len() as f64 * 4.0 / 3.0);
    let padding = 4 - bytes % 4;

    if s.len() != bytes + padding {
        return false;
    }

    if s.trim_end_matches('=').len() != bytes {
        return false;
    }

    base64::decode_config_slice(s, base64::STANDARD, &mut buf).is_ok()
}

// poor-man's ceil, because f64::ceil() isn't available on no_std
fn ceil(x: f64) -> usize {
    assert!(x >= 0.0);
    let u = x as usize;
    if x == u as f64 {
        u
    } else {
        u + 1
    }
}
