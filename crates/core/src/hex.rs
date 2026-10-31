//! Lowercase hexadecimal encoding, shared by the crate's hashes and nonces.

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Encodes `bytes` as lowercase hex.
pub(crate) fn encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|b| {
            [
                char::from(DIGITS[usize::from(b >> 4)]),
                char::from(DIGITS[usize::from(b & 0x0f)]),
            ]
        })
        .collect()
}

/// Decodes exactly `2 * N` lowercase hex digits; anything else is `None`.
pub(crate) fn decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != N * 2 {
        return None;
    }
    let nibble = |d: u8| match d {
        b'0'..=b'9' => Some(d - b'0'),
        b'a'..=b'f' => Some(d - b'a' + 10),
        _ => None,
    };
    let mut out = [0_u8; N];
    for (byte, [high, low]) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        *byte = (nibble(*high)? << 4) | nibble(*low)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_inverts_encode_and_is_strict() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(encode(&bytes), "000fa5ff");
        assert_eq!(decode::<4>("000fa5ff"), Some(bytes));
        assert_eq!(decode::<4>("000FA5FF"), None);
        assert_eq!(decode::<4>("000fa5"), None);
        assert_eq!(decode::<4>("000fa5fg"), None);
        assert_eq!(decode::<4>("000fa5ff00"), None);
    }
}
