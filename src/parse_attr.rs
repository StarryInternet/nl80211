use macaddr::MacAddr;
use neli::err::NlError;
use std::convert::TryInto;

/// Parse a vec of bytes as a String
pub fn parse_string(input: &[u8]) -> String {
    String::from_utf8_lossy(input)
        .trim_matches(char::from(0))
        .to_string()
}

/// Parse a vec of bytes as a mac address
pub fn parse_macaddr(input: &[u8]) -> Result<MacAddr, NlError> {
    if input.len() == 6 {
        let array: [u8; 6] = input
            .try_into()
            .expect("Slice with incorrect number of bytes");
        Ok(array.into())
    } else if input.len() == 8 {
        let array: [u8; 8] = input
            .try_into()
            .expect("Slice with incorrect number of bytes");
        Ok(array.into())
    } else {
        Err(NlError::Msg(format!(
            "Encountered a {}-byte MAC address",
            input.len()
        )))
    }
}

/// Parse a vec of bytes as i8
pub fn parse_i8(input: &[u8]) -> i8 {
    let to_array =
        |slice: &[u8]| -> [u8; 1] { slice.try_into().expect("slice with incorrect length") };

    i8::from_le_bytes(to_array(input))
}

/// Parse a vec of bytes as u16
pub fn parse_u16(input: &[u8]) -> u16 {
    let to_array =
        |slice: &[u8]| -> [u8; 2] { slice.try_into().expect("slice with incorrect length") };

    u16::from_le_bytes(to_array(input))
}

/// Parse a vec of bytes as u32
pub fn parse_u32(input: &[u8]) -> u32 {
    let to_array =
        |slice: &[u8]| -> [u8; 4] { slice.try_into().expect("slice with incorrect length") };

    u32::from_le_bytes(to_array(input))
}

/// Parse a vec of bytes as i32
pub fn parse_i32(input: &[u8]) -> i32 {
    let to_array =
        |slice: &[u8]| -> [u8; 4] { slice.try_into().expect("slice with incorrect length") };

    i32::from_le_bytes(to_array(input))
}

/// Parse a vec of bytes as u64
pub fn parse_u64(input: &[u8]) -> u64 {
    let to_array =
        |slice: &[u8]| -> [u8; 8] { slice.try_into().expect("slice with incorrect length") };

    u64::from_le_bytes(to_array(input))
}

#[cfg(test)]
mod test_type_conversion {
    use super::*;

    #[test]
    fn test_parse_string() {
        let input_string = "test".to_string();
        let bytes_string = input_string.as_bytes().to_vec();
        assert_eq!(parse_string(&bytes_string), input_string);
    }

    #[test]
    fn test_parse_string_trim_zeros() {
        let input = [0x48, 0x45, 0x4C, 0x4C, 0x4F, 0x00];
        assert_eq!(parse_string(&input), "HELLO");
    }

    #[test]
    fn test_parse_i8() {
        assert_eq!(parse_i8(&vec![8]), 8 as i8);
    }

    #[test]
    #[should_panic]
    fn test_parse_i8_should_panic() {
        assert_eq!(parse_i8(&vec![8, 0]), 8 as i8);
    }

    #[test]
    fn test_parse_u16() {
        assert_eq!(parse_u16(&vec![1, 0]), 1 as u16);
    }

    #[test]
    #[should_panic]
    fn test_parse_u16_should_panic() {
        assert_eq!(parse_u16(&vec![1, 0, 0]), 1 as u16);
        assert_eq!(parse_u16(&vec![1]), 1 as u16);
    }

    #[test]
    fn test_parse_u32() {
        assert_eq!(parse_u32(&vec![1, 0, 0, 0]), 1 as u32);
    }

    #[test]
    #[should_panic]
    fn test_parse_u32_should_panic() {
        assert_eq!(parse_u32(&vec![1, 0, 0, 0, 0]), 1 as u32);
        assert_eq!(parse_u32(&vec![1, 0, 0]), 1 as u32);
    }

    #[test]
    fn test_parse_i32() {
        assert_eq!(parse_i32(&vec![1, 0, 0, 0]), 1 as i32);
    }

    #[test]
    #[should_panic]
    fn test_parse_i32_should_panic() {
        assert_eq!(parse_i32(&vec![1, 0, 0, 0, 0]), 1 as i32);
        assert_eq!(parse_i32(&vec![1, 0, 0]), 1 as i32);
    }

    #[test]
    fn test_parse_u64() {
        assert_eq!(parse_u64(&vec![1, 0, 0, 0, 0, 0, 0, 0]), 1 as u64);
    }

    #[test]
    #[should_panic]
    fn test_parse_u64_should_panic() {
        assert_eq!(parse_u64(&vec![1, 0, 0, 0, 0, 0, 0, 0, 0]), 1 as u64);
        assert_eq!(parse_u64(&vec![1, 0, 0]), 1 as u64);
    }
}
