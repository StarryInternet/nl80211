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
}
