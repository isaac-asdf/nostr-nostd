use heapless::String;

const DEC_STRING_SIZE: usize = 10;

/// Panics if number is larger than 7 digits, ie > 9,999,999
pub fn to_decimal_str(num: u32) -> String<DEC_STRING_SIZE> {
    if num == 0 {
        return String::from("0");
    }
    let mut serialized: String<DEC_STRING_SIZE> = String::new();
    let mut n = num;
    while n > 0 {
        let last_dec = n % 10;
        serialized
            .push(char::from_digit(last_dec.into(), 10).unwrap())
            .unwrap();
        n /= 10;
    }

    let mut output_str: String<DEC_STRING_SIZE> = String::new();
    // there's probably a better way to do this...
    while let Some(digit) = serialized.pop() {
        output_str.push(digit).unwrap();
    }

    output_str
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dec_str() {
        let num = 1234;
        let to_str = to_decimal_str(num);
        assert_eq!(to_str.as_str(), "1234");
    }
}
