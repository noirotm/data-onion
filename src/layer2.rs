use bitvec::prelude::*;

fn correct_byte(b: u8) -> Option<u8> {
    let parity_bit = b & 1;
    let val = b >> 1;
    let parity = val.count_ones() % 2;
    if parity_bit == parity as u8 {
        Some(val)
    } else {
        None
    }
}

pub fn parse_parity_buffer(b: &[u8]) -> Vec<u8> {
    let mut bb = bitvec![u8, Msb0;];
    for &byte in b {
        if let Some(mut ab) = correct_byte(byte) {
            ab = ab.reverse_bits();
            for _ in 0..7 {
                ab >>= 1;
                bb.push(ab & 1 == 1);
            }
        }
    }

    bb.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correct_byte() {
        assert_eq!(correct_byte(0b11), Some(0b1));
        assert_eq!(correct_byte(0b10110010), Some(0b1011001));
        assert_eq!(correct_byte(0b01), None);
    }

    #[test]
    fn test_parse_parity_buffer() {
        let b = &[
            0b10000001u8,
            0b11000000u8,
            0b11100001u8,
            0b11110000u8,
            0b10000001u8,
            0b11000000u8,
            0b11100001u8,
            0b11110000u8,
        ];
        let out = &[
            0b10000001u8,
            0b10000011u8,
            0b10000111u8,
            0b10001000u8,
            0b00011000u8,
            0b00111000u8,
            0b01111000u8,
        ];
        assert_eq!(parse_parity_buffer(b), out);
    }
}
