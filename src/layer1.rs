pub fn flip_and_rotate(b: u8) -> u8 {
    let mask = 0b01010101u8;
    let flipped = b ^ mask;
    let lsb = flipped & 0b00000001;
    (flipped >> 1) | (lsb << 7)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flip_and_rotate() {
        assert_eq!(flip_and_rotate(180), 240);
    }
}
