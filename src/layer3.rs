/// XOR encryption is very weak against repeating sequences.
/// At some point, there will be the sequence:
///
/// `==[ Payload ]===============================================`
///
/// Ignoring `==[ Payload ]` there will be 47 identical characters.
/// This means that the key is entirely contained somewhere in the sequence.
/// To find this sequence, just find a sequence of 32 characters followed
/// by exactly the 15 first ones.
/// Once we have located this sequence, as we know the 15 first bytes already,
/// we just have to find these bytes and sync the key.
/// Then we can decode the whole thing.
/// Alternatively, just sync with the absolute position in the payload.
pub fn decode_xor_encoded_payload(b: &[u8]) -> Option<Vec<u8>> {
    // find the paylaod marker sequence
    let i = find_repeated_sequence(b)?;
    let sub = &b[i..i + 32];

    // sync our stream to the next key start
    let sync = i % 32;
    let split = if sync != 0 { Some(32 - sync) } else { None };

    // create 32 bytes sequence where key start is sync with idx 0
    let seq = if let Some(idx) = split {
        let (a, b) = sub.split_at(idx);
        let mut s = Vec::with_capacity(32);
        s.extend_from_slice(b);
        s.extend_from_slice(a);
        s
    } else {
        Vec::from(sub)
    };

    // decode the key
    let key = get_key_from_equal_bytes(&seq);

    // decode the whole sequence
    Some(xor(&key, b))
}

// decode sequence of "=" bytes
fn get_key_from_equal_bytes(b: &[u8]) -> Vec<u8> {
    let s = String::from("================================");
    let c = s.as_bytes();
    xor(c, &b[..32])
}

/// XOR a buffer cyclically
fn xor(key: &[u8], b: &[u8]) -> Vec<u8> {
    key.iter()
        .cycle()
        .zip(b.iter())
        .map(|(&k, &v)| k ^ v)
        .collect()
}

fn find_repeated_sequence(b: &[u8]) -> Option<usize> {
    let mut i = 0;
    let start = b[0];
    loop {
        // read 32 bytes
        let seq = b.get(i..i + 32);
        // read the 15 next ones
        let seq2 = b.get(i + 32..i + 32 + 15);

        if let (Some(seq), Some(seq2)) = (seq, seq2) {
            let subseq = &seq[..15];
            if subseq == seq2 && subseq.contains(&start) {
                return Some(i);
            }
        } else {
            return None;
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let k = &[0b01010101];
        let v = &[0b00110011, 0b00110011];
        let expected = &[0b01100110, 0b01100110];

        assert_eq!(xor(k, v), expected);
    }
}
