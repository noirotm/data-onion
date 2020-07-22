use aes::Aes256;
use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes256Ctr;
use block_modes::block_padding::NoPadding;
use block_modes::{BlockMode, Ecb};
use byteorder::{BigEndian, ReadBytesExt};
use nom::lib::std::iter::repeat_with;
use std::error::Error;
use std::io::Cursor;

pub fn decode_aes_payload(b: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let kek = &b[0..32];
    let _wkiv = &b[32..40];
    let wrapped_key = &b[40..80];
    let iv = &b[80..96];
    let payload = &b[96..];

    // decrypt the key
    let decrypted_key = unwrap_key(kek, wrapped_key)?;

    // decrypt the payload
    let key = GenericArray::from_slice(&decrypted_key);
    let nonce = GenericArray::from_slice(iv);
    let mut cipher = Aes256Ctr::new(&key, &nonce);
    let mut data = Vec::from(payload);
    cipher
        .try_apply_keystream(&mut data)
        .map(|_| data)
        .map_err(|e| format!("{}", e).into())
}

fn unwrap_key(kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // 1 byte for IV + 5 * 8 bytes in the key
    // use AES codebook = ECB, don't unpad!
    type Aes256Ecb = Ecb<Aes256, NoPadding>;

    let mut c = Cursor::new(wrapped_key);
    let mut a = c.read_u64::<BigEndian>()?;
    let mut r = repeat_with(|| c.read_u64::<BigEndian>())
        .flatten()
        .take(4)
        .collect::<Vec<_>>();

    for j in (0..=5).rev() {
        for i in (1..=4).rev() {
            let t = (4 * j + i) as u64;
            let v = a ^ t;
            let mut v = Vec::from(v.to_be_bytes());
            v.extend_from_slice(&r[i - 1].to_be_bytes());

            let cipher = Aes256Ecb::new_var(kek, Default::default())?;
            let b = cipher.decrypt_vec(&v)?;

            let mut c = Cursor::new(&b);

            a = c.read_u64::<BigEndian>()?;
            r[i - 1] = c.read_u64::<BigEndian>()?;
        }
    }

    Ok(r.into_iter()
        .flat_map(|v| Vec::from(v.to_be_bytes()))
        .collect())
}
