use crate::ascii85::{decode_ascii85_str, DecodeError};
use crate::layer1::flip_and_rotate;
use crate::layer2::parse_parity_buffer;
use crate::layer3::decode_xor_encoded_payload;
use crate::layer4::parse_ip_payload;
use crate::layer5::decode_aes_payload;
use crate::layer6::run_payload_program;
use nom::lib::std::fmt::Formatter;
use std::error::Error;
use std::fmt::Display;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::{fmt, io};

mod ascii85;
mod layer1;
mod layer2;
mod layer3;
mod layer4;
mod layer5;
mod layer6;

#[derive(Debug)]
struct ProblemError {
    inner: Box<dyn Error>,
}

impl Display for ProblemError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl From<DecodeError> for ProblemError {
    fn from(e: DecodeError) -> Self {
        Self { inner: e.into() }
    }
}

impl From<Box<dyn Error>> for ProblemError {
    fn from(e: Box<dyn Error>) -> Self {
        Self { inner: e }
    }
}

impl Error for ProblemError {}

fn load_layer(p: impl AsRef<Path>) -> io::Result<String> {
    let mut f = File::open(p)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    Ok(s)
}

fn extract_payload(s: &str) -> Option<&str> {
    const DELIM: &str = "==[ Payload ]===============================================";
    s.find(DELIM).map(|i| &s[i + DELIM.len()..])
}

fn save_layer(p: impl AsRef<Path>, b: &[u8]) -> io::Result<()> {
    let mut f = File::create(p)?;
    f.write_all(b)
}

fn solve_layer<F>(n: u8, f: F) -> Result<(), Box<dyn Error>>
where
    F: Fn(&str) -> Result<Vec<u8>, ProblemError>,
{
    let s = load_layer(format!("layers/0{}.txt", n))?;
    let p = extract_payload(&s).ok_or("Unable to extract payload")?;
    let b = f(&p).map_err(|e| e.to_string())?;
    save_layer(format!("layers/0{}.txt", n + 1), &b)?;
    Ok(())
}

fn solve_layer00(s: &str) -> Result<Vec<u8>, ProblemError> {
    decode_ascii85_str(s).map_err(ProblemError::from)
}

fn solve_layer01(s: &str) -> Result<Vec<u8>, ProblemError> {
    let buffer = decode_ascii85_str(s)?;
    Ok(buffer.into_iter().map(flip_and_rotate).collect())
}

fn solve_layer02(s: &str) -> Result<Vec<u8>, ProblemError> {
    let buffer = decode_ascii85_str(s)?;
    Ok(parse_parity_buffer(&buffer))
}

fn solve_layer03(s: &str) -> Result<Vec<u8>, ProblemError> {
    let buffer = decode_ascii85_str(s)?;
    decode_xor_encoded_payload(&buffer).ok_or_else(|| ProblemError {
        inner: "unable to decode xor-encoded payload".into(),
    })
}

fn solve_layer04(s: &str) -> Result<Vec<u8>, ProblemError> {
    let buffer = decode_ascii85_str(s)?;
    parse_ip_payload(&buffer).map_err(ProblemError::from)
}

fn solve_layer05(s: &str) -> Result<Vec<u8>, ProblemError> {
    let buffer = decode_ascii85_str(s)?;
    decode_aes_payload(&buffer).map_err(ProblemError::from)
}

fn solve_layer06(s: &str) -> Result<Vec<u8>, ProblemError> {
    let buffer = decode_ascii85_str(s)?;
    Ok(run_payload_program(&buffer))
}

fn main() -> Result<(), Box<dyn Error>> {
    solve_layer(0, solve_layer00)?;
    solve_layer(1, solve_layer01)?;
    solve_layer(2, solve_layer02)?;
    solve_layer(3, solve_layer03)?;
    solve_layer(4, solve_layer04)?;
    solve_layer(5, solve_layer05)?;
    solve_layer(6, solve_layer06)?;

    Ok(())
}
