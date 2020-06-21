use nom::branch::alt;
use nom::bytes::complete::{tag, take_while_m_n};
use nom::character::complete::multispace0;
use nom::combinator::{all_consuming, map, map_res};
use nom::multi::{many0, many_m_n};
use nom::sequence::{delimited, preceded, terminated};
use nom::IResult;
use std::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum DecodeError {
    InvalidCharacter(char),
    ParseError(Box<dyn Error>),
    Misc(String),
}

impl Display for DecodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::InvalidCharacter(c) => write!(f, "invalid character: {}", c),
            DecodeError::ParseError(e) => write!(f, "{}", e),
            DecodeError::Misc(s) => write!(f, "{}", s),
        }
    }
}

impl Error for DecodeError {}

fn is_ascii85_value(c: char) -> bool {
    c >= '!' && c <= 'u'
}

fn ws(i: &str) -> IResult<&str, &str> {
    multispace0(i)
}

fn chr(i: &str) -> IResult<&str, u8> {
    map(preceded(ws, take_while_m_n(1, 1, is_ascii85_value)), |b| {
        b.bytes().next().unwrap()
    })(i)
}

fn z(i: &str) -> IResult<&str, Vec<u8>> {
    map(preceded(ws, tag("z")), |_| vec![0, 0, 0, 0])(i)
}

fn fives(i: &str) -> IResult<&str, Vec<u8>> {
    map_res(many_m_n(1, 5, chr), |v| decode_sequence(&v))(i)
}

fn sequence(i: &str) -> IResult<&str, Vec<u8>> {
    alt((z, fives))(i)
}

fn sequences(i: &str) -> IResult<&str, Vec<u8>> {
    map(many0(sequence), |seqs| seqs.into_iter().flatten().collect())(i)
}

fn payload(i: &str) -> IResult<&str, Vec<u8>> {
    let start_tag = preceded(ws, tag("<~"));
    let end_tag = preceded(ws, tag("~>"));

    delimited(start_tag, sequences, end_tag)(i)
}

fn parse_ascii85(i: &str) -> IResult<&str, Vec<u8>> {
    all_consuming(terminated(payload, ws))(i)
}

pub fn decode_ascii85_str(b: &str) -> Result<Vec<u8>, DecodeError> {
    parse_ascii85(b)
        .map_err(|e| DecodeError::ParseError(e.to_owned().into()))
        .map(|(_, v)| v)
}

fn decode_sequence(b: &[u8]) -> Result<Vec<u8>, DecodeError> {
    debug_assert!(!b.is_empty());
    let padding = 5 - b.len();

    let vals = (0..5)
        .map(|n| {
            let c = b.get(n).cloned().unwrap_or(b'u');
            c.checked_sub(33)
                .map(|n| n as u32)
                .ok_or(DecodeError::InvalidCharacter(c as char))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // compose 32-bit value
    let n: u32 = vals[0] * 52200625 + vals[1] * 614125 + vals[2] * 7225 + vals[3] * 85 + vals[4];

    // create 4 bytes out of this
    let bytes = n.to_be_bytes();

    // truncate output if necessary
    let bytes = &bytes[0..(4 - padding)];

    Ok(Vec::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_ascii85_str() {
        const ENCODED: &str = r#"
            <~9jqo^BlbD-BleB1DJ+*+F(f,q/0JhKF<GL>Cj@.4Gp$d7F!,L7@<6@)/0JDEF<G%<+EV:2F!,
            O<DJ+*.@<*K0@<6L(Df-\0Ec5e;DffZ(EZee.Bl.9pF"AGXBPCsi+DGm>@3BB/F*&OCAfu2/AKY
            i(DIb:@FD,*)+C]U=@3BN#EcYf8ATD3s@q?d$AftVqCh[NqF<G:8+EV:.+Cf>-FD5W8ARlolDIa
            l(DId<j@<?3r@:F%a+D58'ATD4$Bl@l3De:,-DJs`8ARoFb/0JMK@qB4^F!,R<AKZ&-DfTqBG%G
            >uD.RTpAKYo'+CT/5+Cei#DII?(E,9)oF*2M7/c~>
        "#;
        const DECODED: &str = "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.";

        let res = decode_ascii85_str(ENCODED).unwrap();
        let s = String::from_utf8(res).unwrap();

        assert_eq!(s, DECODED);
    }

    #[test]
    fn test_decode_sequence() {
        assert_eq!(
            decode_sequence(&[b'9', b'j', b'q', b'o', b'^']).unwrap(),
            vec![b'M', b'a', b'n', b' ']
        );
    }

    #[test]
    fn test_decode_sequence_padded() {
        assert_eq!(decode_sequence(&[b'/', b'c']).unwrap(), vec![b'.']);
    }
}
