use packet::ip::Protocol;
use packet::{ip, udp};
use std::error::Error;
use std::net::Ipv4Addr;

pub fn parse_ip_payload(b: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut stream = b;
    let mut result = vec![];

    while let Ok(ipv4_packet) = ip::v4::Packet::new(stream) {
        let data_len = ipv4_packet.length() as usize - (20 + 8);

        // verify checksum
        let ck = ipv4_packet.checksum();
        let actual_ck = ip::v4::checksum(&stream[..20]);
        let mut ignore = ck != actual_ck;

        // source ip
        let source = ipv4_packet.source();
        let authorized = Ipv4Addr::new(10, 1, 1, 10);
        if source != authorized {
            ignore = true;
        }

        // destination
        let dest = ipv4_packet.destination();
        let authorized = Ipv4Addr::new(10, 1, 1, 200);
        if dest != authorized {
            ignore = true;
        }

        stream = &stream[20..];

        let udp_packet = udp::Packet::new(stream)?;

        dbg!(data_len);
        dbg!(udp_packet.length() - 8);

        // verify checksum
        let ck = dbg!(udp_packet.checksum());
        let actual_ck = dbg!(checksum(
            &ip::Packet::V4(ipv4_packet),
            &stream[..8 + data_len]
        ));
        if ck != actual_ck {
            ignore = true;
        }

        // port verification
        let port = udp_packet.destination();
        if port != 42069 {
            ignore = true;
        }

        stream = &stream[8..];

        let data = &stream[..data_len];
        if !ignore {
            result.extend_from_slice(data);
        }

        stream = &stream[data_len..];
    }

    Ok(result)
}

/// Calculate the checksum for a UDP packet.
///
/// # Note
///
/// Since the checksum for UDP packets includes a pseudo-header based on the
/// enclosing IP packet, one has to be given.
fn checksum<B: AsRef<[u8]>>(ip: &ip::Packet<B>, buffer: &[u8]) -> u16 {
    use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
    use std::io::Cursor;

    let mut prefix = [0u8; 40];
    match *ip {
        ip::Packet::V4(ref packet) => {
            prefix[0..4].copy_from_slice(&packet.source().octets());
            prefix[4..8].copy_from_slice(&packet.destination().octets());
            prefix[9] = Protocol::Udp.into();
            Cursor::new(&mut prefix[10..])
                .write_u16::<BigEndian>(buffer.len() as u16)
                .unwrap();
        }

        ip::Packet::V6(ref _packet) => {
            unimplemented!();
        }
    };

    let mut result = 0u32;
    let mut buffer = Cursor::new(buffer);
    let mut prefix = match *ip {
        ip::Packet::V4(_) => Cursor::new(&prefix[0..12]),
        ip::Packet::V6(_) => Cursor::new(&prefix[0..40]),
    };

    while let Ok(value) = prefix.read_u16::<BigEndian>() {
        result += u32::from(value);

        if result > 0xffff {
            result -= 0xffff;
        }
    }

    while let Ok(value) = buffer.read_u16::<BigEndian>() {
        // Skip checksum field.
        if buffer.position() == 8 {
            continue;
        }

        result += u32::from(value);

        if result > 0xffff {
            result -= 0xffff;
        }
    }

    if let Ok(value) = buffer.read_u8() {
        // if we have a trailing byte, make a padded 16-bit value
        let value = (value as u16) << 8;

        result += u32::from(value);

        if result > 0xffff {
            result -= 0xffff;
        }
    }

    !result as u16
}
