//! DTLS 1.3 record layer types.
//!
//! Supports both DTLSPlaintext (epoch 0) and DTLSCiphertext (unified header)
//! record formats per RFC 9147 Section 4.

use std::fmt;
use std::ops::Range;

use crate::buffer::Buf;
use crate::types::{ContentType, ProtocolVersion, Sequence};
use crate::util::be_u48;
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u16};
use nom::{Err, IResult};

/// DTLS 1.3 record structure.
#[derive(PartialEq, Eq, Default)]
pub struct Dtls13Record {
    pub content_type: ContentType,
    pub sequence: Sequence,
    pub length: u16,
    pub fragment_range: Range<usize>,
}

impl Dtls13Record {
    pub const PLAINTEXT_HEADER_LEN: usize = 13;
    pub const PLAINTEXT_LENGTH_OFFSET: Range<usize> = 11..13;

    pub fn is_ciphertext_header(byte: u8) -> bool {
        byte & 0b1110_0000 == 0b0010_0000
    }

    /// Parse a DTLS 1.3 record. `cid_len` is the local Connection ID length
    /// (0 when CID was not negotiated). Only relevant for ciphertext records.
    pub fn parse(input: &[u8], base_offset: usize, cid_len: usize) -> IResult<&[u8], Dtls13Record> {
        if input.is_empty() {
            return Err(Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Eof,
            )));
        }

        if Self::is_ciphertext_header(input[0]) {
            Self::parse_ciphertext(input, base_offset, cid_len)
        } else {
            Self::parse_plaintext(input, base_offset)
        }
    }

    fn parse_plaintext(input: &[u8], base_offset: usize) -> IResult<&[u8], Dtls13Record> {
        let original_input = input;
        let (input, content_type) = ContentType::parse(input)?;
        let (input, version) = ProtocolVersion::parse(input)?;

        match content_type {
            ContentType::Alert | ContentType::Handshake | ContentType::Ack => {}
            _ => {
                return Err(Err::Failure(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Tag,
                )));
            }
        }

        match version {
            ProtocolVersion::DTLS1_0 | ProtocolVersion::DTLS1_2 => {}
            _ => {
                return Err(Err::Failure(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Tag,
                )));
            }
        }

        let (input, epoch) = be_u16(input)?;
        if epoch != 0 {
            return Err(Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }

        let (input, sequence_number) = be_u48(input)?;
        let (input, length) = be_u16(input)?;
        let (rest, fragment_slice) = take(length as usize)(input)?;

        let relative_offset = fragment_slice.as_ptr() as usize - original_input.as_ptr() as usize;
        let start = base_offset + relative_offset;
        let end = start + fragment_slice.len();

        let sequence = Sequence {
            epoch,
            sequence_number,
        };

        Ok((
            rest,
            Dtls13Record {
                content_type,
                sequence,
                length,
                fragment_range: start..end,
            },
        ))
    }

    /// Parse a DTLSCiphertext record (unified header, epoch >= 2).
    ///
    /// The unified header flags byte layout:
    /// ```text
    /// 0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+
    /// |0|0|1|C|S|L|E E|
    /// +-+-+-+-+-+-+-+-+
    /// ```
    /// C = Connection ID present, S = seq length, L = length present, EE = epoch low bits.
    fn parse_ciphertext(
        input: &[u8],
        base_offset: usize,
        cid_len: usize,
    ) -> IResult<&[u8], Dtls13Record> {
        let original_input = input;
        let (input, flags) = be_u8(input)?;

        let c_flag = flags & 0b0001_0000 != 0;
        if c_flag != (cid_len > 0) {
            return Err(Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }

        let input = if cid_len > 0 {
            let (i, _cid) = take(cid_len)(input)?;
            i
        } else {
            input
        };

        let s_flag = flags & 0b0000_1000 != 0;
        let l_flag = flags & 0b0000_0100 != 0;
        let epoch_bits = (flags & 0b0000_0011) as u16;

        let (input, sequence_number) = if s_flag {
            let (input, seq) = be_u16(input)?;
            (input, seq as u64)
        } else {
            let (input, seq) = be_u8(input)?;
            (input, seq as u64)
        };

        let (rest, length, fragment_slice) = if l_flag {
            let (input, length) = be_u16(input)?;
            let (rest, fragment) = take(length as usize)(input)?;
            (rest, length, fragment)
        } else {
            let length = input.len() as u16;
            let (rest, fragment) = take(length as usize)(input)?;
            (rest, length, fragment)
        };

        let relative_offset = fragment_slice.as_ptr() as usize - original_input.as_ptr() as usize;
        let start = base_offset + relative_offset;
        let end = start + fragment_slice.len();

        let sequence = Sequence {
            epoch: epoch_bits,
            sequence_number,
        };

        Ok((
            rest,
            Dtls13Record {
                content_type: ContentType::ApplicationData,
                sequence,
                length,
                fragment_range: start..end,
            },
        ))
    }

    pub fn fragment<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.fragment_range.clone()]
    }

    pub fn serialize(&self, buf: &[u8], output: &mut Buf) {
        if self.sequence.epoch == 0 {
            self.serialize_plaintext(buf, output);
        } else {
            self.serialize_ciphertext(buf, output);
        }
    }

    fn serialize_plaintext(&self, buf: &[u8], output: &mut Buf) {
        output.push(self.content_type.as_u8());
        ProtocolVersion::DTLS1_2.serialize(output);
        output.extend_from_slice(&self.sequence.epoch.to_be_bytes());
        output.extend_from_slice(&self.sequence.sequence_number.to_be_bytes()[2..]);
        output.extend_from_slice(&self.length.to_be_bytes());
        output.extend_from_slice(self.fragment(buf));
    }

    fn serialize_ciphertext(&self, buf: &[u8], output: &mut Buf) {
        let flags: u8 =
            0b0010_0000 | 0b0000_1000 | 0b0000_0100 | (self.sequence.epoch as u8 & 0x03);
        output.push(flags);
        output.extend_from_slice(&(self.sequence.sequence_number as u16).to_be_bytes());
        output.extend_from_slice(&self.length.to_be_bytes());
        output.extend_from_slice(self.fragment(buf));
    }
}

impl fmt::Debug for Dtls13Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dtls13Record")
            .field("content_type", &self.content_type)
            .field("sequence", &self.sequence)
            .field("length", &self.length)
            .field("fragment_range", &self.fragment_range)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_content_type_whitelist() {
        fn build(content_type: u8) -> Vec<u8> {
            vec![
                content_type,
                0xFE,
                0xFD,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
                0x00,
                0x02,
                0xAA,
                0xBB,
            ]
        }
        fn build_with_epoch(content_type: u8, epoch: u16) -> Vec<u8> {
            vec![
                content_type,
                0xFE,
                0xFD,
                (epoch >> 8) as u8,
                (epoch & 0xFF) as u8,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
                0x00,
                0x02,
                0xAA,
                0xBB,
            ]
        }
        assert!(Dtls13Record::parse(&build(0x15), 0, 0).is_ok());
        assert!(Dtls13Record::parse(&build(0x16), 0, 0).is_ok());
        assert!(Dtls13Record::parse(&build(0x1A), 0, 0).is_ok());
        assert!(Dtls13Record::parse(&build(0x17), 0, 0).is_err());
        assert!(Dtls13Record::parse(&build(0x14), 0, 0).is_err());
        assert!(Dtls13Record::parse(&build(0xFF), 0, 0).is_err());
        assert!(Dtls13Record::parse(&build_with_epoch(0x16, 1), 0, 0).is_err());
        assert!(Dtls13Record::parse(&build_with_epoch(0x16, 2), 0, 0).is_err());
    }

    #[test]
    fn ciphertext_with_cid_parses() {
        let cid: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let flags = 0b0010_0000 | 0b0001_0000 | 0b0000_1000 | 0b0000_0100 | 0x02;
        let mut packet = Vec::new();
        packet.push(flags);
        packet.extend_from_slice(cid);
        packet.extend_from_slice(&42u16.to_be_bytes());
        packet.extend_from_slice(&8u16.to_be_bytes());
        packet.extend_from_slice(&[0xAA; 8]);

        let (rest, parsed) = Dtls13Record::parse(&packet, 0, cid.len()).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.sequence.epoch, 2);
        assert_eq!(parsed.sequence.sequence_number, 42);
        assert_eq!(parsed.length, 8);
    }

    #[test]
    fn ciphertext_c_flag_without_cid_rejected() {
        let mut packet = Vec::new();
        packet.push(0b0010_0000 | 0b0001_0000 | 0b0000_1000 | 0b0000_0100 | 0x02);
        packet.extend_from_slice(&[0u8; 4]);
        packet.extend_from_slice(&42u16.to_be_bytes());
        packet.extend_from_slice(&8u16.to_be_bytes());
        packet.extend_from_slice(&[0xAA; 8]);
        assert!(Dtls13Record::parse(&packet, 0, 0).is_err());
    }

    #[test]
    fn ciphertext_no_c_flag_with_cid_len_rejected() {
        let mut packet = Vec::new();
        packet.push(0b0010_0000 | 0b0000_1000 | 0b0000_0100 | 0x02);
        packet.extend_from_slice(&42u16.to_be_bytes());
        packet.extend_from_slice(&8u16.to_be_bytes());
        packet.extend_from_slice(&[0xAA; 8]);
        assert!(Dtls13Record::parse(&packet, 0, 4).is_err());
    }
}
