//! ALPN extension (RFC 7301).
//!
//! ClientHello and EncryptedExtensions payload:
//! ```text
//! opaque ProtocolName<1..2^8-1>;
//! ProtocolName ProtocolNameList<2..2^16-1>;
//! ```

use crate::buffer::Buf;
use arrayvec::ArrayVec;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::{be_u8, be_u16};
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolNameList {
    /// Ranges into the source buffer (absolute offsets, like `Certificate`).
    pub names: ArrayVec<Range<usize>, 8>,
}

impl ProtocolNameList {
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], Self> {
        let original_input = input;
        let (input, list_len) = be_u16(input)?;
        if list_len == 0 {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let (input, names_data) = take(list_len)(input)?;
        if !input.is_empty() {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let mut names = ArrayVec::new();
        let mut rest = names_data;
        while !rest.is_empty() {
            let before = rest;
            let (after, name_len) = be_u8(rest)?;
            if name_len == 0 {
                return Err(nom::Err::Failure(Error::new(after, ErrorKind::LengthValue)));
            }
            let (after, name_slice) = take(name_len)(after)?;
            let rel = name_slice.as_ptr() as usize - original_input.as_ptr() as usize;
            let start = base_offset + rel;
            names
                .try_push(start..start + name_slice.len())
                .map_err(|_| nom::Err::Failure(Error::new(before, ErrorKind::LengthValue)))?;
            rest = after;
        }
        Ok((input, Self { names }))
    }

    pub fn get<'a>(&self, i: usize, buf: &'a [u8]) -> Option<&'a [u8]> {
        self.names.get(i).map(|r| &buf[r.clone()])
    }

    #[allow(dead_code)]
    pub fn serialize(&self, source_buf: &[u8], output: &mut Buf) {
        let total: usize = self.names.iter().map(|r| 1 + r.len()).sum();
        output.extend_from_slice(&(total as u16).to_be_bytes());
        for range in &self.names {
            let name = &source_buf[range.clone()];
            output.push(name.len() as u8);
            output.extend_from_slice(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;

    #[test]
    fn roundtrip() {
        let message: &[u8] = &[
            0x00, 0x0F, // list length (3 + 9 + 3)
            0x02, b'h', b'2', // "h2"
            0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1', 0x02, b'c', b'o',
        ];
        let (rest, parsed) = ProtocolNameList::parse(message, 0).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.get(0, message), Some(&b"h2"[..]));
        assert_eq!(parsed.get(1, message), Some(&b"http/1.1"[..]));
        assert_eq!(parsed.get(2, message), Some(&b"co"[..]));
        let mut out = Buf::new();
        parsed.serialize(message, &mut out);
        assert_eq!(&*out, message);
    }

    #[test]
    fn empty_list_rejected() {
        assert!(ProtocolNameList::parse(&[0, 0], 0).is_err());
    }

    #[test]
    fn empty_name_rejected() {
        assert!(ProtocolNameList::parse(&[0, 2, 0, b'x'], 0).is_err());
    }
}
