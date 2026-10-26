//! ServerName (SNI) extension (RFC 6066).
//!
//! ```text
//! enum { host_name(0), (255) } NameType;
//! opaque HostName<1..2^16-1>;
//! struct { NameType name_type; select (name_type) {
//!     case host_name: HostName;
//! } name; } ServerName;
//! ServerName server_name_list<1..2^16-1>;
//! ```

use crate::buffer::Buf;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::{be_u8, be_u16};
use std::ops::Range;

const NAME_TYPE_HOST_NAME: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerNameList {
    pub host_name: Option<Range<usize>>,
}

impl ServerNameList {
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], Self> {
        let original_input = input;
        let (input, list_len) = be_u16(input)?;
        let (input, list_data) = take(list_len)(input)?;
        if !input.is_empty() {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let mut host_name: Option<Range<usize>> = None;
        let mut rest = list_data;
        while !rest.is_empty() {
            let (after, name_type) = be_u8(rest)?;
            let (after, name_len) = be_u16(after)?;
            if name_len == 0 {
                return Err(nom::Err::Failure(Error::new(after, ErrorKind::LengthValue)));
            }
            let (after, name_slice) = take(name_len)(after)?;
            if name_type == NAME_TYPE_HOST_NAME && host_name.is_none() {
                let rel = name_slice.as_ptr() as usize - original_input.as_ptr() as usize;
                let start = base_offset + rel;
                host_name = Some(start..start + name_slice.len());
            }
            // RFC 6066: "There MUST NOT be more than one name of the same
            // name_type in the list." Duplicates silently ignored.
            rest = after;
        }
        Ok((input, Self { host_name }))
    }

    pub fn host_name<'a>(&self, buf: &'a [u8]) -> Option<&'a [u8]> {
        self.host_name.as_ref().map(|r| &buf[r.clone()])
    }

    #[allow(dead_code)]
    pub fn serialize(&self, source_buf: &[u8], output: &mut Buf) {
        match &self.host_name {
            Some(range) => {
                let name = &source_buf[range.clone()];
                output.extend_from_slice(&((3 + name.len()) as u16).to_be_bytes());
                output.push(NAME_TYPE_HOST_NAME);
                output.extend_from_slice(&(name.len() as u16).to_be_bytes());
                output.extend_from_slice(name);
            }
            None => output.extend_from_slice(&0u16.to_be_bytes()),
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
            0x00, 0x0C, // list length
            0x00, // name_type: host_name
            0x00, 0x09, b'l', b'o', b'c', b'a', b'l', b'.', b'c', b'o', b'm',
        ];
        let (rest, parsed) = ServerNameList::parse(message, 0).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.host_name(message), Some(&b"local.com"[..]));
        let mut out = Buf::new();
        parsed.serialize(message, &mut out);
        assert_eq!(&*out, message);
    }

    #[test]
    fn unknown_name_type_skipped() {
        let message: &[u8] = &[
            0x00, 0x09, 0x01, 0x00, 0x02, 0xAA, 0xBB, // name_type=1 (unknown), skipped
            0x00, 0x00, 0x01, b'x', // host_name = "x"
        ];
        let (_, parsed) = ServerNameList::parse(message, 0).unwrap();
        assert_eq!(parsed.host_name(message), Some(&b"x"[..]));
    }

    #[test]
    fn empty_list_parses_without_host_name() {
        // Empty ServerNameList is valid in EncryptedExtensions (RFC 6066 §3:
        // "A server that receives a client hello ... SHALL include an extension
        // of type server_name in the (extended) server hello. The extension_data
        // field of this extension SHALL be empty.")
        let (rest, parsed) = ServerNameList::parse(&[0, 0], 0).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.host_name(&[0, 0]), None);
    }
}
