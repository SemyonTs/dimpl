//! Connection ID extension (RFC 9146 / RFC 9147).
//!
//! ```text
//! struct { opaque cid<0..2^8-1>; } ConnectionId;
//! ```

use crate::buffer::Buf;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::be_u8;
use std::ops::Range;

/// Maximum CID length we can carry in `Aad` (32 bytes - 5 header bytes).
pub const MAX_CID_LEN: usize = 27;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionId {
    pub cid: Range<usize>,
}

impl ConnectionId {
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], Self> {
        let original_input = input;
        let (input, len) = be_u8(input)?;
        if len as usize > MAX_CID_LEN {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let (input, cid_slice) = take(len)(input)?;
        if !input.is_empty() {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let rel = cid_slice.as_ptr() as usize - original_input.as_ptr() as usize;
        let start = base_offset + rel;
        Ok((
            input,
            Self {
                cid: start..start + cid_slice.len(),
            },
        ))
    }

    pub fn cid<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.cid.clone()]
    }

    #[allow(dead_code)]
    pub fn serialize(&self, source_buf: &[u8], output: &mut Buf) {
        let cid = &source_buf[self.cid.clone()];
        output.push(cid.len() as u8);
        output.extend_from_slice(cid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;

    #[test]
    fn roundtrip() {
        let message: &[u8] = &[0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let (rest, parsed) = ConnectionId::parse(message, 0).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.cid(message), &[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut out = Buf::new();
        parsed.serialize(message, &mut out);
        assert_eq!(&*out, message);
    }

    #[test]
    fn empty_cid_ok() {
        let message: &[u8] = &[0x00];
        let (rest, parsed) = ConnectionId::parse(message, 0).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.cid(message), &[] as &[u8]);
    }

    #[test]
    fn oversized_cid_rejected() {
        let mut message = vec![28u8];
        message.extend_from_slice(&[0u8; 28]);
        assert!(ConnectionId::parse(&message, 0).is_err());
    }

    #[test]
    fn trailing_bytes_rejected() {
        assert!(ConnectionId::parse(&[0x01, 0xAA, 0xFF], 0).is_err());
    }
}
