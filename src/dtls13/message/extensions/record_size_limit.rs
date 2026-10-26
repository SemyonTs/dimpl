//! RecordSizeLimit extension (RFC 8449).
//!
//! ```text
//! uint16 RecordSizeLimit;
//! ```

use crate::buffer::Buf;
use nom::IResult;
use nom::error::{Error, ErrorKind};
use nom::number::complete::be_u16;

pub const MIN_RECORD_SIZE_LIMIT: u16 = 64;
pub const MAX_RECORD_SIZE_LIMIT: u16 = 16385;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordSizeLimit {
    pub limit: u16,
}

impl RecordSizeLimit {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, limit) = be_u16(input)?;
        if !input.is_empty() {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        if limit < MIN_RECORD_SIZE_LIMIT || limit > MAX_RECORD_SIZE_LIMIT {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::Verify)));
        }
        Ok((input, Self { limit }))
    }

    pub fn serialize(&self, output: &mut Buf) {
        output.extend_from_slice(&self.limit.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;

    #[test]
    fn roundtrip() {
        let message: &[u8] = &[0x04, 0x00]; // 1024
        let (rest, parsed) = RecordSizeLimit::parse(message).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.limit, 1024);
        let mut out = Buf::new();
        parsed.serialize(&mut out);
        assert_eq!(&*out, message);
    }

    #[test]
    fn below_min_rejected() {
        assert!(RecordSizeLimit::parse(&[0x00, 63]).is_err());
    }

    #[test]
    fn above_max_rejected() {
        assert!(RecordSizeLimit::parse(&[0x40, 0x02]).is_err());
    }
}
