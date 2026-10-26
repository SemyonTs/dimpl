//! Length-prefixed wrappers around subslices of a root buffer.
//!
//! Both wrappers store an absolute `Range<usize>` into the buffer that
//! was being parsed, so they are zero-copy: the actual bytes stay in place
//! and are recovered with [`Deref`](std::ops::Deref) or the type-specific
//! accessors.
//!
//! Per RFC 8446 §4.4.2:
//!
//! - `Asn1Cert` wraps `opaque cert_data<1..2^24-1>` — length-prefixed with
//!   a `u24`, minimum **1** byte. A zero-length `cert_data` is rejected.
//! - `DistinguishedName` wraps `opaque DistinguishedName<1..2^16-1>` —
//!   length-prefixed with a `u16`, minimum **1** byte.

use nom::Err;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::{be_u16, be_u24};
use std::ops::Range;

macro_rules! wrapped_slice {
    ($name:ident, $length_parser:path, $min:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name(pub Range<usize>);

        impl $name {
            /// Parse a length-prefixed sub-slice, recording its absolute range
            /// in the root buffer.
            ///
            /// Rejects slices shorter than the minimum length mandated by the
            /// corresponding RFC.
            pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], Self> {
                let original_input = input;
                let (input, len) = $length_parser(input)?;
                #[allow(unused_comparisons)]
                if len < $min {
                    return Err(Err::Failure(Error::new(input, ErrorKind::LengthValue)));
                }
                let (input, data_slice) = take(len)(input)?;

                // Calculate absolute range in root buffer
                let relative_offset =
                    data_slice.as_ptr() as usize - original_input.as_ptr() as usize;
                let start = base_offset + relative_offset;
                let end = start + data_slice.len();

                Ok((input, $name(start..end)))
            }
        }
    };
}

// RFC 8446 §4.4.2: `opaque cert_data<1..2^24-1>` — a zero-length certificate
// is malformed and must be rejected during Certificate parsing, not later when
// its ASN.1 body is decoded.
wrapped_slice!(Asn1Cert, be_u24, 1);

// RFC 5280 §4.1.2.4 / RFC 8446 §4.2.4: distinguished names are non-empty.
wrapped_slice!(DistinguishedName, be_u16, 1);

impl Asn1Cert {
    /// Borrow the certificate's DER bytes from the root buffer.
    pub fn as_slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.0.clone()]
    }
}
