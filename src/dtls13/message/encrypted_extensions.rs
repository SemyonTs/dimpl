use super::{
    Extension, ExtensionType, ProtocolNameList, RecordSizeLimit, ServerNameList, SrtpProfileId,
    UseSrtpExtension,
};
use crate::buffer::Buf;
use arrayvec::ArrayVec;
use nom::Err;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::be_u16;

/// Maximum number of extensions an EncryptedExtensions message can carry.
///
/// Budget: UseSrtp + ALPN + SNI-ack + RecordSizeLimit + spare.
const MAX_EE_EXTENSIONS: usize = 6;

/// EncryptedExtensions message (RFC 8446 Section 4.3.1).
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedExtensions {
    pub extensions: ArrayVec<Extension, MAX_EE_EXTENSIONS>,
    // Receive-side values; outbound serialization uses the raw extensions above.
    srtp_profiles: Option<ArrayVec<SrtpProfileId, 3>>,
    alpn: Option<ProtocolNameList>,
    server_name: Option<ServerNameList>,
    record_size_limit: Option<RecordSizeLimit>,
}

impl EncryptedExtensions {
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], EncryptedExtensions> {
        let original_input = input;
        let mut srtp_profiles = None;
        let mut alpn = None;
        let mut server_name = None;
        let mut record_size_limit = None;
        let (input, extensions_len) = be_u16(input)?;
        let (input, extensions_data) = take(extensions_len)(input)?;

        let data_base_offset =
            base_offset + (extensions_data.as_ptr() as usize - original_input.as_ptr() as usize);

        let mut extensions = ArrayVec::new();
        let mut rest = extensions_data;
        let mut current_offset = data_base_offset;
        while !rest.is_empty() {
            let before_len = rest.len();
            let (new_rest, ext) = Extension::parse(rest, current_offset)?;
            let parsed_len = before_len - new_rest.len();
            current_offset += parsed_len;

            if ext.extension_type.is_supported() {
                if extensions
                    .iter()
                    .any(|existing: &Extension| existing.extension_type == ext.extension_type)
                {
                    return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
                }
                let range = &ext.extension_data_range;
                let data = &original_input[range.start - base_offset..range.end - base_offset];
                match ext.extension_type {
                    ExtensionType::UseSrtp => {
                        srtp_profiles = Some(UseSrtpExtension::parse(data)?.1.profiles);
                    }
                    ExtensionType::ApplicationLayerProtocolNegotiation => {
                        alpn = Some(ProtocolNameList::parse(data, range.start)?.1);
                    }
                    ExtensionType::ServerName => {
                        server_name = Some(ServerNameList::parse(data, range.start)?.1);
                    }
                    ExtensionType::RecordSizeLimit => {
                        record_size_limit = Some(RecordSizeLimit::parse(data)?.1);
                    }
                    _ => {}
                }
                extensions
                    .try_push(ext)
                    .map_err(|_| Err::Failure(Error::new(rest, ErrorKind::LengthValue)))?;
            }
            rest = new_rest;
        }

        Ok((
            input,
            EncryptedExtensions {
                extensions,
                srtp_profiles,
                alpn,
                server_name,
                record_size_limit,
            },
        ))
    }

    #[cfg(test)]
    pub fn new(extensions: ArrayVec<Extension, MAX_EE_EXTENSIONS>) -> Self {
        Self {
            extensions,
            srtp_profiles: None,
            alpn: None,
            server_name: None,
            record_size_limit: None,
        }
    }

    pub fn srtp_profiles(&self) -> Option<&ArrayVec<SrtpProfileId, 3>> {
        self.srtp_profiles.as_ref()
    }

    pub fn alpn(&self) -> Option<&ProtocolNameList> {
        self.alpn.as_ref()
    }

    #[allow(dead_code)]
    pub fn server_name(&self) -> Option<&ServerNameList> {
        self.server_name.as_ref()
    }

    pub fn record_size_limit(&self) -> Option<RecordSizeLimit> {
        self.record_size_limit
    }

    pub fn serialize(&self, buf: &[u8], output: &mut Buf) {
        let mut extensions_len = 0usize;
        for ext in &self.extensions {
            let ext_data = ext.extension_data(buf);
            extensions_len += 4 + ext_data.len();
        }

        output.extend_from_slice(&(extensions_len as u16).to_be_bytes());

        for ext in &self.extensions {
            ext.serialize(buf, output);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ExtensionType;
    use super::*;
    use crate::buffer::Buf;

    const MESSAGE: &[u8] = &[
        0x00, 0x0C, // Extensions length (12)
        0x00, 0x0A, // ExtensionType::SupportedGroups
        0x00, 0x08, // Extension data length
        0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, // Extension data
    ];

    #[test]
    fn roundtrip() {
        let (rest, parsed) = EncryptedExtensions::parse(MESSAGE, 0).unwrap();
        assert!(rest.is_empty());

        let mut serialized = Buf::new();
        parsed.serialize(MESSAGE, &mut serialized);
        assert_eq!(&*serialized, MESSAGE);
    }

    #[test]
    fn duplicate_supported_extensions_are_rejected() {
        let mut message = Vec::new();
        let count = 2;
        message.extend_from_slice(&(count as u16 * 4).to_be_bytes());
        for _ in 0..count {
            message.extend_from_slice(&ExtensionType::Cookie.as_u16().to_be_bytes());
            message.extend_from_slice(&0u16.to_be_bytes());
        }

        let result = EncryptedExtensions::parse(&message, 0);
        assert!(
            matches!(
                result,
                Err(nom::Err::Failure(error))
                    if error.code == nom::error::ErrorKind::LengthValue
            ),
            "duplicate supported extensions should fail with LengthValue"
        );
    }

    #[test]
    fn too_many_distinct_supported_extensions_are_rejected() {
        let mut extensions = Vec::new();
        for extension_type in ExtensionType::supported() {
            let data: &[u8] = match *extension_type {
                ExtensionType::SupportedVersions => &[0xfe, 0xfc],
                ExtensionType::KeyShare => &[0, 23, 0, 1, 7],
                ExtensionType::SupportedGroups => &[0, 2, 0, 23],
                ExtensionType::SignatureAlgorithms => &[0, 2, 4, 3],
                ExtensionType::UseSrtp => &[0, 2, 0, 1, 0],
                ExtensionType::Cookie => &[0, 1, 7],
                ExtensionType::ServerName => &[0, 0],
                ExtensionType::ApplicationLayerProtocolNegotiation => &[0, 3, 1, b'h', b'2'],
                ExtensionType::RecordSizeLimit => &[0x40, 0x01],
                ExtensionType::ConnectionId => &[0x01, 0xAA],
                _ => unreachable!(),
            };
            extensions.extend_from_slice(&extension_type.as_u16().to_be_bytes());
            extensions.extend_from_slice(&(data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(data);
        }
        let mut message = Vec::new();
        message.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        message.extend_from_slice(&extensions);

        let result = EncryptedExtensions::parse(&message, 0);
        assert!(
            matches!(
                result,
                Err(nom::Err::Failure(error))
                    if error.code == nom::error::ErrorKind::LengthValue
            ),
            "too many distinct supported extensions should fail with LengthValue"
        );
    }

    #[test]
    fn new_extensions_roundtrip() {
        let mut buf = Vec::new();
        let mut extensions = Vec::new();

        // ALPN = h2
        let alpn: &[u8] = &[0x00, 0x03, 0x02, b'h', b'2'];
        extensions.extend_from_slice(
            &ExtensionType::ApplicationLayerProtocolNegotiation
                .as_u16()
                .to_be_bytes(),
        );
        extensions.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
        extensions.extend_from_slice(alpn);

        // SNI ack (empty list)
        let sn: &[u8] = &[0x00, 0x00];
        extensions.extend_from_slice(&ExtensionType::ServerName.as_u16().to_be_bytes());
        extensions.extend_from_slice(&(sn.len() as u16).to_be_bytes());
        extensions.extend_from_slice(sn);

        // RecordSizeLimit = 1400
        let rsl: &[u8] = &[0x05, 0x78];
        extensions.extend_from_slice(&ExtensionType::RecordSizeLimit.as_u16().to_be_bytes());
        extensions.extend_from_slice(&(rsl.len() as u16).to_be_bytes());
        extensions.extend_from_slice(rsl);

        buf.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&extensions);

        let (rest, parsed) = EncryptedExtensions::parse(&buf, 0).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.alpn().unwrap().get(0, &buf), Some(&b"h2"[..]));
        assert!(parsed.server_name().is_some());
        assert_eq!(parsed.record_size_limit().unwrap().limit, 1400);

        let mut serialized = Buf::new();
        parsed.serialize(&buf, &mut serialized);
        assert_eq!(&*serialized, &buf[..]);
    }
}
