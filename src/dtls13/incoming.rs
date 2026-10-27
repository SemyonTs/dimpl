use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};

use arrayvec::ArrayVec;

use crate::buffer::{Buf, TmpBuf};
use crate::dtls13::message::{ContentType, Dtls13CipherSuite, Dtls13Record, Handshake, Sequence};
use crate::{Error, InternalError};

/// Holds both the UDP packet and the parsed result of that packet.
pub struct Incoming {
    // Box is here to reduce the size of the Incoming struct
    // to be passed in register instead of using memmove.
    records: Box<Records>,
}

impl Incoming {
    pub fn records(&self) -> &Records {
        &self.records
    }

    /// Mutable access to the record slice.
    ///
    /// Used by `Engine::poll_app_data` to advance a scan hint without re-walking
    /// the entire queue on each poll.
    #[allow(dead_code)]
    pub fn records_mut(&mut self) -> &mut [Record] {
        self.records.records.as_mut_slice()
    }

    pub fn first(&self) -> &Record {
        // Invariant: Every Incoming must have at least one Record
        // or the parser of Incoming returns None.
        &self.records()[0]
    }

    pub fn into_records(self) -> impl Iterator<Item = Record> {
        self.records.records.into_iter()
    }
}

impl Incoming {
    /// Parse an incoming UDP packet
    ///
    /// * `packet` is the data from the UDP socket.
    /// * `decrypt` provides the decryption operations for encrypted records.
    /// * `cs` is the negotiated cipher suite, if any.
    ///
    /// Will surface parser errors.
    pub fn parse_packet(
        packet: &[u8],
        decrypt: &mut dyn RecordHandler,
        cs: Option<Dtls13CipherSuite>,
    ) -> Result<Option<Self>, InternalError> {
        // Parse records directly from packet, copying each record ONCE into its own buffer
        let records = Records::parse(packet, decrypt, cs)?;

        // We need at least one Record to be valid. For replayed frames, we discard
        // the records, hence this might be None
        if records.records.is_empty() {
            return Ok(None);
        }

        let records = Box::new(records);

        Ok(Some(Incoming { records }))
    }
}

/// A number of records parsed from a single UDP packet.
#[derive(Debug)]
pub struct Records {
    pub records: ArrayVec<Record, 16>,
}

impl Records {
    pub fn parse(
        packet: &[u8],
        decrypt: &mut dyn RecordHandler,
        cs: Option<Dtls13CipherSuite>,
    ) -> Result<Records, InternalError> {
        let mut parsed_records: ArrayVec<Record, 16> = ArrayVec::new();
        if let Err(error) = Self::parse_records(packet, decrypt, cs, &mut parsed_records) {
            for record in parsed_records {
                decrypt.push_buffer(record.into_buffer());
            }
            return Err(error);
        }

        let mut records = ArrayVec::new();
        for record in parsed_records {
            if let Some(record) = decrypt.classify_record(record)? {
                records
                    .try_push(record)
                    .expect("filtered records cannot exceed parsed records");
            }
        }

        Ok(Records { records })
    }

    fn parse_records(
        mut packet: &[u8],
        decrypt: &mut dyn RecordHandler,
        cs: Option<Dtls13CipherSuite>,
        parsed_records: &mut ArrayVec<Record, 16>,
    ) -> Result<(), InternalError> {
        // Find record boundaries and copy each record ONCE from the packet
        while !packet.is_empty() {
            let record_end = if Dtls13Record::is_ciphertext_header(packet[0]) {
                // Unified header: variable length
                if packet.len() < 2 {
                    return Err(InternalError::parse_incomplete());
                }

                let flags = packet[0];
                let c_flag = flags & 0x10 != 0;
                let cid_len = if c_flag {
                    match decrypt.local_connection_id() {
                        Some(cid) => cid.len(),
                        None => break,
                    }
                } else {
                    0
                };
                let s_flag = flags & 0b0000_1000 != 0;
                let l_flag = flags & 0b0000_0100 != 0;
                let seq_len = if s_flag { 2 } else { 1 };
                let len_len = if l_flag { 2 } else { 0 };
                let header_len = 1 + cid_len + seq_len + len_len;

                if packet.len() < header_len {
                    return Err(InternalError::parse_incomplete());
                }

                if l_flag {
                    let len_offset = 1 + cid_len + seq_len;
                    // unwrap: header_len check above ensures 2 bytes at len_offset
                    let length_bytes: [u8; 2] =
                        packet[len_offset..len_offset + 2].try_into().unwrap();
                    let length = u16::from_be_bytes(length_bytes) as usize;
                    header_len + length
                } else {
                    // No length field: record consumes the rest of the datagram
                    packet.len()
                }
            } else {
                // Plaintext: fixed 13-byte header
                if packet.len() < Dtls13Record::PLAINTEXT_HEADER_LEN {
                    return Err(InternalError::parse_incomplete());
                }

                // unwrap: PLAINTEXT_HEADER_LEN check above ensures 2 bytes at offset
                let length_bytes: [u8; 2] = packet[Dtls13Record::PLAINTEXT_LENGTH_OFFSET]
                    .try_into()
                    .unwrap();
                let length = u16::from_be_bytes(length_bytes) as usize;
                Dtls13Record::PLAINTEXT_HEADER_LEN + length
            };

            if packet.len() < record_end {
                return Err(InternalError::parse_incomplete());
            }

            // This is the ONLY copy: packet -> record buffer
            let record_slice = &packet[..record_end];
            let record = Record::parse(record_slice, decrypt, cs)?;
            if let Some(record) = record {
                if let Err(error) = parsed_records.try_push(record) {
                    decrypt.push_buffer(error.element().into_buffer());
                    return Err(InternalError::too_many_records());
                }
            } else {
                trace!("Discarding replayed rec");
            }

            packet = &packet[record_end..];
        }

        Ok(())
    }
}

impl Deref for Records {
    type Target = [Record];

    fn deref(&self) -> &Self::Target {
        &self.records
    }
}

pub struct Record {
    buffer: Buf,
    // Box is here to reduce the size of the Record struct
    // to be passed in register instead of using memmove.
    parsed: Box<ParsedRecord>,
}

impl Record {
    /// The first parse pass only parses the record header which is unencrypted.
    /// Copies record data from UDP packet ONCE into a pooled buffer.
    pub fn parse(
        record_slice: &[u8],
        decrypt: &mut dyn RecordHandler,
        cs: Option<Dtls13CipherSuite>,
    ) -> Result<Option<Record>, InternalError> {
        // ONLY COPY: UDP packet slice -> pooled buffer
        let mut buffer = decrypt.pop_buffer();
        buffer.extend_from_slice(record_slice);

        let c_flag = buffer[0] & 0x10 != 0;
        let cid_len = if c_flag {
            decrypt.local_connection_id().map_or(0, |c| c.len())
        } else {
            0
        };

        match Self::parse_buffer(&mut buffer, decrypt, cs, cid_len) {
            Ok(Some(parsed)) => Ok(Some(Record { buffer, parsed })),
            result => {
                decrypt.push_buffer(buffer);
                result.map(|_| None)
            }
        }
    }

    /// Parse (and, for protected records, decrypt) a single record into a `ParsedRecord`.
    ///
    /// Hot-path note: for ciphertext records we deliberately avoid constructing an
    /// intermediate `ParsedRecord` (which used to carry an inline
    /// `ArrayVec<Handshake, 8>` ≈ 8 KB) before decryption. Instead we parse only
    /// the small `Dtls13Record` header, decrypt, and box the final `ParsedRecord`
    /// exactly once. This removes a per-packet 8 KB stack allocation, an 8 KB heap
    /// allocation, and the associated memcpy on the application-data path.
    fn parse_buffer(
        buffer: &mut Buf,
        decrypt: &mut dyn RecordHandler,
        cs: Option<Dtls13CipherSuite>,
        cid_len: usize,
    ) -> Result<Option<Box<ParsedRecord>>, InternalError> {
        let is_ciphertext = Dtls13Record::is_ciphertext_header(buffer[0]);

        // Before keys are available, only handshake epoch 2 and application
        // epoch 3 can be buffered. Epochs with low bits 0 or 1 require KeyUpdate.
        if is_ciphertext && !decrypt.is_peer_encryption_enabled() && buffer[0] & 0x03 < 2 {
            return Ok(None);
        }

        // ---- Plaintext path: full parse + handshake extraction in one pass. ----
        //
        // Plaintext records (epoch 0) are never encrypted, so this is also the
        // only place we ever parse handshakes out of the buffer at rest.
        if !is_ciphertext {
            let parsed = match ParsedRecord::parse(buffer, cs) {
                Ok(p) => p,
                Err(e) => {
                    trace!("Discarding record: parse failed: {}", e);
                    return Ok(None);
                }
            };
            return Ok(Some(Box::new(parsed)));
        }

        // ---- Ciphertext path ----
        //
        // Small stack-only header struct is all we need before decrypting.
        if decrypt.is_peer_encryption_enabled() {
            // Decrypt record number in-place before parsing (RFC 9147 Section 4.2.3)
            let flags = buffer[0];
            let s_flag = flags & 0b0000_1000 != 0;
            let l_flag = flags & 0b0000_0100 != 0;
            let seq_len: usize = if s_flag { 2 } else { 1 };
            let len_len: usize = if l_flag { 2 } else { 0 };
            let header_len = 1 + cid_len + seq_len + len_len;

            if buffer.len() >= header_len + 16 {
                // unwrap: bounds checked above
                let ciphertext_sample: [u8; 16] =
                    buffer[header_len..header_len + 16].try_into().unwrap();

                // Resolve epoch from 2-bit field (doesn't depend on seq bytes)
                let epoch_bits = flags & 0x03;
                let full_epoch = decrypt.resolve_epoch(epoch_bits);

                // Decrypt sequence bytes in place
                decrypt.decrypt_sequence_number(
                    full_epoch,
                    &mut buffer[1 + cid_len..1 + cid_len + seq_len],
                    &ciphertext_sample,
                );
            }
        }

        // Parse only the unified header (small on stack, no handshake list yet).
        let header = match Dtls13Record::parse(buffer, 0, cid_len) {
            Ok((_, header)) => header,
            Err(e) => {
                trace!("Discarding record: parse failed: {}", e);
                return Ok(None);
            }
        };

        // No keys yet: buffer the record as-is so the engine can re-parse it
        // after `enable_peer_encryption` installs the epoch keys.
        // The synthetic content type is `ApplicationData`, so `parse_handshakes_for`
        // returns `None` — no handshake allocation even on this buffered path.
        if !decrypt.is_peer_encryption_enabled() {
            let parsed = ParsedRecord::parse_decrypted(header, buffer, cs);
            return Ok(Some(Box::new(parsed)));
        }

        if cid_len > 0 {
            let cid_bytes = &buffer[1..1 + cid_len];
            match decrypt.local_connection_id() {
                Some(expected) if expected == cid_bytes => {}
                _ => {
                    trace!("Discarding record: CID mismatch");
                    return Ok(None);
                }
            }
        }

        // Resolve the full epoch from the 2-bit value in the unified header
        let epoch_bits = header.sequence.epoch as u8;
        let full_epoch = decrypt.resolve_epoch(epoch_bits);

        // Resolve the full sequence number from the (now decrypted) partial value
        let seq_bits = header.sequence.sequence_number;
        let s_flag = buffer[0] & 0b0000_1000 != 0;
        let full_seq = decrypt.resolve_sequence(full_epoch, seq_bits, s_flag);

        let full_sequence = Sequence {
            epoch: full_epoch,
            sequence_number: full_seq,
        };

        // Anti-replay check (read-only, does not update window)
        if !decrypt.replay_check(full_sequence) {
            return Ok(None);
        }

        // Save the raw header bytes for AAD before mutating the buffer.
        // Max unified header without CID: flags(1) + seq(2) + length(2) = 5 bytes.
        let header_end = header.fragment_range.start;

        // Reject protected records whose encrypted fragment is shorter than
        // the per-suite minimum — they cannot hold a valid ciphertext + tag,
        // so decryption would necessarily fail. Catching it here keeps the
        // cipher impls' bounds-checking from being the only line of defence.
        if buffer.len() - header_end < decrypt.min_protected_fragment_len() {
            return Ok(None);
        }

        let mut header_buf = [0u8; 32];
        header_buf[..header_end].copy_from_slice(&buffer[..header_end]);

        // The encrypted part starts right after the unified header.
        let ciphertext = &mut buffer[header_end..];

        let new_len = {
            let mut buffer = TmpBuf::new(ciphertext);

            // This decrypts in place.
            // RFC 9147 §4.5.2: failed-to-decrypt ciphertext records MUST be silently discarded.
            match decrypt.decrypt_record(&header_buf[..header_end], full_sequence, &mut buffer) {
                Ok(()) => {}
                Err(e) => {
                    trace!("Discarding ciphertext record: decryption failed: {}", e);
                    return Ok(None);
                }
            }

            buffer.len()
        };

        // Decryption succeeded — now commit the replay window update.
        // RFC 9147 §4.5.1: "The window MUST NOT be updated due to a received
        // record until that record has been deprotected successfully."
        decrypt.replay_update(full_sequence);

        // Recover inner content type from DTLSInnerPlaintext
        let decrypted = &buffer[header_end..header_end + new_len];
        let (inner_content_type, content_len) = match recover_inner_content_type(decrypted) {
            Ok(v) => v,
            Err(e) => {
                trace!("Discarding record: invalid inner content type: {}", e);
                return Ok(None);
            }
        };

        let parsed = ParsedRecord::parse_decrypted(
            Dtls13Record {
                content_type: inner_content_type,
                sequence: full_sequence,
                length: content_len as u16,
                fragment_range: header_end..(header_end + content_len),
            },
            buffer,
            cs,
        );
        Ok(Some(Box::new(parsed)))
    }

    pub fn record(&self) -> &Dtls13Record {
        &self.parsed.record
    }

    pub fn handshakes(&self) -> &[Handshake] {
        match &self.parsed.handshakes {
            Some(v) => v.as_slice(),
            None => &[],
        }
    }

    pub fn retain_handshakes(&mut self, mut keep: impl FnMut(&Handshake) -> bool) {
        if let Some(v) = &mut self.parsed.handshakes {
            v.retain(|handshake| keep(handshake));
        }
    }

    pub fn first_handshake(&self) -> Option<&Handshake> {
        self.parsed.handshakes.as_deref().and_then(|v| v.first())
    }

    pub fn is_handled(&self) -> bool {
        match &self.parsed.handshakes {
            Some(v) if !v.is_empty() => v.iter().all(|h| h.is_handled()),
            _ => self.parsed.handled.load(Ordering::Relaxed),
        }
    }

    pub fn set_handled(&self) {
        // Handshakes should be empty because we set_handled() on them individually
        // during defragmentation. set_handled() on the record is only for non-handshakes.
        match &self.parsed.handshakes {
            None => {}
            Some(v) => assert!(
                v.is_empty(),
                "set_handled() requires no pending handshakes on the record"
            ),
        }
        self.parsed.handled.store(true, Ordering::Relaxed);
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub(crate) fn into_buffer(self) -> Buf {
        self.buffer
    }
}

pub struct ParsedRecord {
    record: Dtls13Record,
    /// Handshake fragments parsed from a handshake-content record.
    ///
    /// Only `Some` for records whose content type is `Handshake`. Application
    /// data, alerts, and ACKs leave it `None`.
    ///
    /// Boxed so the fixed part of `ParsedRecord` stays at ~50 bytes. The
    /// inline variant of `ArrayVec<Handshake, 8>` is ~8 KB because the
    /// `Body::Certificate` variant carries a whole certificate list; paying
    /// that per inbound record (even per app-data record) used to dominate
    /// the steady-state receive path. Boxing only on handshake records
    /// removes that cost with zero steady-state overhead.
    handshakes: Option<Box<ArrayVec<Handshake, 8>>>,
    handled: AtomicBool,
}

impl ParsedRecord {
    pub fn parse(
        input: &[u8],
        cipher_suite: Option<Dtls13CipherSuite>,
    ) -> Result<ParsedRecord, InternalError> {
        let (_, record) = Dtls13Record::parse(input, 0, 0)?;
        let handshakes = parse_handshakes_for(&record, input, cipher_suite);
        Ok(ParsedRecord {
            record,
            handshakes,
            handled: AtomicBool::new(false),
        })
    }

    /// Build a ParsedRecord from an already-constructed record (after decryption).
    pub fn parse_decrypted(
        record: Dtls13Record,
        input: &[u8],
        cipher_suite: Option<Dtls13CipherSuite>,
    ) -> ParsedRecord {
        let handshakes = parse_handshakes_for(&record, input, cipher_suite);
        ParsedRecord {
            record,
            handshakes,
            handled: AtomicBool::new(false),
        }
    }
}

/// Parse handshake fragments for a record, if and only if it's a handshake-content record.
///
/// Returning `None` for non-handshake content is what keeps the app-data hot
/// path from ever touching the ~8 KB handshake scratch space.
fn parse_handshakes_for(
    record: &Dtls13Record,
    input: &[u8],
    cipher_suite: Option<Dtls13CipherSuite>,
) -> Option<Box<ArrayVec<Handshake, 8>>> {
    if record.content_type != ContentType::Handshake {
        return None;
    }
    let fragment_offset = record.fragment_range.start;
    Some(Box::new(parse_handshakes(
        record.fragment(input),
        fragment_offset,
        cipher_suite,
    )))
}

/// Trait abstracting record parsing-time handling for incoming records.
///
/// This decouples the record parser from the full `Engine`, allowing the parse loop
/// to acquire buffers, decrypt records, classify control records, and queue only the records that
/// should survive into `Incoming`.
pub trait RecordHandler {
    /// Acquire an empty buffer whose allocation can be reused for a record.
    fn pop_buffer(&mut self) -> Buf;
    /// Recycle a buffer when parsing fails or silently discards a record.
    fn push_buffer(&mut self, buffer: Buf);
    /// Local Connection ID (RFC 9146). `Some(_)` means we accept
    /// ciphertext records with the C-bit set.
    fn local_connection_id(&self) -> Option<&[u8]>;
    fn classify_record(&mut self, record: Record) -> Result<Option<Record>, Error>;
    fn is_peer_encryption_enabled(&self) -> bool;
    fn resolve_epoch(&self, epoch_bits: u8) -> u16;
    fn resolve_sequence(&self, epoch: u16, seq_bits: u64, s_flag: bool) -> u64;
    fn replay_check(&self, seq: Sequence) -> bool;
    fn replay_update(&mut self, seq: Sequence);

    /// Minimum length of a protected record's encrypted fragment for the
    /// negotiated suite (tag length in DTLS 1.3). Used to reject records that
    /// cannot possibly contain a valid ciphertext + tag.
    fn min_protected_fragment_len(&self) -> usize;

    fn decrypt_record(
        &mut self,
        header: &[u8],
        seq: Sequence,
        ciphertext: &mut TmpBuf,
    ) -> Result<(), Error>;

    /// Decrypt the sequence number bytes in a unified header (RFC 9147 Section 4.2.3).
    ///
    /// `epoch` is the resolved full epoch, `seq_bytes` are the encrypted sequence
    /// bytes from the header (1 or 2 bytes), and `ciphertext_sample` is the first
    /// 16 bytes of the ciphertext following the header.
    ///
    /// Returns the decrypted sequence bytes in-place.
    fn decrypt_sequence_number(
        &self,
        epoch: u16,
        seq_bytes: &mut [u8],
        ciphertext_sample: &[u8; 16],
    );
}

fn parse_handshakes(
    mut input: &[u8],
    mut base_offset: usize,
    cipher_suite: Option<Dtls13CipherSuite>,
) -> ArrayVec<Handshake, 8> {
    let mut handshakes = ArrayVec::new();
    while !input.is_empty() {
        if let Ok((remaining, handshake)) = Handshake::parse(input, base_offset, cipher_suite, true)
        {
            let len = input.len() - remaining.len();
            base_offset += len;
            input = remaining;
            if handshakes.try_push(handshake).is_err() {
                break;
            }
        } else {
            break;
        }
    }
    handshakes
}

/// Recover the inner content type from a decrypted DTLSInnerPlaintext.
///
/// The format is: `content || ContentType || zeros*`
/// Scan backward past zero padding to find the content type byte.
fn recover_inner_content_type(decrypted: &[u8]) -> Result<(ContentType, usize), InternalError> {
    // `rposition` finds the index of the last non-zero byte: that's the
    // content type. Everything before it is content (with content_len == i);
    // everything after is zero padding.
    let i = decrypted
        .iter()
        .rposition(|&b| b != 0)
        .ok_or_else(|| InternalError::parse(nom::error::ErrorKind::Fail))?;
    let content_type = ContentType::from_u8(decrypted[i]);
    Ok((content_type, i))
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Incoming")
            .field("records", &self.records())
            .finish()
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("record", &self.parsed.record)
            .field("handshakes", &self.handshakes())
            .finish()
    }
}

/*
Why it is sound to assert UnwindSafe for Incoming

- No internal unwind boundaries: this crate does not use catch_unwind. We do not
  cross panic boundaries internally while mutating state. This marker exists to
  document that external callers can wrap our APIs in catch_unwind without
  observing broken invariants from this type.

- Read-only builders: our dependent builders (e.g., ParsedRecord::parse) take
  only a &[u8] to the buffer and do not mutate the buffer during construction.
  An unwind during builder execution therefore cannot leave the buffer partially
  mutated across a boundary.

- Decrypt-and-reparse is publish-after-complete: when decrypting we first extract
  the buffer, mutate it (in-place decrypt), and only then construct a fresh Record
  from the fully transformed bytes. If a panic occurs mid-transformation, the new
  Record is not built and the previously-built Record is dropped; no consumer can
  observe a half-transformed record across an unwind boundary.

- Interior mutability is benign across unwind: the only interior mutability is
  AtomicBool "handled" flags. They are monotonic (false -> true). If an external
  caller catches a panic and continues, the worst effect is conservatively
  skipping work already done. This does not introduce memory unsafety or aliasing
  violations, and no invariants rely on "handled implies delivery".

Given the above, an unwind cannot leave Incoming in a state where broken
invariants are later observed across a catch_unwind boundary. Marking Incoming
as UnwindSafe is a sound assertion and clarifies behavior for callers.
*/
impl std::panic::UnwindSafe for Incoming {}

#[cfg(test)]
mod tests {
    use crate::buffer::BufferPool;

    use super::*;

    #[derive(Default)]
    struct TestHandler {
        buffers: BufferPool,
        buffers_acquired: usize,
        buffers_returned: usize,
        classify_calls: usize,
        dropped_acks: usize,
    }

    impl RecordHandler for TestHandler {
        fn pop_buffer(&mut self) -> Buf {
            self.buffers_acquired += 1;
            self.buffers.pop()
        }

        fn push_buffer(&mut self, buffer: Buf) {
            self.buffers_returned += 1;
            self.buffers.push(buffer);
        }

        fn local_connection_id(&self) -> Option<&[u8]> {
            None
        }

        fn classify_record(&mut self, record: Record) -> Result<Option<Record>, Error> {
            self.classify_calls += 1;
            if record.record().content_type == ContentType::Ack {
                self.dropped_acks += 1;
                self.push_buffer(record.into_buffer());
                return Ok(None);
            }
            Ok(Some(record))
        }

        fn is_peer_encryption_enabled(&self) -> bool {
            false
        }

        fn resolve_epoch(&self, _epoch_bits: u8) -> u16 {
            panic!("resolve_epoch should not be called when peer encryption is disabled");
        }

        fn resolve_sequence(&self, _epoch: u16, _seq_bits: u64, _s_flag: bool) -> u64 {
            panic!("resolve_sequence should not be called when peer encryption is disabled");
        }

        fn replay_check(&self, _seq: Sequence) -> bool {
            panic!("replay_check should not be called when peer encryption is disabled");
        }

        fn replay_update(&mut self, _seq: Sequence) {
            panic!("replay_update should not be called when peer encryption is disabled");
        }

        fn min_protected_fragment_len(&self) -> usize {
            panic!(
                "min_protected_fragment_len should not be called when peer encryption is disabled"
            );
        }

        fn decrypt_record(
            &mut self,
            _header: &[u8],
            _seq: Sequence,
            _ciphertext: &mut TmpBuf,
        ) -> Result<(), Error> {
            panic!("decrypt_record should not be called when peer encryption is disabled");
        }

        fn decrypt_sequence_number(
            &self,
            _epoch: u16,
            _seq_bytes: &mut [u8],
            _ciphertext_sample: &[u8; 16],
        ) {
            panic!("decrypt_sequence_number should not be called when peer encryption is disabled");
        }
    }

    fn build_plaintext_record(content_type: ContentType, seq: u64, fragment: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(content_type.as_u8());
        out.extend_from_slice(&[0xFE, 0xFD]);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes()[2..]);
        out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(fragment);
        out
    }

    fn build_ciphertext_record(epoch: u16, seq: u16, fragment: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let flags = 0b0010_0000 | 0b0000_1000 | 0b0000_0100 | (epoch as u8 & 0x03);
        out.push(flags);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(fragment);
        out
    }

    #[test]
    fn parse_packet_filters_control_records_after_packet_validation() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&build_plaintext_record(ContentType::Ack, 1, &[0xAA, 0xBB]));
        packet.extend_from_slice(&build_ciphertext_record(2, 2, &[0x11, 0x22, 0x33]));

        let mut handler = TestHandler::default();
        let incoming = Incoming::parse_packet(&packet, &mut handler, None)
            .unwrap()
            .expect("ciphertext application data record should remain");

        assert_eq!(handler.classify_calls, 2);
        assert_eq!(handler.dropped_acks, 1);
        assert_eq!(incoming.records().len(), 1);
        assert_eq!(
            incoming.first().record().content_type,
            ContentType::ApplicationData
        );
        assert_eq!(incoming.first().record().sequence.epoch, 2);

        // Fast path: non-handshake records never allocate a handshake array.
        assert!(
            incoming.first().parsed.handshakes.is_none(),
            "application-data record must not carry an inline handshake array"
        );
    }

    #[test]
    fn records_mut_allows_setting_handled_in_place() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&build_ciphertext_record(2, 1, &[0x11; 32]));
        packet.extend_from_slice(&build_ciphertext_record(2, 2, &[0x22; 32]));

        let mut handler = TestHandler::default();
        let mut incoming = Incoming::parse_packet(&packet, &mut handler, None)
            .unwrap()
            .expect("packet contains two records");
        assert_eq!(incoming.records().len(), 2);
        assert!(!incoming.records()[0].is_handled());
        assert!(!incoming.records()[1].is_handled());

        // Mutate via the new accessor: mark both records handled.
        for rec in incoming.records_mut() {
            rec.set_handled();
        }
        assert!(incoming.records()[0].is_handled());
        assert!(incoming.records()[1].is_handled());
    }

    #[test]
    fn receive_records_reuse_pooled_buffers() {
        let mut handler = TestHandler::default();
        let mut buffer = handler.pop_buffer();
        buffer.resize(2048, 0xAA);
        let allocation = buffer.as_ptr();
        handler.push_buffer(buffer);

        let packet = build_ciphertext_record(2, 1, &[0x11; 1500]);
        for _ in 0..10_000 {
            let incoming = Incoming::parse_packet(&packet, &mut handler, None)
                .expect("parse application data")
                .expect("packet contains a record");
            assert_eq!(incoming.first().buffer().as_ptr(), allocation);
            assert_eq!(incoming.first().buffer(), packet);
            for record in incoming.into_records() {
                handler.push_buffer(record.into_buffer());
            }
        }
    }

    #[test]
    fn discarded_records_return_pooled_buffers() {
        let mut handler = TestHandler::default();
        let mut buffer = handler.pop_buffer();
        buffer.resize(2048, 0xAA);
        let allocation = buffer.as_ptr();
        handler.push_buffer(buffer);

        let packet = build_plaintext_record(ContentType::ApplicationData, 1, &[0x11; 1500]);
        let incoming = Incoming::parse_packet(&packet, &mut handler, None)
            .expect("invalid plaintext application data is discarded");
        assert!(incoming.is_none());
        let reused = handler.pop_buffer();
        assert!(reused.is_empty());
        assert_eq!(reused.as_ptr(), allocation);
    }

    #[test]
    fn truncated_datagram_recycles_all_pooled_records() {
        let mut handler = TestHandler::default();
        let mut packet = build_ciphertext_record(2, 1, &[0x11; 1500]);
        packet.push(0xFF);

        assert!(Incoming::parse_packet(&packet, &mut handler, None).is_err());
        assert_eq!(handler.classify_calls, 0);
        assert_eq!(
            handler.buffers_returned, handler.buffers_acquired,
            "discarding a malformed datagram must recycle its accepted records"
        );
    }

    #[test]
    fn oversized_datagram_recycles_all_pooled_records() {
        let mut handler = TestHandler::default();
        let mut packet = Vec::new();
        for sequence in 0..17 {
            packet.extend_from_slice(&build_ciphertext_record(2, sequence, &[0x11; 32]));
        }

        assert!(Incoming::parse_packet(&packet, &mut handler, None).is_err());
        assert_eq!(handler.classify_calls, 0);
        assert_eq!(
            handler.buffers_returned, handler.buffers_acquired,
            "discarding a datagram with too many records must recycle every record"
        );
    }
}
