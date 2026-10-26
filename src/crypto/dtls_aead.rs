//! DTLS AEAD record formatting types and constants.
//!
//! This module contains types and constants specific to DTLS AEAD record formatting,
//! separate from the pluggable crypto provider abstraction.

use arrayvec::ArrayVec;

/// Explicit nonce length for DTLS AEAD records.
///
/// The explicit nonce is transmitted with each record.
#[cfg(test)]
pub(crate) const DTLS_EXPLICIT_NONCE_LEN: usize = 8;

/// GCM authentication tag length.
///
/// The tag is appended to the ciphertext.
#[cfg(test)]
pub(crate) const GCM_TAG_LEN: usize = 16;

/// Overhead per DTLS 1.2 AES-GCM record (explicit nonce + tag).
///
/// This equals 24 bytes for DTLS AES-GCM.
#[cfg(test)]
pub(crate) const DTLS_AEAD_OVERHEAD: usize = DTLS_EXPLICIT_NONCE_LEN + GCM_TAG_LEN; // 24

/// Compute AAD length from plaintext length for DTLS 1.2 AES-GCM records.
#[inline]
#[cfg(test)]
pub fn aad_len_from_plaintext_len(plaintext_len: u16) -> u16 {
    plaintext_len
}

/// Compute fragment length from plaintext length for DTLS 1.2 AES-GCM records.
/// fragment_len = explicit_nonce(8) + ciphertext(plaintext_len + 16 tag)
#[inline]
#[cfg(test)]
pub fn fragment_len_from_plaintext_len(plaintext_len: usize) -> usize {
    DTLS_EXPLICIT_NONCE_LEN + plaintext_len + GCM_TAG_LEN
}

/// Compute plaintext length from fragment length for DTLS 1.2 AES-GCM records.
/// Returns None if the fragment is smaller than the mandatory AEAD overhead.
#[inline]
#[cfg(test)]
pub fn plaintext_len_from_fragment_len(fragment_len: usize) -> Option<usize> {
    fragment_len.checked_sub(DTLS_AEAD_OVERHEAD)
}

/// Full AEAD nonce (fixed IV + explicit nonce).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce(pub [u8; 12]);

impl Nonce {
    /// Create a nonce by XORing the IV with the padded sequence number.
    ///
    /// Used by both DTLS 1.2 (ChaCha20-Poly1305) and DTLS 1.3:
    /// nonce = iv XOR pad_left(sequence_number, 12)
    /// See RFC 8446 Section 5.3 / RFC 7905.
    pub(crate) fn xor(iv: &[u8; 12], seq: u64) -> Self {
        let mut nonce = *iv;
        let seq_bytes = seq.to_be_bytes(); // 8 bytes
        // XOR the last 8 bytes of the 12-byte IV with the sequence number
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        Self(nonce)
    }
}

/// Additional Authenticated Data for DTLS records.
///
/// Variable-length to support both DTLS 1.2 (13 bytes) and DTLS 1.3 (3-5 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aad(pub ArrayVec<u8, 32>);

impl Aad {
    /// Create Additional Authenticated Data for a DTLS 1.3 record.
    ///
    /// The AAD is the raw unified header bytes (3-5 bytes without CID,
    /// up to 5+27 with Connection ID negotiated via RFC 9146).
    pub(crate) fn new_dtls13(header_bytes: &[u8]) -> Self {
        let mut aad = ArrayVec::new();
        // Capacity is 32; `header_bytes.len() <= 5 + MAX_CID_LEN = 32`.
        aad.try_extend_from_slice(header_bytes)
            .expect("DTLS 1.3 header exceeds AAD capacity");
        Aad(aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_constants_and_length_helpers() {
        assert_eq!(DTLS_EXPLICIT_NONCE_LEN, 8);
        assert_eq!(GCM_TAG_LEN, 16);
        assert_eq!(DTLS_AEAD_OVERHEAD, 24);

        for &pt_len in &[0usize, 1, 37, 512, 1350, 16384] {
            let aad_len = aad_len_from_plaintext_len(pt_len as u16);
            assert_eq!(aad_len as usize, pt_len);

            let frag_len = fragment_len_from_plaintext_len(pt_len);
            assert_eq!(frag_len, DTLS_EXPLICIT_NONCE_LEN + pt_len + GCM_TAG_LEN);

            let roundtrip =
                plaintext_len_from_fragment_len(frag_len).expect("frag_len >= overhead");
            assert_eq!(roundtrip, pt_len);
        }

        assert!(plaintext_len_from_fragment_len(0).is_none());
        assert!(plaintext_len_from_fragment_len(3).is_none());
        assert!(plaintext_len_from_fragment_len(DTLS_AEAD_OVERHEAD - 1).is_none());
    }
}
