//! Cipher suite implementations using aws-lc-rs.

use aws_lc_rs::aead::quic::{self as aws_quic, HeaderProtectionKey};
use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, UnboundKey};
use aws_lc_rs::aead::{Aad as AwsAad, LessSafeKey, Nonce as AwsNonce};
use aws_lc_rs::cipher::{self as aws_cipher, AES_128, AES_256, EncryptingKey, UnboundCipherKey};

use super::super::{Cipher, SupportedDtls13CipherSuite};
use crate::buffer::{Buf, TmpBuf};
use crate::crypto::{Aad, Nonce};
use crate::error::bounded_error_len;
use crate::types::{Dtls13CipherSuite, HashAlgorithm};
use crate::{CryptoError, CryptoOperation};

/// AES-GCM cipher implementation using aws-lc-rs.
struct AesGcm {
    key: LessSafeKey,
}

impl std::fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcm").finish_non_exhaustive()
    }
}

impl AesGcm {
    fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let algorithm = match key.len() {
            16 => &AES_128_GCM,
            32 => &AES_256_GCM,
            _ => {
                return Err(CryptoError::InvalidAesGcmKeySize {
                    actual: bounded_error_len(key.len()),
                });
            }
        };

        let unbound_key = UnboundKey::new(algorithm, key)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::CreateCipher))?;

        Ok(AesGcm {
            key: LessSafeKey::new(unbound_key),
        })
    }
}

impl Cipher for AesGcm {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), CryptoError> {
        let aws_nonce =
            AwsNonce::try_assume_unique_for_key(&nonce).map_err(|_| CryptoError::InvalidNonce)?;
        let aws_aad = AwsAad::from(&aad[..]);
        self.key
            .seal_in_place_append_tag(aws_nonce, aws_aad, plaintext)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Encrypt))?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), CryptoError> {
        if ciphertext.len() < 16 {
            return Err(CryptoError::CiphertextTooShort {
                minimum: 16,
                actual: ciphertext.len() as u8,
            });
        }
        let aws_nonce =
            AwsNonce::try_assume_unique_for_key(&nonce).map_err(|_| CryptoError::InvalidNonce)?;
        let aws_aad = AwsAad::from(&aad[..]);
        let plaintext = self
            .key
            .open_in_place(aws_nonce, aws_aad, ciphertext.as_mut())
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Decrypt))?;
        let plaintext_len = plaintext.len();
        ciphertext.truncate(plaintext_len);
        Ok(())
    }
}

/// ChaCha20-Poly1305 cipher implementation using aws-lc-rs.
struct ChaCha20Poly1305Cipher {
    key: LessSafeKey,
}

impl std::fmt::Debug for ChaCha20Poly1305Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaCha20Poly1305Cipher")
            .finish_non_exhaustive()
    }
}

impl ChaCha20Poly1305Cipher {
    fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidChacha20Poly1305KeySize {
                actual: bounded_error_len(key.len()),
            });
        }
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::CreateCipher))?;
        Ok(ChaCha20Poly1305Cipher {
            key: LessSafeKey::new(unbound_key),
        })
    }
}

impl Cipher for ChaCha20Poly1305Cipher {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), CryptoError> {
        let aws_nonce =
            AwsNonce::try_assume_unique_for_key(&nonce).map_err(|_| CryptoError::InvalidNonce)?;
        let aws_aad = AwsAad::from(&aad[..]);
        self.key
            .seal_in_place_append_tag(aws_nonce, aws_aad, plaintext)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Encrypt))?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), CryptoError> {
        if ciphertext.len() < 16 {
            return Err(CryptoError::CiphertextTooShort {
                minimum: 16,
                actual: ciphertext.len() as u8,
            });
        }
        let aws_nonce =
            AwsNonce::try_assume_unique_for_key(&nonce).map_err(|_| CryptoError::InvalidNonce)?;
        let aws_aad = AwsAad::from(&aad[..]);
        let plaintext = self
            .key
            .open_in_place(aws_nonce, aws_aad, ciphertext.as_mut())
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Decrypt))?;
        let plaintext_len = plaintext.len();
        ciphertext.truncate(plaintext_len);
        Ok(())
    }
}

// ============================================================================
// DTLS 1.3 Cipher Suites
// ============================================================================

/// TLS_AES_128_GCM_SHA256 cipher suite.
#[derive(Debug)]
struct Tls13Aes128GcmSha256;

impl SupportedDtls13CipherSuite for Tls13Aes128GcmSha256 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::AES_128_GCM_SHA256
    }
    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
    fn key_len(&self) -> usize {
        16
    }
    fn iv_len(&self) -> usize {
        12
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        Ok(Box::new(AesGcm::new(key)?))
    }
    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        aes_ecb_encrypt(&AES_128, sn_key, sample)
    }
}

/// TLS_AES_256_GCM_SHA384 cipher suite.
#[derive(Debug)]
struct Tls13Aes256GcmSha384;

impl SupportedDtls13CipherSuite for Tls13Aes256GcmSha384 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::AES_256_GCM_SHA384
    }
    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }
    fn key_len(&self) -> usize {
        32
    }
    fn iv_len(&self) -> usize {
        12
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        Ok(Box::new(AesGcm::new(key)?))
    }
    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        aes_ecb_encrypt(&AES_256, sn_key, sample)
    }
}

/// TLS_CHACHA20_POLY1305_SHA256 cipher suite.
#[derive(Debug)]
struct Tls13ChaCha20Poly1305Sha256;

impl SupportedDtls13CipherSuite for Tls13ChaCha20Poly1305Sha256 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::CHACHA20_POLY1305_SHA256
    }
    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
    fn key_len(&self) -> usize {
        32
    }
    fn iv_len(&self) -> usize {
        12
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        Ok(Box::new(ChaCha20Poly1305Cipher::new(key)?))
    }
    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        let hp_key = HeaderProtectionKey::new(&aws_quic::CHACHA20, sn_key).unwrap();
        let mask = hp_key.new_mask(sample).unwrap();
        let mut out = [0u8; 16];
        out[..5].copy_from_slice(&mask);
        out
    }
}

static TLS13_AES_128_GCM_SHA256: Tls13Aes128GcmSha256 = Tls13Aes128GcmSha256;
static TLS13_AES_256_GCM_SHA384: Tls13Aes256GcmSha384 = Tls13Aes256GcmSha384;
static TLS13_CHACHA20_POLY1305_SHA256: Tls13ChaCha20Poly1305Sha256 = Tls13ChaCha20Poly1305Sha256;

/// All supported DTLS 1.3 cipher suites.
pub(super) static ALL_DTLS13_CIPHER_SUITES: &[&dyn SupportedDtls13CipherSuite] = &[
    &TLS13_AES_128_GCM_SHA256,
    &TLS13_AES_256_GCM_SHA384,
    &TLS13_CHACHA20_POLY1305_SHA256,
];

/// AES-ECB single block encryption for record number protection.
fn aes_ecb_encrypt(
    algorithm: &'static aws_cipher::Algorithm,
    key: &[u8],
    input: &[u8; 16],
) -> [u8; 16] {
    let unbound = UnboundCipherKey::new(algorithm, key).unwrap();
    let ecb_key = EncryptingKey::ecb(unbound).unwrap();
    let mut block = *input;
    ecb_key.encrypt(&mut block).unwrap();
    block
}