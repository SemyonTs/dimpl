//! Cryptographic primitives and helpers used by the DTLS engine.

pub use provider::{KeyProvider, SecureRandom, SignatureVerifier, SigningKey};
use std::ops::Deref;

// Internal module imports
mod keying;

// Provider traits and implementations
#[cfg(feature = "aws-lc-rs")]
pub mod aws_lc_rs;

#[cfg(feature = "rust-crypto")]
pub mod rust_crypto;

mod dtls_aead;
pub mod prf_hkdf;
mod provider;
mod validation;

pub use keying::{KeyingMaterial, SrtpProfile};

// Re-export AEAD types needed for Cipher trait implementations (public API)
pub use dtls_aead::{Aad, Nonce};

// Re-export internal AEAD constants/types for crate-internal use

// Re-export buffer types for provider trait implementations
pub use crate::buffer::{Buf, TmpBuf};

// Re-export all provider traits and types (similar to rustls structure)
pub use provider::{
    ActiveKeyExchange, Cipher, CryptoProvider, CryptoSafe, HashContext, HashProvider, HmacProvider,
    SupportedDtls13CipherSuite, SupportedKxGroup,
};
#[cfg(feature = "_crypto-common")]
pub use provider::{OID_P256, OID_P384, cert_named_group};

// Re-export shared types for provider trait implementations
pub use crate::types::{
    Dtls13CipherSuite, HashAlgorithm, NamedGroup, SignatureAlgorithm, SignatureScheme,
};

impl Deref for Aad {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

impl Deref for Nonce {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
