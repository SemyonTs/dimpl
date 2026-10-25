use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::crypto::{CryptoProvider, SupportedDtls13CipherSuite, SupportedKxGroup};
use crate::types::{Dtls13CipherSuite, NamedGroup};
use crate::{ConfigError, Error};

const MAX_TIMING_DURATION: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

#[cfg(feature = "aws-lc-rs")]
use crate::crypto::aws_lc_rs;

#[cfg(feature = "rust-crypto")]
use crate::crypto::rust_crypto;

/// DTLS 1.3 configuration shared by all connections.
///
/// Build with [`Config::builder()`] or use [`Config::default()`].
#[derive(Clone)]
pub struct Config {
    mtu: usize,
    max_queue_rx: usize,
    max_queue_tx: usize,
    require_client_certificate: bool,
    use_server_cookie: bool,
    flight_start_rto: Duration,
    flight_retries: usize,
    handshake_timeout: Duration,
    crypto_provider: CryptoProvider,
    rng_seed: Option<u64>,
    aead_encryption_limit: u64,
    dtls13_cipher_suites: Option<Vec<Dtls13CipherSuite>>,
    kx_groups: Option<Vec<NamedGroup>>,
}

impl Config {
    /// Create a new configuration builder.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder {
            mtu: 1150,
            max_queue_rx: 30,
            max_queue_tx: 10,
            require_client_certificate: true,
            use_server_cookie: true,
            flight_start_rto: Duration::from_secs(1),
            flight_retries: 4,
            handshake_timeout: Duration::from_secs(40),
            crypto_provider: None,
            rng_seed: None,
            aead_encryption_limit: 1 << 23,
            dtls13_cipher_suites: None,
            kx_groups: None,
        }
    }

    /// Max transmission unit.
    ///
    /// The largest size UDP packets we will produce.
    #[inline(always)]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Max amount of incoming packets to buffer before rejecting more input.
    #[inline(always)]
    pub fn max_queue_rx(&self) -> usize {
        self.max_queue_rx
    }

    /// Max amount of outgoing packets to buffer.
    #[inline(always)]
    pub fn max_queue_tx(&self) -> usize {
        self.max_queue_tx
    }

    /// For a server, require a client certificate.
    ///
    /// This will cause the server to send a CertificateRequest message.
    /// Makes the server fail if the client does not send a certificate.
    #[inline(always)]
    pub fn require_client_certificate(&self) -> bool {
        self.require_client_certificate
    }

    /// Whether the server sends a cookie exchange before the handshake.
    ///
    /// When true (the default), the server requires a stateless cookie
    /// roundtrip for DoS protection via HelloRetryRequest with a cookie.
    ///
    /// When false, the server proceeds directly to ServerHello without
    /// a cookie exchange.
    #[inline(always)]
    pub fn use_server_cookie(&self) -> bool {
        self.use_server_cookie
    }

    /// Time of first retry.
    ///
    /// Every flight restarts with this value.
    /// Doubled for every retry with a ±25% jitter.
    #[inline(always)]
    pub fn flight_start_rto(&self) -> Duration {
        self.flight_start_rto
    }

    /// Max number of retries per flight.
    #[inline(always)]
    pub fn flight_retries(&self) -> usize {
        self.flight_retries
    }

    /// Timeout for the entire handshake, regardless of flights.
    #[inline(always)]
    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// Cryptographic provider.
    ///
    /// Provides all cryptographic operations (ciphers, key exchange, signing, etc.).
    #[inline(always)]
    pub fn crypto_provider(&self) -> &CryptoProvider {
        &self.crypto_provider
    }

    /// Optional seed for deterministic random number generation.
    ///
    /// When set, most non-cryptographic randomness (backoff jitter, TLS random bytes,
    /// AEAD nonces, cookie secrets) will be deterministic based on this seed.
    /// This is useful for testing and reproducibility.
    ///
    /// Note: Cryptographic operations (key exchange, signatures) always use
    /// secure system randomness regardless of this setting.
    #[inline(always)]
    pub fn rng_seed(&self) -> Option<u64> {
        self.rng_seed
    }

    /// Maximum number of AEAD encryptions before triggering a KeyUpdate.
    ///
    /// When the number of application-epoch ciphertext records reaches this
    /// limit, the endpoint automatically initiates a KeyUpdate to rotate keys.
    /// Defaults to 2^23 (8,388,608).
    #[inline(always)]
    pub fn aead_encryption_limit(&self) -> u64 {
        self.aead_encryption_limit
    }

    /// Allowed DTLS 1.3 cipher suites, filtered by the config's allow-list.
    ///
    /// Returns all provider DTLS 1.3 cipher suites when no filter is set.
    /// When a filter is set via the builder's `dtls13_cipher_suites` method,
    /// only suites in both the provider and the filter are returned.
    pub fn dtls13_cipher_suites(
        &self,
    ) -> impl Iterator<Item = &'static dyn SupportedDtls13CipherSuite> + '_ {
        let filter = self.dtls13_cipher_suites.as_ref();
        self.crypto_provider
            .dtls13_cipher_suites
            .iter()
            .copied()
            .filter(move |cs| match filter {
                Some(list) => list.contains(&cs.suite()),
                None => true,
            })
    }

    /// Allowed key exchange groups, filtered by the config's allow-list.
    ///
    /// Returns all provider-supported key exchange groups when no filter
    /// is set. When a filter is set via the builder's `kx_groups` method,
    /// only groups in both the provider and the filter are returned.
    pub fn kx_groups(&self) -> impl Iterator<Item = &'static dyn SupportedKxGroup> + '_ {
        let filter = self.kx_groups.as_ref();
        self.crypto_provider
            .supported_kx_groups()
            .filter(move |kx| match filter {
                Some(list) => list.contains(&kx.name()),
                None => true,
            })
    }
}

/// Builder for [`Config`]. See each setter for defaults.
pub struct ConfigBuilder {
    mtu: usize,
    max_queue_rx: usize,
    max_queue_tx: usize,
    require_client_certificate: bool,
    use_server_cookie: bool,
    flight_start_rto: Duration,
    flight_retries: usize,
    handshake_timeout: Duration,
    crypto_provider: Option<CryptoProvider>,
    rng_seed: Option<u64>,
    aead_encryption_limit: u64,
    dtls13_cipher_suites: Option<Vec<Dtls13CipherSuite>>,
    kx_groups: Option<Vec<NamedGroup>>,
}

impl ConfigBuilder {
    /// Set the max transmission unit (MTU).
    ///
    /// The largest size UDP packets we will produce.
    /// Defaults to 1150.
    pub fn mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set the max amount of incoming packets to buffer before rejecting more input.
    ///
    /// Defaults to 30.
    pub fn max_queue_rx(mut self, max_queue_rx: usize) -> Self {
        self.max_queue_rx = max_queue_rx;
        self
    }

    /// Set the max amount of outgoing packets to buffer.
    ///
    /// Defaults to 10.
    pub fn max_queue_tx(mut self, max_queue_tx: usize) -> Self {
        self.max_queue_tx = max_queue_tx;
        self
    }

    /// Set whether to require a client certificate (for servers).
    ///
    /// This will cause the server to send a CertificateRequest message.
    /// Makes the server fail if the client does not send a certificate.
    /// Defaults to true.
    pub fn require_client_certificate(mut self, require: bool) -> Self {
        self.require_client_certificate = require;
        self
    }

    /// Set whether the server sends a cookie exchange before the handshake.
    ///
    /// When true (the default), the server requires a stateless cookie
    /// roundtrip for DoS protection via HelloRetryRequest with a cookie.
    ///
    /// When false, the server proceeds directly to ServerHello without
    /// a cookie exchange.
    pub fn use_server_cookie(mut self, use_cookie: bool) -> Self {
        self.use_server_cookie = use_cookie;
        self
    }

    /// Set the time of first retry.
    ///
    /// Each flight starts its timer when its first packet is emitted. The base
    /// interval doubles after every retry, with independent +/-25% jitter on
    /// each interval. This is proportional even for sub-second values; the
    /// minimum jittered interval is 1 nanosecond. Backoff arithmetic saturates
    /// on overflow. Also governs DTLS 1.3 KeyUpdate flights.
    ///
    /// Defaults to 1 second. Must be nonzero and at most ten years (3650 days).
    pub fn flight_start_rto(mut self, rto: Duration) -> Self {
        self.flight_start_rto = rto;
        self
    }

    /// Set the max number of retries per flight.
    ///
    /// Excludes the initial transmission: zero disables retransmissions.
    /// Timer-driven and duplicate-triggered retransmissions share this budget.
    /// Once the handshake has completed locally, the final flight is still
    /// resent in answer to the peer's retransmitted final flight.
    /// Also governs DTLS 1.3 KeyUpdate flights.
    /// Defaults to 4.
    pub fn flight_retries(mut self, retries: usize) -> Self {
        self.flight_retries = retries;
        self
    }

    /// Set the timeout for the entire handshake, regardless of flights.
    ///
    /// Starts when the client emits its first ClientHello packet through
    /// [`crate::Output::Packet`], or when the server accepts its first
    /// structurally valid ClientHello fragment, even if its body is later rejected.
    /// A corrected ClientHello shares the same deadline for this peer.
    /// Construction and idle time consume no budget. Uses the logical time
    /// supplied to [`crate::Dtls::handle_timeout`].
    ///
    /// The absolute deadline survives cookie exchanges, later flights, and
    /// retransmissions. It is disabled after completion and does not apply to
    /// application traffic or DTLS 1.3 KeyUpdate.
    ///
    /// Retry exhaustion may fail earlier; increasing this timeout does not
    /// increase [`Self::flight_retries`]. With the defaults, an unanswered flight
    /// exhausts retries after roughly 31 seconds, before the 40-second deadline.
    ///
    /// Defaults to 40 seconds. Must be nonzero and at most ten years (3650 days).
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Set a custom crypto provider.
    ///
    /// If not set, the default aws-lc-rs provider will be used, if the feature
    /// flag `aws-lc-rs` is enabled.
    pub fn with_crypto_provider(mut self, provider: CryptoProvider) -> Self {
        self.crypto_provider = Some(provider);
        self
    }

    /// Set a seed for deterministic random number generation.
    ///
    /// When set, most non-cryptographic randomness (backoff jitter, TLS random bytes,
    /// AEAD nonces, cookie secrets) will be deterministic based on this seed.
    ///
    /// This is useful for testing and reproducibility.
    ///
    /// Note: Cryptographic operations (key exchange, signatures) always use
    /// secure system randomness regardless of this setting.
    pub fn dangerously_set_rng_seed(mut self, seed: u64) -> Self {
        self.rng_seed = Some(seed);
        self
    }

    /// Set the maximum number of AEAD encryptions before triggering a KeyUpdate.
    ///
    /// Defaults to 2^23 (8,388,608).
    pub fn aead_encryption_limit(mut self, limit: u64) -> Self {
        self.aead_encryption_limit = limit;
        self
    }

    /// Restrict which DTLS 1.3 cipher suites are offered and accepted.
    ///
    /// Only cipher suites present in both this list and the provider will
    /// be used. Passing an empty slice is rejected by `build()`, since DTLS 1.3
    /// is the only supported version.
    ///
    /// By default all provider DTLS 1.3 cipher suites are used.
    pub fn dtls13_cipher_suites(mut self, suites: &[Dtls13CipherSuite]) -> Self {
        self.dtls13_cipher_suites = Some(suites.to_vec());
        self
    }

    /// Restrict which key exchange groups are offered and accepted.
    ///
    /// Only groups present in both this list and the provider will be
    /// used. Order determines preference (first = most preferred).
    ///
    /// By default all provider-supported key exchange groups are used.
    pub fn kx_groups(mut self, groups: &[NamedGroup]) -> Self {
        self.kx_groups = Some(groups.to_vec());
        self
    }

    /// Build the configuration.
    ///
    /// Validates timing settings and the crypto provider before returning the
    /// configuration. Returns `Error::ConfigError` for invalid settings.
    ///
    /// The crypto provider is selected in the following priority order:
    /// 1. Explicit provider set via `with_crypto_provider()`
    /// 2. Default provider installed via `CryptoProvider::install_default()`
    /// 3. AWS-LC provider (if `aws-lc-rs` feature is enabled)
    /// 4. RustCrypto provider (if `rust-crypto` feature is enabled)
    /// 5. Panic if no provider is available
    pub fn build(self) -> Result<Config, Error> {
        if self.handshake_timeout.is_zero() || self.handshake_timeout > MAX_TIMING_DURATION {
            return Err(ConfigError::InvalidHandshakeTimeout.into());
        }
        if self.flight_start_rto.is_zero() || self.flight_start_rto > MAX_TIMING_DURATION {
            return Err(ConfigError::InvalidFlightStartRto.into());
        }

        let crypto_provider = self
            .crypto_provider
            .or_else(|| CryptoProvider::get_default().cloned());

        #[cfg(feature = "aws-lc-rs")]
        let crypto_provider = crypto_provider.or_else(|| Some(aws_lc_rs::default_provider()));

        #[cfg(feature = "rust-crypto")]
        let crypto_provider = crypto_provider.or_else(|| Some(rust_crypto::default_provider()));

        let crypto_provider = crypto_provider.expect(
            "No crypto provider available. Either set one explicitly via \
             with_crypto_provider(), install a default via CryptoProvider::install_default(), \
             or enable the 'aws-lc-rs' or 'rust-crypto' feature.",
        );

        // Always validate the crypto provider
        crypto_provider.validate()?;

        // Validate MTU: must be large enough for DTLS record + handshake headers
        if self.mtu < 64 {
            return Err(Error::ConfigError(ConfigError::MtuTooSmall {
                mtu: self.mtu as u16,
                minimum: 64,
            }));
        }

        // Validate aead_encryption_limit: must be at least 1
        if self.aead_encryption_limit == 0 {
            return Err(Error::ConfigError(ConfigError::AeadEncryptionLimitTooSmall));
        }

        // Validate cipher-suite filter: DTLS 1.3 is the only version, so at
        // least one suite must survive the allow-list.
        let dtls13_count = {
            let all = crypto_provider.dtls13_cipher_suites.iter();
            match &self.dtls13_cipher_suites {
                Some(list) => all.filter(|cs| list.contains(&cs.suite())).count(),
                None => all.count(),
            }
        };
        if dtls13_count == 0 {
            return Err(Error::ConfigError(
                ConfigError::NoCipherSuitesAfterFiltering,
            ));
        }

        // Validate kx_groups filter: DTLS 1.3 needs at least one group.
        let filtered_kx = |kx: &&'static dyn SupportedKxGroup| -> bool {
            match &self.kx_groups {
                Some(list) => list.contains(&kx.name()),
                None => true,
            }
        };
        let kx_count = crypto_provider
            .supported_kx_groups()
            .filter(|kx| filtered_kx(kx))
            .count();
        if kx_count == 0 {
            return Err(Error::ConfigError(
                ConfigError::NoDtls13KeyExchangeGroupsAfterFiltering,
            ));
        }

        Ok(Config {
            mtu: self.mtu,
            max_queue_rx: self.max_queue_rx,
            max_queue_tx: self.max_queue_tx,
            require_client_certificate: self.require_client_certificate,
            use_server_cookie: self.use_server_cookie,
            flight_start_rto: self.flight_start_rto,
            flight_retries: self.flight_retries,
            handshake_timeout: self.handshake_timeout,
            crypto_provider,
            rng_seed: self.rng_seed,
            aead_encryption_limit: self.aead_encryption_limit,
            dtls13_cipher_suites: self.dtls13_cipher_suites,
            kx_groups: self.kx_groups,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::builder()
            .build()
            .expect("Default config should always validate")
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("mtu", &self.mtu)
            .field("max_queue_rx", &self.max_queue_rx)
            .field("max_queue_tx", &self.max_queue_tx)
            .field(
                "require_client_certificate",
                &self.require_client_certificate,
            )
            .field("use_server_cookie", &self.use_server_cookie)
            .field("flight_start_rto", &self.flight_start_rto)
            .field("flight_retries", &self.flight_retries)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("crypto_provider", &self.crypto_provider)
            .field("rng_seed", &self.rng_seed)
            .field("aead_encryption_limit", &self.aead_encryption_limit)
            .field("dtls13_cipher_suites", &self.dtls13_cipher_suites)
            .field("kx_groups", &self.kx_groups)
            .finish()
    }
}

impl fmt::Debug for ConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigBuilder")
            .field("mtu", &self.mtu)
            .field("max_queue_rx", &self.max_queue_rx)
            .field("max_queue_tx", &self.max_queue_tx)
            .field(
                "require_client_certificate",
                &self.require_client_certificate,
            )
            .field("use_server_cookie", &self.use_server_cookie)
            .field("flight_start_rto", &self.flight_start_rto)
            .field("flight_retries", &self.flight_retries)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("crypto_provider", &self.crypto_provider)
            .field("rng_seed", &self.rng_seed)
            .field("aead_encryption_limit", &self.aead_encryption_limit)
            .field("dtls13_cipher_suites", &self.dtls13_cipher_suites)
            .field("kx_groups", &self.kx_groups)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_defaults() {
        let config = Config::default();
        assert_eq!(config.handshake_timeout(), Duration::from_secs(40));
        assert_eq!(config.flight_start_rto(), Duration::from_secs(1));
        assert_eq!(config.flight_retries(), 4);
    }

    #[test]
    fn timing_duration_bounds() {
        for duration in [
            Duration::ZERO,
            MAX_TIMING_DURATION + Duration::from_nanos(1),
            Duration::MAX,
        ] {
            let error = Config::builder()
                .handshake_timeout(duration)
                .build()
                .expect_err("unsupported handshake timeout");
            assert_eq!(
                error,
                Error::ConfigError(ConfigError::InvalidHandshakeTimeout)
            );
            assert_eq!(
                error.to_string(),
                "config error: handshake_timeout must be nonzero and at most 3650 days"
            );
            let error = Config::builder()
                .flight_start_rto(duration)
                .build()
                .expect_err("unsupported initial RTO");
            assert_eq!(
                error,
                Error::ConfigError(ConfigError::InvalidFlightStartRto)
            );
            assert_eq!(
                error.to_string(),
                "config error: flight_start_rto must be nonzero and at most 3650 days"
            );
        }
        for duration in [Duration::from_nanos(1), MAX_TIMING_DURATION] {
            for retries in [0, usize::MAX] {
                let config = Config::builder()
                    .handshake_timeout(duration)
                    .flight_start_rto(duration)
                    .flight_retries(retries)
                    .build()
                    .expect("supported timing boundaries");
                assert_eq!(config.handshake_timeout(), duration);
                assert_eq!(config.flight_start_rto(), duration);
                assert_eq!(config.flight_retries(), retries);
            }
        }
    }

    #[test]
    fn rejects_zero_mtu() {
        match Config::builder().mtu(0).build() {
            Err(Error::ConfigError(ConfigError::MtuTooSmall { mtu, minimum })) => {
                assert_eq!(mtu, 0);
                assert_eq!(minimum, 64);
            }
            Err(other) => panic!("expected ConfigError, got: {other:?}"),
            Ok(_) => panic!("expected error for MTU=0"),
        }
    }

    #[test]
    fn rejects_small_mtu() {
        match Config::builder().mtu(32).build() {
            Err(Error::ConfigError(ConfigError::MtuTooSmall { mtu, minimum })) => {
                assert_eq!(mtu, 32);
                assert_eq!(minimum, 64);
            }
            Err(other) => panic!("expected ConfigError, got: {other:?}"),
            Ok(_) => panic!("expected error for MTU=32"),
        }
    }

    #[test]
    fn accepts_minimum_mtu() {
        Config::builder()
            .mtu(64)
            .build()
            .expect("MTU 64 should be accepted");
    }

    #[test]
    fn rejects_zero_aead_limit() {
        match Config::builder().aead_encryption_limit(0).build() {
            Err(Error::ConfigError(ConfigError::AeadEncryptionLimitTooSmall)) => {}
            Err(other) => panic!("expected ConfigError, got: {other:?}"),
            Ok(_) => panic!("expected error for aead_encryption_limit=0"),
        }
    }

    #[test]
    fn accepts_minimum_aead_limit() {
        Config::builder()
            .aead_encryption_limit(1)
            .build()
            .expect("aead_encryption_limit 1 should be accepted");
    }

    #[test]
    fn filter_dtls13_cipher_suite() {
        let config = Config::builder()
            .dtls13_cipher_suites(&[Dtls13CipherSuite::AES_256_GCM_SHA384])
            .build()
            .expect("should accept single DTLS 1.3 suite");
        let suites: Vec<_> = config.dtls13_cipher_suites().map(|cs| cs.suite()).collect();
        assert_eq!(suites, &[Dtls13CipherSuite::AES_256_GCM_SHA384]);
    }

    #[test]
    fn filter_kx_groups() {
        let config = Config::builder()
            .kx_groups(&[NamedGroup::Secp256r1])
            .build()
            .expect("should accept single kx group");
        let groups: Vec<_> = config.kx_groups().map(|g| g.name()).collect();
        assert_eq!(groups, &[NamedGroup::Secp256r1]);
    }

    #[test]
    fn empty_dtls13_filter_rejected() {
        match Config::builder().dtls13_cipher_suites(&[]).build() {
            Err(Error::ConfigError(ConfigError::NoCipherSuitesAfterFiltering)) => {}
            Err(other) => panic!("expected ConfigError, got: {other:?}"),
            Ok(_) => panic!("expected error when DTLS 1.3 filter is empty"),
        }
    }

    #[test]
    fn empty_kx_groups_filter_rejected() {
        match Config::builder().kx_groups(&[]).build() {
            Err(Error::ConfigError(ConfigError::NoDtls13KeyExchangeGroupsAfterFiltering)) => {}
            Err(other) => panic!("expected ConfigError, got: {other:?}"),
            Ok(_) => panic!("expected error for empty kx groups"),
        }
    }

    #[test]
    fn x25519_only_accepted_for_dtls13_only() {
        let config = Config::builder()
            .kx_groups(&[NamedGroup::X25519])
            .build()
            .expect("X25519-only should be accepted for DTLS 1.3-only config");
        let groups: Vec<_> = config.kx_groups().map(|g| g.name()).collect();
        assert_eq!(groups, &[NamedGroup::X25519]);
    }

    #[test]
    fn kx_groups_match_provider_when_unfiltered() {
        let config = Config::default();
        let from_config: Vec<_> = config.kx_groups().map(|g| g.name()).collect();
        let from_provider: Vec<_> = config
            .crypto_provider()
            .supported_kx_groups()
            .map(|g| g.name())
            .collect();
        assert_eq!(from_config, from_provider);
    }

    #[test]
    fn no_filter_returns_all() {
        let config = Config::default();
        assert!(config.dtls13_cipher_suites().count() >= 2);
        assert!(config.kx_groups().count() >= 2);
    }

    #[test]
    fn filter_with_explicit_provider() {
        #[cfg(feature = "aws-lc-rs")]
        {
            let config = Config::builder()
                .with_crypto_provider(aws_lc_rs::default_provider())
                .dtls13_cipher_suites(&[Dtls13CipherSuite::AES_128_GCM_SHA256])
                .kx_groups(&[NamedGroup::X25519, NamedGroup::Secp256r1])
                .build()
                .expect("should accept filtered config with explicit provider");
            let suites13: Vec<_> = config.dtls13_cipher_suites().map(|cs| cs.suite()).collect();
            assert_eq!(suites13, &[Dtls13CipherSuite::AES_128_GCM_SHA256]);
            let groups: Vec<_> = config.kx_groups().map(|g| g.name()).collect();
            assert_eq!(groups, &[NamedGroup::X25519, NamedGroup::Secp256r1]);
        }
    }
}
