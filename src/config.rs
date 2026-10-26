use std::fmt;
use std::time::Duration;

use crate::crypto::{CryptoProvider, SupportedDtls13CipherSuite, SupportedKxGroup};
use crate::dtls13::message::{MAX_CID_LEN, MAX_RECORD_SIZE_LIMIT, MIN_RECORD_SIZE_LIMIT};
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
    alpn_protocols: Vec<Vec<u8>>,
    server_name: Option<String>,
    record_size_limit: u16,
    connection_id: Option<Vec<u8>>,
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
            alpn_protocols: Vec::new(),
            server_name: None,
            record_size_limit: MAX_RECORD_SIZE_LIMIT,
            connection_id: None,
        }
    }

    /// Max transmission unit: the largest size UDP packets we will produce.
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
    #[inline(always)]
    pub fn require_client_certificate(&self) -> bool {
        self.require_client_certificate
    }

    /// Whether the server sends a cookie exchange before the handshake.
    #[inline(always)]
    pub fn use_server_cookie(&self) -> bool {
        self.use_server_cookie
    }

    /// Time of first retry.
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
    #[inline(always)]
    pub fn crypto_provider(&self) -> &CryptoProvider {
        &self.crypto_provider
    }

    /// Optional seed for deterministic random number generation.
    #[inline(always)]
    pub fn rng_seed(&self) -> Option<u64> {
        self.rng_seed
    }

    /// Maximum number of AEAD encryptions before triggering a KeyUpdate.
    #[inline(always)]
    pub fn aead_encryption_limit(&self) -> u64 {
        self.aead_encryption_limit
    }

    /// ALPN protocols offered to the peer, in preference order.
    ///
    /// Empty means ALPN is disabled on this endpoint.
    #[inline(always)]
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn_protocols
    }

    /// SNI host name sent by the client (or `None` for servers).
    #[inline(always)]
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// RFC 8449 Record Size Limit (default 16385).
    #[inline(always)]
    pub fn record_size_limit(&self) -> u16 {
        self.record_size_limit
    }

    /// RFC 9146 Connection ID, or `None` if not used.
    #[inline(always)]
    pub fn connection_id(&self) -> Option<&[u8]> {
        self.connection_id.as_deref()
    }

    /// Allowed DTLS 1.3 cipher suites, filtered by the config's allow-list.
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
    alpn_protocols: Vec<Vec<u8>>,
    server_name: Option<String>,
    record_size_limit: u16,
    connection_id: Option<Vec<u8>>,
}

impl ConfigBuilder {
    /// Set the max transmission unit (MTU). Defaults to 1150.
    pub fn mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set the max amount of incoming packets to buffer. Defaults to 30.
    pub fn max_queue_rx(mut self, max_queue_rx: usize) -> Self {
        self.max_queue_rx = max_queue_rx;
        self
    }

    /// Set the max amount of outgoing packets to buffer. Defaults to 10.
    pub fn max_queue_tx(mut self, max_queue_tx: usize) -> Self {
        self.max_queue_tx = max_queue_tx;
        self
    }

    /// Set whether to require a client certificate (for servers). Defaults to `true`.
    pub fn require_client_certificate(mut self, require: bool) -> Self {
        self.require_client_certificate = require;
        self
    }

    /// Set whether the server sends a cookie exchange before the handshake.
    /// Defaults to `true`.
    pub fn use_server_cookie(mut self, use_cookie: bool) -> Self {
        self.use_server_cookie = use_cookie;
        self
    }

    /// Set the time of first retry. Defaults to 1 second.
    pub fn flight_start_rto(mut self, rto: Duration) -> Self {
        self.flight_start_rto = rto;
        self
    }

    /// Set the max number of retries per flight. Defaults to 4.
    pub fn flight_retries(mut self, retries: usize) -> Self {
        self.flight_retries = retries;
        self
    }

    /// Set the timeout for the entire handshake. Defaults to 40 seconds.
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Set a custom crypto provider.
    pub fn with_crypto_provider(mut self, provider: CryptoProvider) -> Self {
        self.crypto_provider = Some(provider);
        self
    }

    /// Set a seed for deterministic random number generation.
    pub fn dangerously_set_rng_seed(mut self, seed: u64) -> Self {
        self.rng_seed = Some(seed);
        self
    }

    /// Set the maximum number of AEAD encryptions before triggering a KeyUpdate.
    /// Defaults to 2^23.
    pub fn aead_encryption_limit(mut self, limit: u64) -> Self {
        self.aead_encryption_limit = limit;
        self
    }

    /// Restrict which DTLS 1.3 cipher suites are offered and accepted.
    pub fn dtls13_cipher_suites(mut self, suites: &[Dtls13CipherSuite]) -> Self {
        self.dtls13_cipher_suites = Some(suites.to_vec());
        self
    }

    /// Restrict which key exchange groups are offered and accepted.
    pub fn kx_groups(mut self, groups: &[NamedGroup]) -> Self {
        self.kx_groups = Some(groups.to_vec());
        self
    }

    /// Offer ALPN protocols (RFC 7301), in preference order.
    ///
    /// Empty slice disables ALPN. On the client, all entries are sent in
    /// `ClientHello`; on the server, the first match wins.
    pub fn alpn_protocols(mut self, protocols: &[&[u8]]) -> Self {
        self.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
        self
    }

    /// Server Name Indication (RFC 6066). Sent by the client only.
    pub fn server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// Record Size Limit (RFC 8449). Defaults to `MAX_RECORD_SIZE_LIMIT` (16385).
    pub fn record_size_limit(mut self, limit: u16) -> Self {
        self.record_size_limit = limit;
        self
    }

    /// Connection ID (RFC 9146). Both sides must configure one for CID
    /// to actually be used in the wire format.
    pub fn connection_id(mut self, cid: &[u8]) -> Self {
        self.connection_id = Some(cid.to_vec());
        self
    }

    /// Build the configuration.
    ///
    /// Validates timing settings and the crypto provider before returning
    /// the configuration. Returns `Error::ConfigError` for invalid settings.
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

        crypto_provider.validate()?;

        if self.mtu < 64 {
            return Err(Error::ConfigError(ConfigError::MtuTooSmall {
                mtu: self.mtu as u16,
                minimum: 64,
            }));
        }

        if self.aead_encryption_limit == 0 {
            return Err(Error::ConfigError(ConfigError::AeadEncryptionLimitTooSmall));
        }

        if self.record_size_limit < MIN_RECORD_SIZE_LIMIT
            || self.record_size_limit > MAX_RECORD_SIZE_LIMIT
        {
            return Err(Error::ConfigError(ConfigError::InvalidRecordSizeLimit));
        }

        if let Some(cid) = &self.connection_id {
            if cid.len() > MAX_CID_LEN {
                return Err(Error::ConfigError(ConfigError::ConnectionIdTooLong {
                    len: cid.len(),
                    max: MAX_CID_LEN,
                }));
            }
        }

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
            alpn_protocols: self.alpn_protocols,
            server_name: self.server_name,
            record_size_limit: self.record_size_limit,
            connection_id: self.connection_id,
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
            .field("alpn_protocols", &self.alpn_protocols)
            .field("server_name", &self.server_name)
            .field("record_size_limit", &self.record_size_limit)
            .field(
                "connection_id_len",
                &self.connection_id.as_ref().map_or(0, |v| v.len()),
            )
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
            .field("alpn_protocols", &self.alpn_protocols)
            .field("server_name", &self.server_name)
            .field("record_size_limit", &self.record_size_limit)
            .field(
                "connection_id_len",
                &self.connection_id.as_ref().map_or(0, |v| v.len()),
            )
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
            let error = Config::builder()
                .flight_start_rto(duration)
                .build()
                .expect_err("unsupported initial RTO");
            assert_eq!(
                error,
                Error::ConfigError(ConfigError::InvalidFlightStartRto)
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
        assert!(matches!(
            Config::builder().mtu(0).build(),
            Err(Error::ConfigError(ConfigError::MtuTooSmall { .. }))
        ));
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
        assert!(matches!(
            Config::builder().aead_encryption_limit(0).build(),
            Err(Error::ConfigError(ConfigError::AeadEncryptionLimitTooSmall))
        ));
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
        assert!(matches!(
            Config::builder().dtls13_cipher_suites(&[]).build(),
            Err(Error::ConfigError(
                ConfigError::NoCipherSuitesAfterFiltering
            ))
        ));
    }

    #[test]
    fn empty_kx_groups_filter_rejected() {
        assert!(matches!(
            Config::builder().kx_groups(&[]).build(),
            Err(Error::ConfigError(
                ConfigError::NoDtls13KeyExchangeGroupsAfterFiltering
            ))
        ));
    }

    #[test]
    fn alpn_default_empty() {
        assert!(Config::default().alpn_protocols().is_empty());
    }

    #[test]
    fn alpn_roundtrip() {
        let config = Config::builder()
            .alpn_protocols(&[b"h2", b"http/1.1"])
            .build()
            .unwrap();
        assert_eq!(
            config.alpn_protocols(),
            &[b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn server_name_default_none() {
        assert!(Config::default().server_name().is_none());
    }

    #[test]
    fn server_name_roundtrip() {
        let config = Config::builder()
            .server_name("example.com")
            .build()
            .unwrap();
        assert_eq!(config.server_name(), Some("example.com"));
    }

    #[test]
    fn record_size_limit_default() {
        assert_eq!(Config::default().record_size_limit(), MAX_RECORD_SIZE_LIMIT);
    }

    #[test]
    fn record_size_limit_invalid_low() {
        assert!(matches!(
            Config::builder().record_size_limit(0).build(),
            Err(Error::ConfigError(ConfigError::InvalidRecordSizeLimit))
        ));
        assert!(matches!(
            Config::builder().record_size_limit(63).build(),
            Err(Error::ConfigError(ConfigError::InvalidRecordSizeLimit))
        ));
    }

    #[test]
    fn record_size_limit_invalid_high() {
        assert!(matches!(
            Config::builder()
                .record_size_limit(MAX_RECORD_SIZE_LIMIT + 1)
                .build(),
            Err(Error::ConfigError(ConfigError::InvalidRecordSizeLimit))
        ));
    }

    #[test]
    fn record_size_limit_valid_range() {
        Config::builder()
            .record_size_limit(MIN_RECORD_SIZE_LIMIT)
            .build()
            .expect("min valid");
        Config::builder()
            .record_size_limit(MAX_RECORD_SIZE_LIMIT)
            .build()
            .expect("max valid");
    }

    #[test]
    fn connection_id_default_none() {
        assert!(Config::default().connection_id().is_none());
    }

    #[test]
    fn connection_id_roundtrip() {
        let cid = [0xDE, 0xAD, 0xBE, 0xEF];
        let config = Config::builder().connection_id(&cid).build().unwrap();
        assert_eq!(config.connection_id(), Some(&cid[..]));
    }

    #[test]
    fn connection_id_too_long_rejected() {
        let cid = vec![0u8; MAX_CID_LEN + 1];
        assert!(matches!(
            Config::builder().connection_id(&cid).build(),
            Err(Error::ConfigError(ConfigError::ConnectionIdTooLong { .. }))
        ));
    }

    #[test]
    fn connection_id_max_len_accepted() {
        let cid = vec![0u8; MAX_CID_LEN];
        Config::builder()
            .connection_id(&cid)
            .build()
            .expect("max CID length should be accepted");
    }
}
