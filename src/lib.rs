//! dimpl — DTLS 1.3 implementation (Sans‑IO, Sync)
//!
//! dimpl is a DTLS 1.3 implementation aimed at WebRTC. It is a Sans‑IO
//! state machine you embed into your own UDP/RTC event loop: you feed incoming
//! datagrams, poll for outgoing records or timers, and wire up certificate
//! verification and SRTP key export yourself.
//!
//! # Goals
//! - **DTLS 1.3**: Implements the DTLS 1.3 handshake and record layer used by WebRTC.
//! - **Safety**: `forbid(unsafe_code)` throughout the crate.
//! - **Minimal Rust‑only deps**: Uses small, well‑maintained Rust crypto crates.
//! - **Low overhead**: Tight control over allocations and buffers; Sans‑IO integration.
//!
//! ## Non‑goals
//! - **DTLS 1.0 / DTLS 1.2**
//! - **Async** (the crate is Sans‑IO and event‑loop agnostic)
//! - **no_std** (at least not without allocation)
//! - **RSA**
//! - **DHE**
//! - **PSK** (only implemented for DTLS 1.2 in this crate; not available in 1.3)
//!
//! # Cryptography surface
//! - **Cipher suites (TLS 1.3 over DTLS)**
//!   - `TLS_AES_128_GCM_SHA256`
//!   - `TLS_AES_256_GCM_SHA384`
//!   - `TLS_CHACHA20_POLY1305_SHA256`
//! - **AEAD**: AES‑GCM 128/256, ChaCha20‑Poly1305 (no CBC/EtM modes).
//! - **Key exchange**: ECDHE (P‑256/P‑384), X25519
//! - **Signatures**: ECDSA P‑256/SHA‑256, ECDSA P‑384/SHA‑384
//! - **DTLS‑SRTP**: Exports keying material for `SRTP_AEAD_AES_256_GCM`,
//!   `SRTP_AEAD_AES_128_GCM`, and `SRTP_AES128_CM_SHA1_80` ([RFC 5764], [RFC 7714]).
//!
//! ## Certificate model
//! During the handshake the engine emits
//! [`Output::PeerCert`][peer_cert] with the peer's leaf
//! certificate (DER). The crate uses that certificate to verify DTLS
//! handshake messages, but it does not perform any PKI validation. Your
//! application is responsible for validating the peer certificate according to
//! your policy (fingerprint, chain building, name/EKU checks, pinning, etc.).
//!
//! ## Sans‑IO integration model
//! Drive the engine with three calls:
//! - [`Dtls::handle_packet`][handle_packet] — feed an entire
//!   received UDP datagram.
//! - [`Dtls::poll_output`][poll_output] — drain pending output:
//!   DTLS records, timers, events.
//! - [`Dtls::handle_timeout`][handle_timeout] — trigger
//!   retransmissions/time‑based progress.
//!
//! The output is an [`Output`][output] enum with borrowed
//! references into your provided buffer:
//! - `Packet(&[u8])`: send on your UDP socket
//! - `BufferTooSmall { needed }`: resize the poll buffer and retry
//! - `Timeout(Instant)`: schedule a timer and call `handle_timeout` at/after it
//! - `Connected`: handshake complete
//! - `PeerCert(&[u8])`: peer leaf certificate (DER) — validate in your app
//! - `KeyingMaterial(KeyingMaterial, SrtpProfile)`: DTLS‑SRTP export
//! - `ApplicationData(&[u8])`: plaintext received from peer
//! - `CloseNotify`: peer sent a `close_notify` alert (graceful shutdown)
//!
//! # Error handling
//!
//! Every `Error` returned by the public API
//! ([`handle_packet`][handle_packet], [`handle_timeout`][handle_timeout],
//! `send_application_data`, and `close`) is **fatal**: the connection is no
//! longer usable and must be thrown away. The engine has no recoverable
//! error states, so the correct response is always to drop the `Dtls`
//! instance — and start a fresh handshake if you still need a connection.
//!
//! Transient, non‑fatal conditions inherent to running over an unreliable
//! transport — malformed datagrams, replayed or out‑of‑window records, and
//! other parser noise — are handled internally and never surface as an
//! `Error`. Such packets are discarded (logged at `debug!`) while the
//! connection keeps running. You therefore never need to distinguish
//! "retry" from "give up": a returned `Error` always means give up on this
//! connection.
//!
//! # Example (Sans‑IO loop)
//!
//! ```rust,no_run
//! # #[cfg(feature = "rcgen")]
//! # {
//! use std::sync::Arc;
//! use std::time::Instant;
//!
//! use dimpl::{certificate, Config, Dtls, Output};
//!
//! enum Event { Udp(Vec<u8>, Instant), Timer(Instant) }
//! fn wait_next_event(_next_wake: Option<Instant>) -> Event { Event::Udp(Vec::new(), Instant::now()) }
//! fn send_udp(_bytes: &[u8]) {}
//!
//! fn example_event_loop(mut dtls: Dtls) -> Result<(), dimpl::Error> {
//!     let mut next_wake: Option<Instant> = None;
//!     let mut received_packet: Option<Vec<u8>> = None;
//!     loop {
//!         let mut out_buf = vec![0u8; 2048];
//!         loop {
//!             match dtls.poll_output(&mut out_buf) {
//!                 Output::Packet(p) => send_udp(p),
//!                 Output::BufferTooSmall { needed } => { out_buf.resize(needed, 0); }
//!                 Output::Timeout(t) => { next_wake = Some(t); break; }
//!                 Output::Connected => {}
//!                 Output::PeerCert(_der) => {}
//!                 Output::KeyingMaterial(_km, _profile) => {}
//!                 Output::ApplicationData(_data) => {}
//!                 Output::CloseNotify => return Ok(()),
//!                 _ => {}
//!             }
//!         }
//!         if let Some(packet) = received_packet.take() {
//!             dtls.handle_packet(&packet)?;
//!             continue;
//!         }
//!         match wait_next_event(next_wake) {
//!             Event::Udp(pkt, now) => {
//!                 dtls.handle_timeout(now)?;
//!                 received_packet = Some(pkt);
//!             }
//!             Event::Timer(now) => dtls.handle_timeout(now)?,
//!         }
//!     }
//! }
//!
//! fn mk_dtls_client() -> Dtls {
//!     let cert = certificate::generate_self_signed_certificate().unwrap();
//!     let cfg = Arc::new(Config::default());
//!     let mut dtls = Dtls::new_13(cfg, cert, Instant::now());
//!     dtls.set_active(true);
//!     dtls
//! }
//!
//! let dtls = mk_dtls_client();
//! let _ = example_event_loop(dtls);
//! # }
//! ```
//!
//! ### MSRV
//! Rust 1.85.0
//!
//! ### Status
//! - Session resumption is not implemented (WebRTC does a full handshake on ICE restart).
//! - Renegotiation is not applicable to DTLS 1.3 (use KeyUpdate instead).
//!
//! [peer_cert]: https://docs.rs/dimpl/latest/dimpl/enum.Output.html#variant.PeerCert
//! [handle_packet]: https://docs.rs/dimpl/latest/dimpl/struct.Dtls.html#method.handle_packet
//! [poll_output]: https://docs.rs/dimpl/latest/dimpl/struct.Dtls.html#method.poll_output
//! [handle_timeout]: https://docs.rs/dimpl/latest/dimpl/struct.Dtls.html#method.handle_timeout
//! [output]: https://docs.rs/dimpl/latest/dimpl/enum.Output.html
//! [RFC 5764]: https://www.rfc-editor.org/rfc/rfc5764
//! [RFC 7714]: https://www.rfc-editor.org/rfc/rfc7714
//!
#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(unknown_lints)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

#[macro_use]
extern crate log;

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

// Shared types
mod types;
pub use types::{
    CompressionMethod, ContentType, Dtls13CipherSuite, HashAlgorithm, NamedGroup, ProtocolVersion,
    Sequence, SignatureAlgorithm, SignatureScheme,
};

// DTLS 1.3 engine
mod dtls13;

use dtls13::{Client, Server};

mod time_tricks;

pub(crate) mod buffer;
mod util;
mod window;

mod error;
pub(crate) use error::InternalError;
pub use error::{
    CertificateError, ConfigError, CryptoError, CryptoOperation, CryptoProviderValidationError,
    Error, InvalidStateError, SecurityError, TimeoutError, UnexpectedMessageError,
};

mod config;
pub use config::{Config, ConfigBuilder};

#[cfg(feature = "rcgen")]
pub mod certificate;

pub mod crypto;
pub use crypto::{KeyingMaterial, SrtpProfile};

mod rng;
mod timer;
pub(crate) use rng::SeededRng;

/// Certificate and private key pair.
#[derive(Clone)]
pub struct DtlsCertificate {
    /// Certificate in DER format.
    pub certificate: Vec<u8>,
    /// Private key in DER format.
    pub private_key: Vec<u8>,
}

impl fmt::Debug for DtlsCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DtlsCertificate")
            .field("certificate", &self.certificate.len())
            .field("private_key", &self.private_key.len())
            .finish()
    }
}

/// Sans-IO DTLS 1.3 endpoint (client or server).
///
/// New instances start in the **server role**. Call
/// [`set_active(true)`](Self::set_active) to switch to client before
/// the handshake begins.
///
/// Drive the state machine with [`handle_packet`](Self::handle_packet),
/// [`poll_output`](Self::poll_output), and
/// [`handle_timeout`](Self::handle_timeout).
pub struct Dtls {
    inner: Option<Inner>,
}

enum Inner {
    Client(Client),
    Server(Server),
}

impl Dtls {
    /// Create a new DTLS 1.3 instance in the server role.
    ///
    /// Call [`set_active(true)`](Self::set_active) to switch to client
    /// before the handshake begins.
    ///
    /// During the handshake, the peer's leaf certificate is surfaced via
    /// [`Output::PeerCert`]. It is up to the application to validate that
    /// certificate according to its security policy.
    pub fn new_13(config: Arc<Config>, certificate: DtlsCertificate, now: Instant) -> Self {
        let inner = Inner::Server(Server::new(config, certificate, now));
        Dtls { inner: Some(inner) }
    }

    /// Returns the negotiated DTLS protocol version (`DTLS1_3` once the
    /// instance exists; DTLS 1.3 is the only supported version).
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.inner.as_ref()?;
        Some(ProtocolVersion::DTLS1_3)
    }

    /// Return true while DTLS shutdown is in progress.
    ///
    /// This becomes true after local shutdown starts, or while a received
    /// `close_notify` still needs to be reported by
    /// [`poll_output`](Self::poll_output). Callers should continue polling
    /// until this returns false or [`is_closed`](Self::is_closed) returns true.
    pub fn is_closing(&self) -> bool {
        match self.inner.as_ref() {
            Some(Inner::Client(c)) => c.is_closing(),
            Some(Inner::Server(s)) => s.is_closing(),
            None => false,
        }
    }

    /// Return true once DTLS shutdown is terminal for the embedder.
    ///
    /// This only becomes true after no application data can be sent and no
    /// close-related packets or events remain to be drained through
    /// [`poll_output`](Self::poll_output).
    pub fn is_closed(&self) -> bool {
        match self.inner.as_ref() {
            Some(Inner::Client(c)) => c.is_closed(),
            Some(Inner::Server(s)) => s.is_closed(),
            None => false,
        }
    }

    /// Return true if the instance is operating in the client role.
    pub fn is_active(&self) -> bool {
        matches!(self.inner, Some(Inner::Client(_)))
    }

    /// Switch between server and client roles.
    pub fn set_active(&mut self, active: bool) {
        match (self.is_active(), active) {
            (true, false) => {
                let Inner::Client(c) = self.inner.take().unwrap() else {
                    unreachable!()
                };
                self.inner = Some(Inner::Server(c.into_server()));
            }
            (false, true) => {
                let Inner::Server(s) = self.inner.take().unwrap() else {
                    unreachable!()
                };
                self.inner = Some(Inner::Client(s.into_client()));
            }
            _ => {}
        }
    }

    /// Process an incoming DTLS datagram.
    ///
    /// Refresh the logical clock with [`Self::handle_timeout`] before receiving
    /// packets at a new instant, even if no advertised timer is due. A server's
    /// overall handshake deadline starts at that time when the first structurally
    /// valid ClientHello fragment is accepted. Later body validation failures do
    /// not reset this peer's deadline. Unrelated input does not start the deadline.
    /// Poll until [`Output::Timeout`] after each mutation.
    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client(c) => c.handle_packet(packet),
            Inner::Server(s) => s.handle_packet(packet),
        }
    }

    /// Poll for pending output from the DTLS engine.
    ///
    /// Emitting the first ClientHello fragment starts the client's handshake
    /// deadline; queuing output or returning [`Output::BufferTooSmall`] does not.
    /// Uses the logical time from [`Self::handle_timeout`]; refresh it first if
    /// time has advanced. Caller-side transport delays are outside dimpl.
    /// Continue polling until [`Output::Timeout`].
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Output<'a> {
        match self.inner.as_mut().unwrap() {
            Inner::Client(c) => c.poll_output(buf),
            Inner::Server(s) => s.poll_output(buf),
        }
    }

    /// Handle time-based events such as retransmission timers.
    ///
    /// Advances the logical clock for subsequent operations, even when no timer
    /// is due. Time alone does not start handshake or unsent-flight timers.
    /// Supply monotonically increasing instants and poll until [`Output::Timeout`]
    /// after each mutation. See [`ConfigBuilder::handshake_timeout`] for the
    /// overall deadline and retry policy.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client(c) => c.handle_timeout(now),
            Inner::Server(s) => s.handle_timeout(now),
        }
    }

    /// Send application data over the established DTLS session.
    ///
    /// Returns the number of bytes accepted for buffering or transmission, not
    /// delivery. Currently accepts the entire slice or none of it.
    ///
    /// Data sent before handshake completion is buffered internally and returns
    /// `Ok(data.len())`. An empty slice also returns `Ok(0)` on success; this
    /// does not indicate handshake readiness.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<usize, Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client(c) => c.send_application_data(data),
            Inner::Server(s) => s.send_application_data(data),
        }
        .map(|()| data.len())
    }

    /// Initiate graceful shutdown by sending a `close_notify` alert.
    ///
    /// **Connected**: queues a `close_notify` alert; the next
    /// [`poll_output`](Self::poll_output) cycle yields it as
    /// [`Output::Packet`].
    ///
    /// **Handshake in progress**: aborts immediately without sending an
    /// alert (no authenticated channel exists). Subsequent calls to
    /// [`send_application_data`](Self::send_application_data) will return
    /// an error.
    ///
    /// The alert is not retransmitted (per RFC 9147 §5.10).
    pub fn close(&mut self) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client(c) => c.close(),
            Inner::Server(s) => s.close(),
        }
    }
}

impl fmt::Debug for Dtls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (role, state) = match &self.inner {
            Some(Inner::Client(c)) => ("Client", c.state_name()),
            Some(Inner::Server(s)) => ("Server", s.state_name()),
            None => ("None", ""),
        };
        f.debug_struct("Dtls")
            .field("role", &role)
            .field("state", &state)
            .finish()
    }
}

/// Output events produced by the DTLS engine when polled.
#[non_exhaustive]
pub enum Output<'a> {
    /// A DTLS record to transmit on the wire.
    Packet(&'a [u8]),
    /// The provided output buffer is too small for the next pending output.
    BufferTooSmall {
        /// Minimum buffer length required to emit the pending output.
        needed: usize,
    },
    /// Schedule a timer and call [`Dtls::handle_timeout`] at this instant.
    Timeout(Instant),
    /// The handshake completed and the connection is established.
    Connected,
    /// The peer's leaf certificate in DER encoding.
    PeerCert(&'a [u8]),
    /// Extracted DTLS-SRTP keying material and selected SRTP profile.
    KeyingMaterial(KeyingMaterial, SrtpProfile),
    /// Received application data plaintext.
    ApplicationData(&'a [u8]),
    /// The peer sent a `close_notify` alert, indicating graceful connection closure.
    CloseNotify,
}

impl fmt::Debug for Output<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(v) => write!(f, "Packet({})", v.len()),
            Self::BufferTooSmall { needed } => write!(f, "BufferTooSmall({needed})"),
            Self::Timeout(v) => write!(f, "Timeout({:?})", v),
            Self::Connected => write!(f, "Connected"),
            Self::PeerCert(v) => write!(f, "PeerCert({})", v.len()),
            Self::KeyingMaterial(v, p) => write!(f, "KeyingMaterial({}, {:?})", v.len(), p),
            Self::ApplicationData(v) => write!(f, "ApplicationData({})", v.len()),
            Self::CloseNotify => write!(f, "CloseNotify"),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "rcgen")]
mod test {
    use std::panic::UnwindSafe;

    use crate::certificate::generate_self_signed_certificate;
    use crate::types::NamedGroup;

    use super::*;

    fn new_instance_13() -> Dtls {
        let cert = generate_self_signed_certificate().expect("Failed to generate cert");
        let config = Arc::new(Config::default());
        Dtls::new_13(config, cert, Instant::now())
    }

    #[test]
    fn test_dtls13_default() {
        let mut dtls = new_instance_13();
        assert!(!dtls.is_active());
        dtls.set_active(true);
        assert!(dtls.is_active());
        dtls.set_active(false);
        assert!(!dtls.is_active());
    }

    #[test]
    fn is_send() {
        fn is_send<T: Send>(_t: T) {}
        fn is_sync<T: Sync>(_t: T) {}
        is_send(new_instance_13());
        is_sync(new_instance_13());
    }

    #[test]
    fn is_unwind_safe() {
        fn is_unwind_safe<T: UnwindSafe>(_t: T) {}
        is_unwind_safe(new_instance_13());
    }

    #[test]
    fn test_protocol_version_13() {
        let dtls = new_instance_13();
        assert_eq!(dtls.protocol_version(), Some(ProtocolVersion::DTLS1_3));
    }

    #[test]
    #[should_panic(expected = "Server certificate cannot be empty")]
    fn new_13_panics_on_empty_certificate() {
        let cert = generate_self_signed_certificate().expect("Failed to generate cert");
        let config = Arc::new(Config::default());
        let empty = DtlsCertificate {
            certificate: vec![],
            private_key: cert.private_key,
        };
        let _ = Dtls::new_13(config, empty, Instant::now());
    }

    fn make_record(content_type: u8, body: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(13 + body.len());
        pkt.push(content_type);
        pkt.extend_from_slice(&[0xFE, 0xFD]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&(body.len() as u16).to_be_bytes());
        pkt.extend_from_slice(body);
        pkt
    }

    fn make_handshake(
        msg_type: u8,
        length: u32,
        frag_off: u32,
        frag_len: u32,
        body: &[u8],
    ) -> Vec<u8> {
        let mut hs = Vec::with_capacity(12 + body.len());
        hs.push(msg_type);
        hs.extend_from_slice(&length.to_be_bytes()[1..]);
        hs.extend_from_slice(&[0x00, 0x00]);
        hs.extend_from_slice(&frag_off.to_be_bytes()[1..]);
        hs.extend_from_slice(&frag_len.to_be_bytes()[1..]);
        hs.extend_from_slice(body);
        hs
    }

    fn dtls13_ch_body_with_extensions(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0xFE, 0xFD]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02]);
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        body
    }

    #[test]
    fn dtls13_server_accepts_distinct_supported_key_shares_before_cookie_hrr() {
        let supported_versions = [0x02, 0xFE, 0xFC];

        let mut supported_groups = Vec::new();
        supported_groups
            .extend_from_slice(&(NamedGroup::supported().len() as u16 * 2).to_be_bytes());
        for group in NamedGroup::supported() {
            supported_groups.extend_from_slice(&group.as_u16().to_be_bytes());
        }

        let mut key_share = Vec::new();
        key_share.extend_from_slice(&(NamedGroup::supported().len() as u16 * 5).to_be_bytes());
        for group in NamedGroup::supported() {
            key_share.extend_from_slice(&group.as_u16().to_be_bytes());
            key_share.extend_from_slice(&1u16.to_be_bytes());
            key_share.push(0x42);
        }

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x002Bu16.to_be_bytes());
        extensions.extend_from_slice(&(supported_versions.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&supported_versions);
        extensions.extend_from_slice(&0x000Au16.to_be_bytes());
        extensions.extend_from_slice(&(supported_groups.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&supported_groups);
        extensions.extend_from_slice(&0x0033u16.to_be_bytes());
        extensions.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&key_share);

        let body = dtls13_ch_body_with_extensions(&extensions);
        let len = body.len() as u32;
        let hs = make_handshake(0x01, len, 0, len, &body);
        let pkt = make_record(0x16, &hs);

        let mut dtls = new_instance_13();
        dtls.handle_packet(&pkt)
            .expect("all distinct supported key shares should fit server-side parsing");
    }

    #[test]
    fn dtls13_server_accepts_unknown_supported_versions_before_cookie_hrr() {
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x002Bu16.to_be_bytes());
        extensions.extend_from_slice(&(10u16).to_be_bytes());
        extensions.extend_from_slice(&[0x04, 0xFE, 0xFE, 0xFE, 0xFC, 0xFE, 0xFD, 0xFE, 0xFF, 0xFE]);

        let body = dtls13_ch_body_with_extensions(&extensions);
        let len = body.len() as u32;
        let hs = make_handshake(0x01, len, 0, len, &body);
        let pkt = make_record(0x16, &hs);

        let mut dtls = new_instance_13();
        dtls.handle_packet(&pkt)
            .expect("unknown supported_versions values should not overflow server-side parsing");
    }
}
