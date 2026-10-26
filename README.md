# dimpl13
[![dimpl13](https://img.shields.io/crates/v/dimpl13?label=dimpl13&logo=rust)](https://crates.io/crates/dimpl13)
[![Downloads](https://img.shields.io/crates/d/dimpl13?label=downloads)](https://crates.io/crates/dimpl13)
[![License](https://img.shields.io/crates/l/dimpl13?label=license)](https://crates.io/crates/dimpl13)
[![docs.rs](https://img.shields.io/docsrs/dimpl13?label=docs.rs)](https://docs.rs/dimpl13)
[![MSRV](https://img.shields.io/badge/MSRV-1.88.0-blue)](https://blog.rust-lang.org/)

**dimpl13** is a separate fork of [dimpl](https://github.com/algesten/dimpl) aimed at
building a sufficiently performant and convenient middleware for **DTLS 1.3**
over UDP/RTC. It is a Sans-IO state machine that you embed into your
event loop: you feed it incoming datagrams, poll for outgoing records and
timers, and handle certificate validation and SRTP key export
yourself.

The crate follows the upstream dimpl development path and mirrors its design,
module structure, and most of the public API. Differences:

- **DTLS 1.3 only.** There is no support for DTLS 1.0 or DTLS 1.2 in this fork.
  No code, no API, no documentation about 1.2 remains here.
- **Focus on performance.** A number of abstractions unnecessary for 1.3 have been removed
  (PSK, PRF-TLS-1.2, auto-sense), allocations on the hot path have been reduced
  (`ParsedRecord` no longer carries an inline buffer of handshake fragments for every
  app-data packet), and transient paths for queue-full errors have been added.
- **Minor interface changes.** Some signatures differ from
  upstream where justified by the goal of "convenient middleware" —
  for example, `Dtls::send_application_data` returns `Ok(0)` when the
  transmit queue is full, so the caller can retry without data loss.

If you need DTLS 1.2 or auto-sense (version detection from the first
ClientHello) — use the original [dimpl](https://github.com/algesten/dimpl).

## Goals
- **DTLS 1.3**: implements the handshake and record layer to the extent necessary
  for WebRTC.
- **Safety**: `forbid(unsafe_code)` throughout the crate.
- **Minimal Rust-only deps**: only small, well-maintained
  Rust crates for cryptography.
- **Low overhead**: tight control over allocations and buffers;
  Sans-IO integration.
- **Predictable retries**: queue overflow on the hot path does not
  kill the connection — the application receives a "retry later" signal.

### Non-goals
- **DTLS 1.0 / DTLS 1.2** (use [dimpl](https://github.com/algesten/dimpl) for DTLS 1.2)
- **Async**: the crate is Sans-IO and is not tied to a specific event loop.
- **no_std** (probably not in principle)
- **RSA**
- **DHE**
- **PSK** — in DTLS 1.3 the PSK path was never implemented in upstream dimpl;
  the fork preserves this state.
- **Version auto-sense** — makes no sense when 1.3 is the only version.

## Cryptography surface
- **Cipher suites (TLS 1.3 over DTLS)**
  - `TLS_AES_128_GCM_SHA256`
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_CHACHA20_POLY1305_SHA256`
- **AEAD**: AES-GCM 128/256, ChaCha20-Poly1305 (no CBC/EtM).
- **Key exchange**: ECDHE (P-256 / P-384), X25519.
- **Signatures**: ECDSA P-256/SHA-256, ECDSA P-384/SHA-384.
- **DTLS-SRTP**: exports keying material for
  `SRTP_AEAD_AES_256_GCM`, `SRTP_AEAD_AES_128_GCM` and
  `SRTP_AES128_CM_SHA1_80` ([RFC 5764], [RFC 7714]).

### Certificate model
During the handshake the engine emits [`Output::PeerCert`][peer_cert] with the peer's
leaf certificate (DER). The crate uses the certificate to verify the signature of
DTLS handshake messages but does not perform PKI validation.
The application validates the certificate according to its own policy (fingerprint,
chain building, name/EKU checks, pinning, etc.).

### Sans-IO integration model
Using the engine takes three calls:
- [`Dtls::handle_packet`][handle_packet] — feed a complete received
  UDP datagram.
- [`Dtls::poll_output`][poll_output] — pull outgoing
  DTLS records, timers, events.
- [`Dtls::handle_timeout`][handle_timeout] — advance
  retransmissions / time-based progress.

`Output` is an enum with borrowed references into the buffer you gave
to `poll_output`:
- `Packet(&[u8])` — send to the UDP socket.
- `BufferTooSmall { needed }` — enlarge the buffer and retry.
- `Timeout(Instant)` — schedule a timer, call
  `handle_timeout` at this (or a later) moment.
- `Connected` — handshake completed.
- `PeerCert(&[u8])` — peer's leaf certificate (DER) for validation.
- `KeyingMaterial(KeyingMaterial, SrtpProfile)` — DTLS-SRTP export.
- `ApplicationData(&[u8])` — plaintext from the peer.
- `CloseNotify` — the peer sent `close_notify` (graceful shutdown).

## Error handling

Every `Error` returned by the public API
([`handle_packet`][handle_packet], [`handle_timeout`][handle_timeout],
`send_application_data`, `close`) is **fatal** for the connection: the engine
has no recoverable states, and the correct reaction is to drop
`Dtls` and, if the connection is still needed, start a new handshake.

Transient conditions inherent to an unreliable transport — corrupted
datagrams, retransmissions, out-of-window records, parser noise, **receive
queue overflow** — are handled internally and do not surface as `Error`.
Such packets are silently dropped (`debug!` log), and the connection
stays alive. An `Error` never needs to be interpreted as
"retry" — it always means "give up and tear down the connection".

**The exception is transmit queue overflow on the application data hot path.**
[`Dtls::send_application_data`][send_app] returns
`Ok(0)` if the queue is full; the data is **not** accepted and must be
resent after [`poll_output`][poll_output]. This is not a connection error,
it is backpressure. See also `Config::builder().max_queue_tx(...)`.

## Example (Sans-IO loop)

```rust,no_run
use std::sync::Arc;
use std::time::Instant;

use dimpl13::{certificate, Config, Dtls, Output};

enum Event { Udp(Vec<u8>, Instant), Timer(Instant) }
fn wait_next_event(_next_wake: Option<Instant>) -> Event {
    Event::Udp(Vec::new(), Instant::now())
}
fn send_udp(_bytes: &[u8]) {}

fn example_event_loop(mut dtls: Dtls) -> Result<(), dimpl13::Error> {
    let mut next_wake: Option<Instant> = None;
    let mut received_packet: Option<Vec<u8>> = None;
    loop {
        // Drain engine output until we have to wait for I/O or a timer.
        let mut out_buf = vec![0u8; 2048];
        loop {
            match dtls.poll_output(&mut out_buf) {
                Output::Packet(p) => send_udp(p),
                Output::BufferTooSmall { needed } => {
                    out_buf.resize(needed, 0);
                }
                Output::Timeout(t) => { next_wake = Some(t); break; }
                Output::Connected => { /* ready to send app data */ }
                Output::PeerCert(_der) => { /* validate if desired */ }
                Output::KeyingMaterial(_km, _profile) => { /* feed SRTP */ }
                Output::ApplicationData(_data) => { /* deliver to app */ }
                Output::CloseNotify => return Ok(()),
                _ => {}
            }
        }

        if let Some(packet) = received_packet.take() {
            dtls.handle_packet(&packet)?;
            continue;
        }

        match wait_next_event(next_wake) {
            Event::Udp(pkt, now) => {
                dtls.handle_timeout(now)?;
                received_packet = Some(pkt);
            }
            Event::Timer(now) => dtls.handle_timeout(now)?,
        }
    }
}

fn mk_dtls_client() -> Dtls {
    let cert = certificate::generate_self_signed_certificate().unwrap();
    let cfg = Arc::new(Config::default());
    let mut dtls = Dtls::new_13(cfg, cert, Instant::now());
    dtls.set_active(true); // client role
    dtls
}

let dtls = mk_dtls_client();
let _ = example_event_loop(dtls);
```

## Backpressure and queue sizes

`Config::builder()` allows you to increase queue sizes if your
scenario (e.g. KCP-over-DTLS) generates bursts:

```rust,no_run
# use std::sync::Arc;
# use dimpl13::Config;
let config = Arc::new(
    Config::builder()
        .max_queue_rx(256)
        .max_queue_tx(256)
        .build()
        .unwrap(),
);
```

The default values (`max_queue_rx = 30`, `max_queue_tx = 10`)
are designed for WebRTC and keep per-connection memory minimal. With
`256 / 256` the upper bound is ~576 KB per connection (2 × 256 × 1150 B),
and that much is actually used only when the queues are fully loaded.

## Versioning and divergence from upstream

- The crate **deliberately** does not track `dimpl` one-to-one. Major
  public API changes relative to upstream are documented in
  [`CHANGELOG.md`].
- All changes not related to removing 1.2 or to optimizations are kept
  in the upstream style where possible, to ease merging of
  cryptographic bug fixes.
- If you want upstream-compatible behavior, use
  [dimpl][upstream].

#### MSRV
Rust 1.88.0

#### Status
- Session resumption is not implemented (WebRTC performs a full handshake on ICE restart).
- Renegotiation is not applicable in DTLS 1.3; use `KeyUpdate`.

[upstream]: https://github.com/algesten/dimpl
[send_app]: https://docs.rs/dimpl13/latest/dimpl13/struct.Dtls.html#method.send_application_data
[peer_cert]: https://docs.rs/dimpl13/latest/dimpl13/enum.Output.html#variant.PeerCert
[handle_packet]: https://docs.rs/dimpl13/latest/dimpl13/struct.Dtls.html#method.handle_packet
[poll_output]: https://docs.rs/dimpl13/latest/dimpl13/struct.Dtls.html#method.poll_output
[handle_timeout]: https://docs.rs/dimpl13/latest/dimpl13/struct.Dtls.html#method.handle_timeout
[output]: https://docs.rs/dimpl13/latest/dimpl13/enum.Output.html
[RFC 5764]: https://www.rfc-editor.org/rfc/rfc5764
[RFC 7714]: https://www.rfc-editor.org/rfc/rfc7714
[CHANGELOG.md]: ./CHANGELOG.md

License: MIT OR Apache-2.0

CHANGELOG.md is not filled in and is inherited from upstream.
Contributions are highly welcome, but please,
when adding functionality, put it behind cargo features.
I don't think too much about contribution requirements, so
you can contribute to dimpl13 freely, without being
limited by strict rules. Use Russian or English,
but exclusively English in code and commits, put significant
features behind cargo features, use cargo fmt. Documentation in Russian
is not a requirement. Use issues, PRs — as you prefer, I will
maintain dimpl13 since I use DTLS 1.3 in production.
AI usage is not prohibited and does not require labeling, although I
may still not review garbage contributions.
