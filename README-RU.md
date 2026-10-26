# dimpl13
[![dimpl13](https://img.shields.io/crates/v/dimpl13?label=dimpl13&logo=rust)](https://crates.io/crates/dimpl13)
[![Downloads](https://img.shields.io/crates/d/dimpl13?label=downloads)](https://crates.io/crates/dimpl13)
[![License](https://img.shields.io/crates/l/dimpl13?label=license)](https://crates.io/crates/dimpl13)
[![docs.rs](https://img.shields.io/docsrs/dimpl13?label=docs.rs)](https://docs.rs/dimpl13)
[![MSRV](https://img.shields.io/badge/MSRV-1.88.0-blue)](https://blog.rust-lang.org/)

**dimpl13** — это отдельное ответвление [dimpl](https://github.com/algesten/dimpl), нацеленное на
создание достаточно производительного и удобного middleware для **DTLS 1.3**
поверх UDP/RTC. Это Sans‑IO state machine, которую вы встраиваете в свой
event loop: подаёте входящие датаграммы, опрашиваете исходящие записи и
таймеры, самостоятельно подключаете валидацию сертификатов и экспорт
SRTP‑ключей.

Крейт следует пути развития апстримного dimpl и повторяет его дизайн,
структуру модулей и большую часть публичного API. Отличия:

- **Только DTLS 1.3.** Поддержки DTLS 1.0 и DTLS 1.2 в этом форке нет.
  Ни кода, ни API, ни документации про 1.2 здесь не осталось.
- **Расширения DTLS 1.3.** Добавлены ALPN ([RFC 7301]), SNI ([RFC 6066]),
  Connection ID ([RFC 9146]) и Record Size Limit ([RFC 8449]). Все они
  настраиваются через `Config::builder()` и (где применимо) читаются через
  `Dtls::negotiated_alpn()` / `Dtls::peer_server_name()`. Подробности —
  в секции [Supported DTLS 1.3 extensions](#supported-dtls-13-extensions).
- **Фокус на производительности.** Убран ряд не нужных для 1.3 абстракций
  (PSK, PRF‑TLS‑1.2, auto‑sense), уменьшены аллокации на горячем пути
  (`ParsedRecord` не таскает inline‑буфер handshake‑фрагментов на каждый
  app‑data пакет), добавлены транзиентные пути для queue‑full ошибок.
- **Небольшие изменения интерфейсов.** Некоторые сигнатуры отличаются от
  апстрима там, где это оправдано задачей «удобный middleware» —
  например, `Dtls::send_application_data` возвращает `Ok(0)`, когда
  transmit‑queue переполнена, чтобы вызывающий код мог ретраить без
  потери данных.

Если вам нужен DTLS 1.2 или auto‑sense (обнаружение версии по первому
ClientHello) — используйте оригинальный [dimpl](https://github.com/algesten/dimpl).

## Async wrapper for Tokio

Если вам нужна асинхронная обвязка поверх Tokio вместо прямой работы с
Sans‑IO движком — используйте крейт
**[`tokio-dtls`](https://crates.io/crates/tokio-dtls)**. Он оборачивает
`dimpl13` в привычный `async` API (`connect` / `accept`, `send` / `recv`,
`close`), держит `UdpSocket` и фоновую задачу внутри и пробрасывает
результаты согласования (ALPN, SNI) наружу через
`DtlsConnection::negotiated_alpn()` / `DtlsConnection::peer_server_name()`.
Криптография и state machine — те же, что и в `dimpl13`; меняется только
модель использования. Выбирайте `tokio-dtls`, если не хотите писать свой
event loop; `dimpl13` — если нужен полный контроль над движком.

## Goals
- **DTLS 1.3**: реализует handshake и record layer в объёме, необходимом
  для WebRTC и типовых UDP‑протоколов.
- **Safety**: `forbid(unsafe_code)` во всём крейте.
- **Minimal Rust‑only deps**: только небольшие, хорошо поддерживаемые
  Rust‑крейты для криптографии.
- **Low overhead**: плотный контроль над аллокациями и буферами;
  Sans‑IO интеграция.
- **Predictable retries**: переполнение очередей на горячем пути не
  роняет соединение — приложение получает сигнал «повтори позже».

### Non‑goals
- **DTLS 1.0 / DTLS 1.2** (используйте [dimpl](https://github.com/algesten/dimpl) для DTLS 1.2)
- **Async**: крейт Sans‑IO и не привязан к конкретному event loop
  (для Tokio см. [tokio-dtls](https://crates.io/crates/tokio-dtls)).
- **no_std** (наверное в принципе)
- **RSA**
- **DHE**
- **PSK** — в DTLS 1.3 PSK‑путь в апстримном dimpl реализован не был;
  форк сохраняет это состояние.
- **Auto‑sense версии** — не имеет смысла, когда 1.3 единственная версия.

## Cryptography surface
- **Cipher suites (TLS 1.3 over DTLS)**
  - `TLS_AES_128_GCM_SHA256`
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_CHACHA20_POLY1305_SHA256`
- **AEAD**: AES‑GCM 128/256, ChaCha20‑Poly1305 (без CBC/EtM).
- **Key exchange**: ECDHE (P‑256 / P‑384), X25519.
- **Signatures**: ECDSA P‑256/SHA‑256, ECDSA P‑384/SHA‑384.
- **DTLS‑SRTP**: экспортирует keying material для
  `SRTP_AEAD_AES_256_GCM`, `SRTP_AEAD_AES_128_GCM` и
  `SRTP_AES128_CM_SHA1_80` ([RFC 5764], [RFC 7714]).

## Supported DTLS 1.3 extensions

Четыре расширения настраиваются через `dimpl13::Config::builder()` и
(где применимо) наблюдаются через публичное API движка:

| Расширение | Направление | Как настроить | Как прочитать |
|---|---|---|---|
| **ALPN** (RFC 7301) | обе стороны | `Config::builder().alpn_protocols(&[b"h2", …])` | `Dtls::negotiated_alpn()` |
| **SNI** (RFC 6066) | клиент → сервер | `Config::builder().server_name("example.com")` | `Dtls::peer_server_name()` |
| **Connection ID** (RFC 9146) | обе стороны | `Config::builder().connection_id(&[…])` | прозрачно |
| **Record Size Limit** (RFC 8449) | обе стороны, асимметрично | `Config::builder().record_size_limit(1200)` | прозрачно |

Детали:

- **ALPN.** Клиент отправляет список протоколов; сервер выбирает один из
  своего списка предпочтений. Обе стороны получают выбранный протокол
  через `negotiated_alpn()`. Если пересечения нет, сервер аварийно
  завершает handshake с `Error::SecurityError(NoCommonAlpnProtocol)` —
  это корректное поведение по RFC 7301.
- **SNI.** Клиент отправляет имя сервера; сервер может прочитать его
  через `peer_server_name()`. На клиенте метод всегда возвращает `None`.
  `dimpl13` **не** проверяет соответствие SNI сертификату пира — это
  политика приложения.
- **Connection ID.** Требуется настроить **на обеих** сторонах; иначе
  расширение тихо отключается и wire‑формат возвращается к стандартному
  заголовку записи. Транспарентно для `send_application_data` /
  `Output::ApplicationData`. Это механизм, сохраняющий сессию при
  NAT‑rebinding.
- **Record Size Limit.** Каждая сторона объявляет максимальный размер
  исходящих записей; лимит пира применяется к нашим исходящим записям.
  По умолчанию `16385` (`Config::default()`). Асимметрично: достаточно,
  чтобы одна сторона выставила значение. Полезно для constrained‑сетей.

```rust,no_run
use std::sync::Arc;
use dimpl13::{Config, Dtls, certificate};
use std::time::Instant;

let config = Arc::new(
    Config::builder()
        .alpn_protocols(&[b"h2".as_slice(), b"http/1.1".as_slice()])
        .server_name("example.com")               // только клиент
        .connection_id(&[0xDE, 0xAD, 0xBE, 0xEF]) // обе стороны
        .record_size_limit(1200)                  // обе стороны
        .build()
        .unwrap(),
);
let cert = certificate::generate_self_signed_certificate().unwrap();
let mut dtls = Dtls::new_13(config, cert, Instant::now());
dtls.set_active(true); // клиент

// ... прогон handshake ...

if let Some(proto) = dtls.negotiated_alpn() {
    println!("negotiated ALPN: {}", String::from_utf8_lossy(proto));
}
// на сервере:
// if let Some(sni) = dtls.peer_server_name() { … }
```

Если расширения не нужны, `Config::default()` даёт «голый» DTLS 1.3 без
ALPN, без SNI, без Connection ID и с дефолтным Record Size Limit — это
самый дешёвый режим.

### Certificate model
Во время handshake движок выдаёт [`Output::PeerCert`][peer_cert] с
leaf‑сертификатом пира (DER). Крейт использует сертификат для проверки
подписи DTLS handshake‑сообщений, но не выполняет PKI‑валидацию.
Приложение само валидирует сертификат по своей политике (fingerprint,
построение цепочки, проверки name/EKU, pinning и т. п.).

### Sans‑IO integration model
Использование движка — три вызова:
- [`Dtls::handle_packet`][handle_packet] — подать целую принятую
  UDP‑датаграмму.
- [`Dtls::poll_output`][poll_output] — вытянуть исходящие
  DTLS‑записи, таймеры, события.
- [`Dtls::handle_timeout`][handle_timeout] — продвинуть
  ретрансмиссии / time‑based progress.

`Output` — enum с заимствованными ссылками в буфер, который вы дали
`poll_output`:
- `Packet(&[u8])` — отправить в UDP‑сокет.
- `BufferTooSmall { needed }` — увеличить буфер и повторить.
- `Timeout(Instant)` — запланировать таймер, вызвать
  `handle_timeout` в этот (или позже) момент.
- `Connected` — handshake завершён.
- `PeerCert(&[u8])` — leaf‑сертификат пира (DER) для проверки.
- `KeyingMaterial(KeyingMaterial, SrtpProfile)` — DTLS‑SRTP экспорт.
- `ApplicationData(&[u8])` — открытый текст от пира.
- `CloseNotify` — пир прислал `close_notify` (graceful shutdown).

## Error handling

Каждая `Error`, возвращённая публичным API
([`handle_packet`][handle_packet], [`handle_timeout`][handle_timeout],
`send_application_data`, `close`), **фатальна** для соединения: движок
не имеет восстанавливаемых состояний, корректная реакция — выбросить
`Dtls` и, если соединение ещё нужно, начать новый handshake.

Транзиентные условия, свойственные ненадёжному транспорту — битые
датаграммы, повторы, out‑of‑window записи, парсерный шум, **переполнение
приёмной очереди** — обрабатываются внутри и наружу как `Error` не
выходят. Такие пакеты тихо отбрасываются (лог `debug!`), соединение
живёт дальше. Ошибку `Error` никогда не нужно интерпретировать как
«повторить» — она всегда означает «сдаваться и рвать соединение».

**Исключение — переполнение transmit‑очереди на горячем пути прикладных
данных.** [`Dtls::send_application_data`][send_app] возвращает
`Ok(0)`, если очередь переполнена; данные **не** приняты и их надо
переслать после [`poll_output`][poll_output]. Это не ошибка соединения,
это backpressure. См. также `Config::builder().max_queue_tx(...)`.

## Example (Sans‑IO loop)

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

`Config::builder()` позволяет поднять размеры очередей, если ваш
сценарий (например, KCP‑over‑DTLS) генерирует всплески:

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

Значения по умолчанию (`max_queue_rx = 30`, `max_queue_tx = 10`)
рассчитаны на WebRTC и держат память на соединение минимальной. При
`256 / 256` верхняя граница ~576 KB на соединение (2 × 256 × 1150 B),
причём реально столько занимается только при полной загрузке очередей.

## Versioning and divergence from upstream

- Крейт **специально** не отслеживает `dimpl` один‑в‑один. Основные
  изменения в публичном API относительно апстрима документируются в
  [`CHANGELOG.md`].
- Все правки, не связанные с удалением 1.2, добавлением расширений
  (ALPN/SNI/CID/RSL) или оптимизациями, по возможности держатся в стиле
  апстрима, чтобы облегчить мерж криптографических багов‑фиксов.
- Если вы хотите upstream‑совместимое поведение, используйте
  [dimpl][upstream].

#### MSRV
Rust 1.88.0

#### Status
- Session resumption не реализован (WebRTC делает full handshake на ICE restart).
- Renegotiation в DTLS 1.3 не применим; используйте `KeyUpdate`.

[upstream]: https://github.com/algesten/dimpl
[send_app]: https://docs.rs/dimpl13/latest/dimpl13/struct.Dtls.html#method.send_application_data
[peer_cert]: https://docs.rs/dimpl13/latest/dimpl13/enum.Output.html#variant.PeerCert
[handle_packet]: https://docs.rs/dimpl13/latest/dimpl13/struct.Dtls.html#method.handle_packet
[poll_output]: https://docs.rs/dimpl13/latest/dimpl13/struct.Dtls.html#method.poll_output
[handle_timeout]: https://docs.rs/dimpl13/latest/dimpl13/struct.Dtls.html#method.handle_timeout
[output]: https://docs.rs/dimpl13/latest/dimpl13/enum.Output.html
[RFC 5764]: https://www.rfc-editor.org/rfc/rfc5764
[RFC 7714]: https://www.rfc-editor.org/rfc/rfc7714
[RFC 6066]: https://www.rfc-editor.org/rfc/rfc6066
[RFC 7301]: https://www.rfc-editor.org/rfc/rfc7301
[RFC 8449]: https://www.rfc-editor.org/rfc/rfc8449
[RFC 9146]: https://www.rfc-editor.org/rfc/rfc9146
[CHANGELOG.md]: ./CHANGELOG.md

License: MIT OR Apache-2.0

CHANGELOG.md не заполнен, а унаследован от апстрима. 
Внесение вклада крайне приветствуется, однако пожалуйста, 
добавляя функционал выносите это в cargo features. 
Я не думаю слишком много о требованиях к вкладу, поэтому
вы можете вносить вклад в dimpl13 свободно, в плане
не ограничено строгими правилами. Используйте русский или английский,
но исключительно английский в коде и коммитах, выносите значительные 
фичи в cargo features, используйте cargo fmt. Документация на русском 
не требование. Используйте issues, PR -- как вам удобно, я буду 
поддерживать dimpl13, так как использую DTLS 1.3 в проде.
Использование ИИ не запрещено и не требует маркировки, хотя я 
всё же могу не рассматривать мусорный вклад.
