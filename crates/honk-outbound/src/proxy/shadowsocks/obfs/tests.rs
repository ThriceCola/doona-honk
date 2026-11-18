use super::*;
use honk_config::node::{ShadowsocksObfs, ShadowsocksObfsMode};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn plan(mode: ShadowsocksObfsMode, host: Option<&str>, path: Option<&str>, port: u16) -> Plan {
    Plan::new(
        &ShadowsocksObfs {
            mode,
            host: host.map(str::to_string),
            path: path.map(str::to_string),
        },
        "server.example",
        port,
    )
}

/// Write sink that keeps every byte and never applies backpressure.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Sink {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Independent HTTP/1.1 request decoder: the layout check must not reuse the
/// encoder's own idea of the header.
struct ParsedRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl ParsedRequest {
    fn parse(bytes: &[u8]) -> Self {
        let split = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("terminated header");
        let head = std::str::from_utf8(&bytes[..split]).expect("utf-8 header");
        let mut lines = head.split("\r\n");
        let request_line = lines.next().expect("request line");
        let mut parts = request_line.split(' ');
        let method = parts.next().unwrap().to_string();
        let target = parts.next().unwrap().to_string();
        let version = parts.next().unwrap().to_string();
        assert!(parts.next().is_none(), "request line has one target");
        let headers = lines
            .map(|line| {
                let (name, value) = line.split_once(':').expect("header line");
                (name.to_string(), value.trim().to_string())
            })
            .collect();
        Self {
            method,
            target,
            version,
            headers,
            body: bytes[split + 4..].to_vec(),
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Independent TLS record/handshake walker for the fake ClientHello.
struct ParsedClientHello {
    handshake_type: u8,
    version: [u8; 2],
    session_ticket: Vec<u8>,
    server_name: String,
    extensions: Vec<u16>,
    consumed: usize,
}

impl ParsedClientHello {
    fn parse(bytes: &[u8]) -> Self {
        assert_eq!(bytes[0], 0x16, "handshake record type");
        assert_eq!(&bytes[1..3], &[0x03, 0x01], "record version");
        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        let end = 5 + record_len;
        assert!(bytes.len() >= end, "record length fits the buffer");
        let bytes = &bytes[..end];
        let mut cursor = 5usize;
        let handshake_type = bytes[cursor];
        let handshake_len =
            u32::from_be_bytes([0, bytes[cursor + 1], bytes[cursor + 2], bytes[cursor + 3]])
                as usize;
        assert_eq!(
            handshake_len,
            bytes.len() - 9,
            "handshake length covers the body"
        );
        cursor += 4;
        let version = [bytes[cursor], bytes[cursor + 1]];
        cursor += 2;
        cursor += 32; // random
        let session_id_len = bytes[cursor] as usize;
        cursor += 1 + session_id_len;
        let suites_len = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += 2 + suites_len;
        let compression_len = bytes[cursor] as usize;
        cursor += 1 + compression_len;
        let ext_len = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += 2;
        let ext_end = cursor + ext_len;
        assert_eq!(
            ext_end,
            bytes.len(),
            "extension length reaches the record end"
        );
        let mut extensions = Vec::new();
        let mut session_ticket = Vec::new();
        let mut server_name = String::new();
        while cursor < ext_end {
            let kind = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
            let len = u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]) as usize;
            cursor += 4;
            let data = &bytes[cursor..cursor + len];
            match kind {
                0x0023 => session_ticket = data.to_vec(),
                0x0000 => {
                    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                    assert_eq!(list_len, data.len() - 2, "SNI list length covers the entry");
                    assert_eq!(data[2], 0, "host_name name type");
                    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
                    assert_eq!(data.len(), 5 + name_len, "SNI name length covers the host");
                    server_name = String::from_utf8(data[5..].to_vec()).unwrap();
                }
                _ => {}
            }
            extensions.push(kind);
            cursor += len;
        }
        Self {
            handshake_type,
            version,
            session_ticket,
            server_name,
            extensions,
            consumed: cursor,
        }
    }
}

fn ciphertext(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

#[tokio::test]
async fn http_first_request_wraps_the_payload() {
    let sink = Sink::default();
    let mut writer = Writer::new(
        sink.clone(),
        plan(
            ShadowsocksObfsMode::Http,
            Some("cdn.example"),
            Some("/asset"),
            8388,
        ),
    );
    let payload = ciphertext(40);
    writer.write_all(&payload).await.unwrap();

    let request = ParsedRequest::parse(&sink.bytes());
    assert_eq!(request.method, "GET");
    assert_eq!(request.target, "/asset");
    assert_eq!(request.version, "HTTP/1.1");
    assert_eq!(request.header("Host"), Some("cdn.example:8388"));
    let user_agent = request.header("User-Agent").unwrap();
    let version = user_agent.strip_prefix("curl/7.").expect("curl user agent");
    let (major, minor) = version.split_once('.').expect("major.minor");
    assert!(major.parse::<u8>().is_ok_and(|major| major < 87));
    assert!(minor.parse::<u8>().is_ok_and(|minor| minor < 2));
    assert_eq!(request.header("Upgrade"), Some("websocket"));
    assert_eq!(request.header("Connection"), Some("Upgrade"));
    use base64::Engine as _;
    let key = base64::engine::general_purpose::URL_SAFE
        .decode(request.header("Sec-WebSocket-Key").unwrap())
        .expect("base64url key");
    assert_eq!(key.len(), 16);
    assert_eq!(request.header("Content-Length"), Some("40"));
    assert_eq!(request.body, payload);
}

#[tokio::test]
async fn http_authority_omits_port_80_and_falls_back_to_the_server_host() {
    let sink = Sink::default();
    let mut writer = Writer::new(
        sink.clone(),
        plan(ShadowsocksObfsMode::Http, None, None, 80),
    );
    writer.write_all(b"x").await.unwrap();
    let request = ParsedRequest::parse(&sink.bytes());
    assert_eq!(request.target, "/");
    assert_eq!(request.header("Host"), Some("server.example"));
}

#[tokio::test]
async fn http_obfuscates_only_the_first_write() {
    let sink = Sink::default();
    let mut writer = Writer::new(
        sink.clone(),
        plan(ShadowsocksObfsMode::Http, None, None, 8388),
    );
    writer.write_all(b"first").await.unwrap();
    writer.write_all(b"second").await.unwrap();
    let bytes = sink.bytes();
    let request = ParsedRequest::parse(&bytes);
    assert_eq!(request.header("Content-Length"), Some("5"));
    assert_eq!(request.body, b"firstsecond", "later writes pass through");
}

#[tokio::test]
async fn tls_client_hello_carries_the_first_chunk_in_its_ticket() {
    let sink = Sink::default();
    let mut writer = Writer::new(
        sink.clone(),
        plan(
            ShadowsocksObfsMode::Tls,
            Some("www.example.org"),
            None,
            8388,
        ),
    );
    let payload = ciphertext(64);
    writer.write_all(&payload).await.unwrap();

    let hello = ParsedClientHello::parse(&sink.bytes());
    assert_eq!(hello.handshake_type, 1);
    assert_eq!(hello.version, [0x03, 0x03]);
    assert_eq!(hello.session_ticket, payload);
    assert_eq!(hello.server_name, "www.example.org");
    // Session ticket first: simple-obfs servers read the payload from there.
    assert_eq!(hello.extensions[0], 0x0023);
    assert_eq!(hello.consumed, sink.bytes().len());
}

#[tokio::test]
async fn tls_frames_every_later_write_as_application_data() {
    let sink = Sink::default();
    let mut writer = Writer::new(
        sink.clone(),
        plan(ShadowsocksObfsMode::Tls, None, None, 8388),
    );
    let first = ciphertext(TLS_CHUNK);
    let second = ciphertext(20_000);
    writer.write_all(&first).await.unwrap();
    writer.write_all(&second).await.unwrap();

    let bytes = sink.bytes();
    let hello_len = tls_client_hello(&first, "server.example").len();
    let mut cursor = hello_len;
    let mut frames = Vec::new();
    while cursor < bytes.len() {
        assert_eq!(&bytes[cursor..cursor + 3], &[0x17, 0x03, 0x03]);
        let len = u16::from_be_bytes([bytes[cursor + 3], bytes[cursor + 4]]) as usize;
        assert!(
            len <= TLS_CHUNK,
            "a frame never exceeds the reference chunk"
        );
        frames.extend_from_slice(&bytes[cursor + 5..cursor + 5 + len]);
        cursor += 5 + len;
    }
    assert_eq!(frames, second);
}

/// A framed write may only report bytes it queued or wrote, and the socket
/// failure must reach the caller instead of being swallowed. A short write
/// keeps the rest of the envelope buffered, in order.
#[tokio::test]
async fn tls_write_accounts_for_queued_frames_and_reports_the_failure() {
    /// Accepts a prefix and then fails.
    struct FailingSink {
        accepted: usize,
    }

    impl AsyncWrite for FailingSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.accepted == 0 {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")));
            }
            let take = self.accepted.min(buf.len());
            self.accepted -= take;
            Poll::Ready(Ok(take))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    let mut writer = Writer::new(
        FailingSink { accepted: 32 },
        plan(ShadowsocksObfsMode::Tls, None, None, 8388),
    );
    let payload = ciphertext(TLS_CHUNK);
    let delivered = std::future::poll_fn(|cx| Pin::new(&mut writer).poll_write(cx, &payload))
        .await
        .expect("the handshake is buffered before the socket reports the loss");
    assert_eq!(delivered, TLS_CHUNK);
    let error = std::future::poll_fn(|cx| Pin::new(&mut writer).poll_write(cx, b"more"))
        .await
        .expect_err("the buffered frame still reports the write failure");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}

/// A socket that reports `Pending` once: the framed bytes must stay buffered
/// and leave in order when the socket becomes writable, and the caller must
/// still be told that its payload was accepted.
#[tokio::test]
async fn tls_handshake_survives_a_pending_socket() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct PendingSink {
        ready: Arc<AtomicBool>,
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncWrite for PendingSink {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if !self.ready.load(Ordering::SeqCst) {
                // Wake immediately: the test flips the flag before polling again.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.bytes.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    let ready = Arc::new(AtomicBool::new(false));
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let plan = plan(ShadowsocksObfsMode::Tls, Some("mask.example"), None, 8388);
    let mut writer = Writer::new(
        PendingSink {
            ready: ready.clone(),
            bytes: bytes.clone(),
        },
        plan,
    );
    let payload = ciphertext(64);
    assert_eq!(
        std::future::poll_fn(|cx| Pin::new(&mut writer).poll_write(cx, &payload))
            .await
            .unwrap(),
        payload.len(),
        "a pending socket still accepts the payload into the envelope"
    );
    ready.store(true, Ordering::SeqCst);
    writer.flush().await.unwrap();
    let hello = ParsedClientHello::parse(&bytes.lock().unwrap().clone());
    assert_eq!(hello.session_ticket, payload);
    assert_eq!(hello.server_name, "mask.example");
}

async fn feed(source: &str, plan: Plan) -> Reader<tokio::io::DuplexStream> {
    let (mut writer, reader) = tokio::io::duplex(64 * 1024);
    let bytes = source.as_bytes().to_vec();
    tokio::spawn(async move {
        let _ = writer.write_all(&bytes).await;
    });
    Reader::new(reader, &plan)
}

#[tokio::test]
async fn http_response_header_may_straddle_reads() {
    let mut reader = feed(
        "HTTP/1.1 200 OK\r\nServer: obfs\r\nX-Trace: 1\r\n\r\nplaintext",
        plan(ShadowsocksObfsMode::Http, None, None, 8388),
    )
    .await;
    let mut body = Vec::new();
    reader.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"plaintext");
}

#[tokio::test]
async fn http_response_header_without_body_keeps_reading() {
    let mut reader = feed(
        "HTTP/1.1 200 OK\r\n\r\n",
        plan(ShadowsocksObfsMode::Http, None, None, 8388),
    )
    .await;
    let mut buf = [0u8; 4];
    let read = tokio::time::timeout(std::time::Duration::from_millis(50), reader.read(&mut buf))
        .await
        .expect("a header-only first response is not end of stream");
    assert_eq!(read.unwrap(), 0, "the peer closed after the header");
}

#[tokio::test]
async fn http_response_header_is_bounded() {
    let header = format!(
        "HTTP/1.1 200 OK\r\n{}\r\n",
        "X: y\r\n".repeat(MAX_HTTP_HEADER)
    );
    let mut reader = feed(&header, plan(ShadowsocksObfsMode::Http, None, None, 8388)).await;
    let mut buf = [0u8; 64];
    let error = reader
        .read(&mut buf)
        .await
        .expect_err("unterminated header");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

/// Server response prefix exactly as shadowsocks/simple-obfs emits it: a fixed
/// 96-byte ServerHello record, a 6-byte ChangeCipherSpec, then the first
/// payload behind an encrypted-handshake record header.
fn tls_server_prefix(first_payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x16, 0x03, 0x01, 0x00, 0x5b];
    out.extend_from_slice(&[0u8; 91]);
    out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    out.extend_from_slice(&[TLS_RECORD_HANDSHAKE, 0x03, 0x03]);
    out.extend_from_slice(&(first_payload.len() as u16).to_be_bytes());
    out.extend_from_slice(first_payload);
    out
}

#[tokio::test]
async fn tls_skips_the_server_hello_and_zero_length_records() {
    let first = ciphertext(37);
    let second = ciphertext(11);
    let mut bytes = tls_server_prefix(&first);
    // A zero-length record makes no progress and must be skipped.
    bytes.extend_from_slice(&[TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x00]);
    bytes.extend_from_slice(&tls_record(&second));
    let (mut source, reader) = tokio::io::duplex(64 * 1024);
    source.write_all(&bytes).await.unwrap();
    drop(source);
    let mut reader = Reader::new(reader, &plan(ShadowsocksObfsMode::Tls, None, None, 8388));
    let mut body = Vec::new();
    reader.read_to_end(&mut body).await.unwrap();
    let mut expected = first;
    expected.extend_from_slice(&second);
    assert_eq!(body, expected);
}

#[tokio::test]
async fn tls_record_payload_may_straddle_reads() {
    let plan = plan(ShadowsocksObfsMode::Tls, None, None, 8388);
    let (mut source, read_end) = tokio::io::duplex(64 * 1024);
    source.write_all(&tls_server_prefix(&[])).await.unwrap();
    source
        .write_all(&[TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x08, 1, 2, 3])
        .await
        .unwrap();
    let mut reader = Reader::new(read_end, &plan);
    let mut buf = [0u8; 16];
    assert_eq!(reader.read(&mut buf).await.unwrap(), 3);
    assert_eq!(&buf[..3], &[1, 2, 3]);
    source.write_all(&[4, 5, 6, 7, 8]).await.unwrap();
    assert_eq!(reader.read(&mut buf).await.unwrap(), 5);
    assert_eq!(&buf[..5], &[4, 5, 6, 7, 8]);
}

#[tokio::test]
async fn tls_rejects_a_peer_that_is_not_obfs() {
    let mut reader = feed(
        "HTTP/1.1 400 Bad Request\r\n\r\n",
        plan(ShadowsocksObfsMode::Tls, None, None, 8388),
    )
    .await;
    let mut buf = [0u8; 16];
    let error = reader.read(&mut buf).await.expect_err("not a server hello");
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn tls_write_survives_backpressure() {
    let plan = plan(ShadowsocksObfsMode::Tls, None, None, 8388);
    let (source, mut peer) = tokio::io::duplex(1024);
    let mut writer = Writer::new(source, plan);
    let payload = ciphertext(300_000);
    let expected = payload.clone();
    let consumer = tokio::spawn(async move {
        let mut raw = Vec::new();
        peer.read_to_end(&mut raw).await.unwrap();
        let hello = ParsedClientHello::parse(&raw);
        let mut cursor = hello.consumed;
        let mut plain = hello.session_ticket;
        while cursor < raw.len() {
            assert_eq!(&raw[cursor..cursor + 3], &[0x17, 0x03, 0x03]);
            let len = u16::from_be_bytes([raw[cursor + 3], raw[cursor + 4]]) as usize;
            plain.extend_from_slice(&raw[cursor + 5..cursor + 5 + len]);
            cursor += 5 + len;
        }
        plain
    });
    writer.write_all(&payload).await.unwrap();
    writer.shutdown().await.unwrap();
    drop(writer);
    assert_eq!(consumer.await.unwrap(), expected);
}
