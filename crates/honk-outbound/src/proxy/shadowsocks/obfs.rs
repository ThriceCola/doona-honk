//! simple-obfs client transport (`http` and `tls` modes).
//!
//! This layer sits *below* the Shadowsocks cipher: it carries ciphertext and
//! never sees plaintext, matching dae's dialer stack (`dialer/shadowsocks`
//! wraps the obfs dialer, then the cipher dialer wraps that). The first bytes
//! of a connection are therefore the first SS ciphertext, wrapped in either a
//! WebSocket-shaped `GET` or a fake `ClientHello`.
//!
//! Wire formats follow `github.com/olicesx/outbound/transport/simpleobfs`
//! (`http.go`, `tls.go` — the revision dae pins), which follows
//! shadowsocks/simple-obfs. Differences are deliberate robustness, not wire
//! changes: the HTTP response header accumulates across reads under a bound,
//! zero-length TLS records are skipped instead of returning `(0, nil)`, a
//! partially read record keeps its remaining count, and a framed write reports
//! the chunks that already left. `Write` therefore never loses bytes the peer
//! may already have.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use honk_config::node::{ShadowsocksObfs, ShadowsocksObfsMode};
use rand::{Rng, RngExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::aead2022::unix_timestamp;
use super::stream::SsWrite;

/// Bound on the response header: the peer controls how many bytes it can send
/// without a `\r\n\r\n` terminator.
const MAX_HTTP_HEADER: usize = 8 * 1024;

/// simple-obfs frames application data in TLS records of at most 16 KiB.
const TLS_CHUNK: usize = 16 * 1024;

/// Payload bytes one `poll_write` may frame, bounding per-connection buffers
/// the same way the SS codec bounds its own send buffer.
const TLS_FRAME_CAP: usize = 64 * 1024;

/// Fixed bytes a simple-obfs server sends before its first data record: a fake
/// `ServerHello` record (96 bytes) and a fake `ChangeCipherSpec` (6 bytes). The
/// record header that follows is parsed like any other.
const TLS_SERVER_PREFIX: usize = 96 + 6;

/// The TLS record types simple-obfs uses: handshake for the first response
/// record (the server reuses the encrypted-handshake header for its first
/// payload) and application data afterwards.
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_APPLICATION_DATA: u8 = 0x17;

/// Resolved wire parameters for one connection. `host` falls back to the
/// server address when the node leaves it empty, and `path` to `/`.
#[derive(Clone)]
pub(crate) struct Plan {
    mode: ShadowsocksObfsMode,
    host: String,
    port: u16,
    path: String,
}

impl Plan {
    pub(crate) fn new(obfs: &ShadowsocksObfs, server_host: &str, server_port: u16) -> Self {
        Self {
            mode: obfs.mode,
            host: obfs.host.clone().unwrap_or_else(|| server_host.to_string()),
            port: server_port,
            path: obfs.path.clone().unwrap_or_else(|| "/".to_string()),
        }
    }
}

/// Encode the first HTTP request around `payload` bytes of ciphertext.
fn http_request(plan: &Plan, payload_len: usize) -> Vec<u8> {
    use base64::Engine as _;
    let mut rng = rand::rng();
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    let key = base64::engine::general_purpose::URL_SAFE.encode(nonce);
    let major = rng.random_range(0..87);
    let minor = rng.random_range(0..2);
    // The reference client writes `host:port` unless the server is on port 80.
    let authority = if plan.port == 80 {
        plan.host.clone()
    } else {
        format!("{}:{}", plan.host, plan.port)
    };
    format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: curl/7.{}.{}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Content-Length: {}\r\n\r\n",
        plan.path, authority, major, minor, key, payload_len
    )
    .into_bytes()
}

/// The fake `ClientHello` that carries `payload` in its session-ticket
/// extension.
///
/// The layout is byte-compatible with the reference template: the session
/// ticket is the first extension (simple-obfs servers read the payload from
/// there), the SNI carries the obfs host, and all three length fields count the
/// payload and host exactly.
fn tls_client_hello(payload: &[u8], host: &str) -> Vec<u8> {
    let mut rng = rand::rng();
    let mut random = [0u8; 28];
    rng.fill_bytes(&mut random);
    let mut session_id = [0u8; 32];
    rng.fill_bytes(&mut session_id);

    let mut hello = Vec::with_capacity(256 + payload.len() + host.len());
    // handshake record: type, TLS 1.0 version, length
    hello.extend_from_slice(&[0x16, 0x03, 0x01]);
    let record_len = 212 + payload.len() + host.len();
    hello.extend_from_slice(&(record_len as u16).to_be_bytes());
    // ClientHello: type, three-byte length, TLS 1.2 version
    hello.push(1);
    hello.push(0);
    hello.extend_from_slice(&((208 + payload.len() + host.len()) as u16).to_be_bytes());
    hello.extend_from_slice(&[0x03, 0x03]);
    // random: 4 bytes of time, 28 random
    hello.extend_from_slice(&(unix_timestamp() as u32).to_be_bytes());
    hello.extend_from_slice(&random);
    hello.push(session_id.len() as u8);
    hello.extend_from_slice(&session_id);
    // cipher suites (56 bytes) and null compression
    hello.extend_from_slice(&[0x00, 0x38]);
    hello.extend_from_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0,
        0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00,
        0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);
    hello.extend_from_slice(&[0x01, 0x00]);
    hello.extend_from_slice(&((79 + payload.len() + host.len()) as u16).to_be_bytes());
    // session ticket: the payload rides here
    hello.extend_from_slice(&[0x00, 0x23]);
    hello.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    hello.extend_from_slice(payload);
    // server name indication
    hello.extend_from_slice(&[0x00, 0x00]);
    hello.extend_from_slice(&((host.len() + 5) as u16).to_be_bytes());
    hello.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    hello.push(0);
    hello.extend_from_slice(&(host.len() as u16).to_be_bytes());
    hello.extend_from_slice(host.as_bytes());
    // ec point formats, supported groups, signature algorithms, the two flags
    hello.extend_from_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);
    hello.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
    ]);
    hello.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05,
        0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);
    hello.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);
    hello.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
    hello
}

/// One TLS application-data record: `17 03 03 | u16 length | payload`.
fn tls_record(payload: &[u8]) -> Vec<u8> {
    debug_assert!(payload.len() <= TLS_CHUNK);
    let mut record = Vec::with_capacity(5 + payload.len());
    record.extend_from_slice(&[TLS_RECORD_APPLICATION_DATA, 0x03, 0x03]);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

enum WriteStage {
    /// Nothing has been written: the next payload becomes the handshake.
    Handshake,
    /// The handshake is out; frames carry the rest.
    Open,
}

/// Client-side obfs encoder over one write half.
pub(crate) struct Writer<W> {
    inner: W,
    plan: Plan,
    stage: WriteStage,
    /// Framed bytes waiting for the socket, and how many of them are out.
    out: Vec<u8>,
    off: usize,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub(crate) fn new(inner: W, plan: Plan) -> Self {
        Self {
            inner,
            plan,
            stage: WriteStage::Handshake,
            out: Vec::new(),
            off: 0,
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.off < self.out.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out[self.off..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "simple-obfs write zero",
                    )));
                }
                Poll::Ready(Ok(written)) => self.off += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out.clear();
        self.off = 0;
        Poll::Ready(Ok(()))
    }

    /// Frame up to [`TLS_FRAME_CAP`] bytes of `buf` as TLS records.
    fn frame_records(&mut self, buf: &[u8]) -> usize {
        let accepted = buf.len().min(TLS_FRAME_CAP);
        for chunk in buf[..accepted].chunks(TLS_CHUNK) {
            self.out.extend_from_slice(&tls_record(chunk));
        }
        accepted
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Writer<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            // A partially written envelope stays ordered: take no new bytes
            // until it is out.
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.stage {
            WriteStage::Handshake => {
                match this.plan.mode {
                    ShadowsocksObfsMode::Http => {
                        // The request carries the payload as its body.
                        this.out = http_request(&this.plan, buf.len());
                        this.out.extend_from_slice(buf);
                        this.stage = WriteStage::Open;
                        let _ = this.poll_drain(cx);
                        Poll::Ready(Ok(buf.len()))
                    }
                    ShadowsocksObfsMode::Tls => {
                        // The payload rides inside the fake ClientHello, so a
                        // write longer than one chunk keeps the rest for the
                        // caller to send as records.
                        let chunk = &buf[..buf.len().min(TLS_CHUNK)];
                        this.out = tls_client_hello(chunk, &this.plan.host);
                        this.stage = WriteStage::Open;
                        let _ = this.poll_drain(cx);
                        Poll::Ready(Ok(chunk.len()))
                    }
                }
            }
            WriteStage::Open => match this.plan.mode {
                // HTTP obfuscates the first request only.
                ShadowsocksObfsMode::Http => Pin::new(&mut this.inner).poll_write(cx, buf),
                ShadowsocksObfsMode::Tls => {
                    let accepted = this.frame_records(buf);
                    let _ = this.poll_drain(cx);
                    Poll::Ready(Ok(accepted))
                }
            },
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl<W: SsWrite> SsWrite for Writer<W> {
    fn tcp(&self) -> &TcpStream {
        self.inner.tcp()
    }

    const REWRITES_FIRST_WRITE: bool = true;
}

#[derive(Clone, Copy)]
enum ReadStage {
    /// HTTP: accumulate through the response header terminator.
    HttpHeader,
    /// TLS: consume the fixed fake `ServerHello` + `ChangeCipherSpec`.
    TlsPrefix,
    /// TLS: the next five bytes are a record header.
    TlsRecordHeader,
    /// TLS: `remaining` bytes of the current record's payload.
    TlsRecordBody { remaining: u16 },
    /// Application bytes pass straight through (HTTP mode only).
    Open,
}

/// Client-side obfs decoder over one read half.
///
/// `buf[off..filled]` is the live window: the accumulated HTTP header before
/// the terminator, the body bytes that arrived behind it, the fixed TLS
/// server prefix, or the five-byte record header being assembled.
pub(crate) struct Reader<R> {
    inner: R,
    stage: ReadStage,
    buf: Vec<u8>,
    filled: usize,
    off: usize,
    /// HTTP: bytes already searched for the terminator without a match.
    scanned: usize,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    pub(crate) fn new(inner: R, plan: &Plan) -> Self {
        Self {
            inner,
            stage: match plan.mode {
                ShadowsocksObfsMode::Http => ReadStage::HttpHeader,
                ShadowsocksObfsMode::Tls => ReadStage::TlsPrefix,
            },
            buf: Vec::new(),
            filled: 0,
            off: 0,
            scanned: 0,
        }
    }

    /// Read into `buf` from `filled`, keeping at most `cap` bytes.
    fn poll_fill(&mut self, cx: &mut Context<'_>, cap: usize) -> Poll<io::Result<usize>> {
        if self.buf.len() < cap {
            self.buf.resize(cap, 0);
        }
        let mut read = ReadBuf::new(&mut self.buf[self.filled..cap]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                let filled = read.filled().len();
                self.filled += filled;
                Poll::Ready(Ok(filled))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.filled = 0;
        self.off = 0;
        self.scanned = 0;
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Reader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            // Body bytes that arrived behind the HTTP response header go first.
            if matches!(this.stage, ReadStage::Open) && this.off < this.filled {
                let take = (this.filled - this.off).min(out.remaining());
                out.put_slice(&this.buf[this.off..this.off + take]);
                this.off += take;
                if this.off == this.filled {
                    this.reset();
                }
                return Poll::Ready(Ok(()));
            }
            match this.stage {
                ReadStage::Open => return Pin::new(&mut this.inner).poll_read(cx, out),
                ReadStage::HttpHeader => {
                    // Only bytes appended since the last scan can complete the
                    // terminator, so each byte is searched once.
                    let from = this.scanned.min(this.filled);
                    if let Some(position) = this.buf[..this.filled]
                        .windows(4)
                        .skip(from)
                        .position(|window| window == b"\r\n\r\n")
                    {
                        let body = from + position + 4;
                        this.off = body;
                        this.stage = ReadStage::Open;
                        if this.off == this.filled {
                            this.reset();
                        }
                        continue;
                    }
                    this.scanned = this.filled.saturating_sub(3);
                    if this.filled == MAX_HTTP_HEADER {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "simple-obfs http: response header exceeds its bound",
                        )));
                    }
                    match this.poll_fill(cx, MAX_HTTP_HEADER) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "simple-obfs http: peer closed inside the response header",
                            )));
                        }
                        Poll::Ready(Ok(_)) => continue,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                ReadStage::TlsPrefix => {
                    if this.filled < TLS_SERVER_PREFIX {
                        match this.poll_fill(cx, TLS_SERVER_PREFIX) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "simple-obfs tls: peer closed inside the server hello",
                                )));
                            }
                            Poll::Ready(Ok(_)) => continue,
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    if this.buf[0] != TLS_RECORD_HANDSHAKE
                        || this.buf[TLS_SERVER_PREFIX - 6] != 0x14
                    {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "simple-obfs tls: peer did not answer with a server hello",
                        )));
                    }
                    this.reset();
                    this.stage = ReadStage::TlsRecordHeader;
                    continue;
                }
                ReadStage::TlsRecordHeader => {
                    if this.filled < 5 {
                        match this.poll_fill(cx, 5) {
                            Poll::Ready(Ok(0)) => {
                                if this.filled == 0 {
                                    // Clean EOF at a record boundary.
                                    return Poll::Ready(Ok(()));
                                }
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "simple-obfs tls: peer closed inside a record header",
                                )));
                            }
                            Poll::Ready(Ok(_)) => continue,
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let record_type = this.buf[0];
                    if !matches!(
                        record_type,
                        TLS_RECORD_HANDSHAKE | TLS_RECORD_APPLICATION_DATA
                    ) || this.buf[1] != 0x03
                        || this.buf[2] != 0x03
                    {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "simple-obfs tls: unexpected record header",
                        )));
                    }
                    let length = u16::from_be_bytes([this.buf[3], this.buf[4]]);
                    this.reset();
                    if length == 0 {
                        // A zero-length record makes no progress; skip it.
                        continue;
                    }
                    this.stage = ReadStage::TlsRecordBody { remaining: length };
                }
                ReadStage::TlsRecordBody { remaining } => {
                    let take = usize::from(remaining).min(out.remaining());
                    let mut read = ReadBuf::new(&mut out.initialize_unfilled()[..take]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                        Poll::Ready(Ok(())) => {
                            let filled = read.filled().len();
                            if filled == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "simple-obfs tls: peer closed inside a record",
                                )));
                            }
                            let remaining = remaining - filled as u16;
                            this.stage = if remaining == 0 {
                                ReadStage::TlsRecordHeader
                            } else {
                                ReadStage::TlsRecordBody { remaining }
                            };
                            out.advance(filled);
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
