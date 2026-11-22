//! The client side of the RFC 6455 opening handshake, written here so the
//! connection ticket lives only in a scrubbed buffer.
//!
//! `tokio-tungstenite`'s own client handshake parses the whole URL into an
//! `http::Uri` (immutable `Bytes`) and renders the request line into an
//! ordinary `Vec`, neither of which can be scrubbed. This module builds the
//! upgrade request into a `Zeroizing<Vec<u8>>` of exact capacity, sends it,
//! validates the response against RFC 6455 section 4.2.2, and hands any bytes
//! read past the response head back to the caller for the frame layer.

use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::handshake::{client::generate_key, derive_accept_key};
use zeroize::{Zeroize, Zeroizing};

use super::error::WebSocketError;

/// Largest response head (status line, headers, and the blank line) accepted.
pub(super) const MAX_RESPONSE_HEAD_BYTES: usize = 8 * 1024;

/// Header slots offered to the response parser. More than this is refused.
const MAX_RESPONSE_HEADERS: usize = 64;
/// Read granularity while waiting for the response head.
const READ_CHUNK_BYTES: usize = 1024;
const HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";
const WSS_DEFAULT_PORT: u16 = 443;

/// A built upgrade request: the bytes to send and the key it must be answered
/// for. The bytes may hold the ticket, so they are `Zeroizing`, allocated at
/// their exact final size so no growth step leaves an unscrubbed older copy.
pub(super) struct UpgradeRequest {
    bytes: Zeroizing<Vec<u8>>,
    key: String,
}

impl std::fmt::Debug for UpgradeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpgradeRequest")
            .field("bytes", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl UpgradeRequest {
    /// Renders the upgrade request. `host`, `path`, and `query` are checked
    /// character by character, so no value can add a header or end the
    /// request early. Errors never repeat the offending text.
    ///
    /// Only the headers RFC 6455 requires are sent: no `Origin`, no `Cookie`,
    /// no subprotocol, no extension offer.
    pub(super) fn build(
        host: &str,
        port: u16,
        path: &str,
        query: Option<&str>,
    ) -> Result<Self, WebSocketError> {
        validate_host(host)?;
        validate_uri_text(path, UriPart::Path)?;
        if !path.starts_with('/') {
            return Err(invalid("websocket request path must be absolute"));
        }
        if let Some(query) = query {
            validate_uri_text(query, UriPart::Query)?;
        }
        let key = generate_key();
        let port_suffix = if port == WSS_DEFAULT_PORT {
            String::new()
        } else {
            format!(":{port}")
        };
        let query_prefix: &[u8] = if query.is_some() { b"?" } else { b"" };
        let parts: [&[u8]; 10] = [
            b"GET ",
            path.as_bytes(),
            query_prefix,
            query.unwrap_or_default().as_bytes(),
            b" HTTP/1.1\r\nHost: ",
            host.as_bytes(),
            port_suffix.as_bytes(),
            b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ",
            key.as_bytes(),
            b"\r\nSec-WebSocket-Version: 13\r\n\r\n",
        ];
        let total: usize = parts.iter().map(|part| part.len()).sum();
        let mut bytes = Zeroizing::new(Vec::with_capacity(total));
        for part in parts {
            bytes.extend_from_slice(part);
        }
        Ok(Self { bytes, key })
    }
}

fn invalid(reason: &str) -> WebSocketError {
    WebSocketError::InvalidUrl {
        reason: reason.to_string(),
    }
}

fn protocol(reason: &str) -> WebSocketError {
    WebSocketError::Protocol {
        reason: reason.to_string(),
    }
}

fn io_failure(error: &std::io::Error) -> WebSocketError {
    WebSocketError::Connect {
        reason: format!("i/o error ({:?})", error.kind()),
    }
}

/// A host is a DNS name, IPv4 literal, or bracketed IPv6 literal. Anything
/// else (whitespace, control characters, `/`, `@`, `?`, non-ASCII) is refused.
fn validate_host(host: &str) -> Result<(), WebSocketError> {
    let allowed = |byte: u8| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':' | b'[' | b']')
    };
    if host.is_empty() || host.len() > 255 || !host.bytes().all(allowed) {
        return Err(invalid("websocket host contains a forbidden character"));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum UriPart {
    Path,
    Query,
}

/// RFC 3986 `pchar` (plus `/`, and `?` in a query) and nothing else; `%` must
/// start a two-digit escape. The `#` fragment delimiter, spaces, controls,
/// non-ASCII, and the characters RFC 3986 excludes never pass.
fn validate_uri_text(text: &str, part: UriPart) -> Result<(), WebSocketError> {
    let reason = match part {
        UriPart::Path => "websocket request path contains a forbidden character",
        UriPart::Query => "websocket request query contains a forbidden character",
    };
    let bytes = text.as_bytes();
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let allowed = match byte {
            b'%' => {
                let escape = bytes.get(index + 1..index + 3);
                if !escape.is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)) {
                    return Err(invalid(reason));
                }
                index += 2;
                true
            }
            b'?' => matches!(part, UriPart::Query),
            byte => {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'-' | b'.'
                            | b'_'
                            | b'~'
                            | b'!'
                            | b'$'
                            | b'&'
                            | b'\''
                            | b'('
                            | b')'
                            | b'*'
                            | b'+'
                            | b','
                            | b';'
                            | b'='
                            | b':'
                            | b'@'
                            | b'/'
                    )
            }
        };
        if !allowed {
            return Err(invalid(reason));
        }
        index += 1;
    }
    Ok(())
}

/// Refuses a query the request line could not carry. The connector calls this
/// before any policy, DNS, or dial work so a bad query never costs a connection.
pub(super) fn validate_query(query: &str) -> Result<(), WebSocketError> {
    validate_uri_text(query, UriPart::Query)
}

/// Sends the request, then reads and validates the server's answer.
///
/// Returns the bytes the server sent after its response head. They belong to
/// the WebSocket frame layer and must be handed to it unchanged.
///
/// `deadline` bounds the whole exchange; the request buffer is overwritten
/// once it has been written, and again here on every exit path.
pub(super) async fn client_upgrade<S>(
    stream: &mut S,
    request: &mut UpgradeRequest,
    deadline: Duration,
) -> Result<Vec<u8>, WebSocketError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let outcome = tokio::time::timeout(deadline, exchange(stream, request)).await;
    request.bytes.as_mut_slice().zeroize();
    match outcome {
        Ok(result) => result,
        Err(_elapsed) => Err(WebSocketError::ConnectTimeout),
    }
}

async fn exchange<S>(
    stream: &mut S,
    request: &mut UpgradeRequest,
) -> Result<Vec<u8>, WebSocketError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let written = async {
        stream.write_all(&request.bytes).await?;
        stream.flush().await
    }
    .await;
    request.bytes.as_mut_slice().zeroize();
    written.map_err(|error| io_failure(&error))?;

    let mut buffered = Vec::with_capacity(MAX_RESPONSE_HEAD_BYTES + READ_CHUNK_BYTES);
    let mut scanned = 0;
    let head_len = loop {
        if let Some(end) = find_head_end(&buffered, scanned) {
            break end;
        }
        scanned = buffered.len().saturating_sub(HEAD_TERMINATOR.len() - 1);
        if buffered.len() >= MAX_RESPONSE_HEAD_BYTES {
            return Err(protocol("websocket handshake response head is too large"));
        }
        let mut chunk = [0u8; READ_CHUNK_BYTES];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| io_failure(&error))?;
        if read == 0 {
            return Err(WebSocketError::Connect {
                reason: "peer closed during the websocket handshake".to_string(),
            });
        }
        buffered.extend_from_slice(&chunk[..read]);
    };
    if head_len > MAX_RESPONSE_HEAD_BYTES {
        return Err(protocol("websocket handshake response head is too large"));
    }
    let leftover = buffered.split_off(head_len);
    validate_response(&buffered, &request.key)?;
    Ok(leftover)
}

/// Index just past the first `\r\n\r\n` at or after `from`.
fn find_head_end(buffered: &[u8], from: usize) -> Option<usize> {
    buffered
        .get(from..)?
        .windows(HEAD_TERMINATOR.len())
        .position(|window| window == HEAD_TERMINATOR)
        .map(|position| from + position + HEAD_TERMINATOR.len())
}

/// RFC 6455 section 4.2.2, from the client's side, plus the refusals this
/// client adds (it requested no subprotocol and no extension, and never
/// follows a redirect).
fn validate_response(head: &[u8], key: &str) -> Result<(), WebSocketError> {
    let mut slots = [httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
    let mut response = httparse::Response::new(&mut slots);
    let parsed = response.parse(head);
    // The status classifies a refusal even when the rest of a non-101 answer
    // is not parseable (a proxy's error page, say): the supervisor sorts a
    // 401/403 as a credential failure.
    if let Some(status) = response.code.filter(|status| *status != 101) {
        return Err(if (300..400).contains(&status) {
            WebSocketError::RedirectRejected { status }
        } else {
            WebSocketError::HandshakeRejected { status }
        });
    }
    match parsed {
        Ok(httparse::Status::Complete(length)) if length == head.len() => {}
        _ => return Err(protocol("malformed HTTP handshake")),
    }
    if response.version != Some(1) {
        return Err(protocol("websocket handshake needs an HTTP/1.1 response"));
    }
    let headers = response.headers;
    if !any_token(headers, "upgrade", "websocket") {
        return Err(protocol(
            "handshake response lacks the websocket Upgrade header",
        ));
    }
    if !any_token(headers, "connection", "upgrade") {
        return Err(protocol(
            "handshake response lacks the Upgrade Connection header",
        ));
    }
    let mut accepts = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("sec-websocket-accept"));
    let (Some(accept), None) = (accepts.next(), accepts.next()) else {
        return Err(protocol(
            "handshake response needs exactly one Sec-WebSocket-Accept",
        ));
    };
    let expected = derive_accept_key(key.as_bytes());
    if !bool::from(accept.value.trim_ascii().ct_eq(expected.as_bytes())) {
        return Err(protocol(
            "handshake response has a wrong Sec-WebSocket-Accept",
        ));
    }
    for unrequested in ["sec-websocket-extensions", "sec-websocket-protocol"] {
        if headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case(unrequested))
        {
            return Err(protocol(
                "handshake response negotiates something that was not requested",
            ));
        }
    }
    Ok(())
}

/// True when any header called `name` carries `token` in its comma-separated
/// list, compared case-insensitively.
fn any_token(headers: &[httparse::Header<'_>], name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .flat_map(|header| header.value.split(|byte| *byte == b','))
        .any(|candidate| {
            candidate
                .trim_ascii()
                .eq_ignore_ascii_case(token.as_bytes())
        })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures_util::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::{Message, handshake::derive_accept_key, protocol::Role};
    use zeroize::Zeroizing;

    use super::{MAX_RESPONSE_HEAD_BYTES, UpgradeRequest, client_upgrade};
    use crate::websocket::error::WebSocketError;

    const TICKET: &str = "SECRET_TICKET_123";
    const HOST: &str = "gateway.example.test";
    const LONG: Duration = Duration::from_secs(5);

    fn request() -> UpgradeRequest {
        UpgradeRequest::build(HOST, 443, "/connect", Some("ticket=SECRET_TICKET_123"))
            .expect("request builds")
    }

    /// Reads the client's request off the server half and returns its text.
    async fn read_request(server: &mut DuplexStream) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 256];
        while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = server.read(&mut chunk).await.expect("server read");
            assert!(read > 0, "client closed before finishing the request");
            buffer.extend_from_slice(&chunk[..read]);
        }
        String::from_utf8(buffer).expect("request is utf-8")
    }

    fn key_of(text: &str) -> String {
        text.lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("sec-websocket-key")
                    .then(|| value.trim().to_string())
            })
            .expect("request carries a key")
    }

    fn ok_head(key: &str, extra: &str) -> String {
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n{extra}\r\n",
            derive_accept_key(key.as_bytes())
        )
    }

    /// Runs one upgrade against a scripted server. `script` gets the server
    /// half and the key the client sent, and returns the bytes to drip back.
    async fn upgrade_with<F>(deadline: Duration, script: F) -> Result<Vec<u8>, WebSocketError>
    where
        F: FnOnce(
                DuplexStream,
                String,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + 'static,
    {
        let (mut client, mut server) = duplex(64 * 1024);
        let handle = tokio::spawn(async move {
            let text = read_request(&mut server).await;
            let key = key_of(&text);
            script(server, key).await;
        });
        let mut request = request();
        let outcome = client_upgrade(&mut client, &mut request, deadline).await;
        handle.abort();
        outcome
    }

    fn reply(
        bytes: Vec<u8>,
    ) -> impl FnOnce(
        DuplexStream,
        String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        move |mut server: DuplexStream, _key: String| {
            Box::pin(async move {
                let _ = server.write_all(&bytes).await;
                let _ = server.flush().await;
                std::future::pending::<()>().await;
            })
        }
    }

    fn assert_no_ticket(error: &WebSocketError) {
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains(TICKET), "{rendered}");
        assert!(!rendered.contains("ticket="), "{rendered}");
    }

    #[test]
    fn request_carries_exactly_the_required_headers() {
        let built = request();
        let text = String::from_utf8(built.bytes.to_vec()).expect("utf-8");
        let mut lines = text.split("\r\n");
        assert_eq!(
            lines.next(),
            Some("GET /connect?ticket=SECRET_TICKET_123 HTTP/1.1")
        );
        let mut names: Vec<String> = lines
            .filter(|line| !line.is_empty())
            .map(|line| {
                line.split(':')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "connection",
                "host",
                "sec-websocket-key",
                "sec-websocket-version",
                "upgrade"
            ]
        );
        assert!(text.contains("\r\nHost: gateway.example.test\r\n"));
        assert!(text.contains("\r\nUpgrade: websocket\r\n"));
        assert!(text.contains("\r\nConnection: Upgrade\r\n"));
        assert!(text.contains("\r\nSec-WebSocket-Version: 13\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        assert_eq!(built.key.len(), 24, "16 random bytes, base64");
        assert!(text.contains(&format!("Sec-WebSocket-Key: {}\r\n", built.key)));

        let other_port = UpgradeRequest::build(HOST, 8443, "/", None).expect("builds");
        let text = String::from_utf8(other_port.bytes.to_vec()).expect("utf-8");
        assert!(text.starts_with("GET / HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("\r\nHost: gateway.example.test:8443\r\n"));
        assert_ne!(
            built.key,
            UpgradeRequest::build(HOST, 443, "/", None)
                .expect("builds")
                .key,
            "every request draws a fresh key"
        );
    }

    #[test]
    fn request_construction_refuses_header_injection() {
        let bad_hosts = [
            "",
            "a b",
            "a\r\nX-Injected: 1",
            "a\tb",
            "ex\u{e9}.test",
            "a/b",
            "a@b",
            "a?b",
        ];
        for host in bad_hosts {
            assert!(
                matches!(
                    UpgradeRequest::build(host, 443, "/p", None),
                    Err(WebSocketError::InvalidUrl { .. })
                ),
                "host {host:?}"
            );
        }
        let bad_paths = [
            "",
            "p",
            "/a b",
            "/a\r\nX-Injected: 1",
            "/a\u{7f}",
            "/a#b",
            "//x\\y",
        ];
        for path in bad_paths {
            assert!(
                matches!(
                    UpgradeRequest::build(HOST, 443, path, None),
                    Err(WebSocketError::InvalidUrl { .. })
                ),
                "path {path:?}"
            );
        }
        let bad_queries = [
            "ticket=a b",
            "ticket=a\r\nX-Injected: 1",
            "ticket=a\nb",
            "ticket=a\u{0}b",
            "ticket=a#b",
            "ticket=\u{e9}",
            "ticket=%zz",
            "ticket=%4",
            "ticket=a\"b",
            "ticket=a<b",
        ];
        for query in bad_queries {
            match UpgradeRequest::build(HOST, 443, "/p", Some(query)) {
                Err(error @ WebSocketError::InvalidUrl { .. }) => {
                    let rendered = format!("{error} {error:?}");
                    assert!(!rendered.contains("ticket"), "query leaked: {rendered}");
                }
                other => panic!("query {query:?} must be refused, got {other:?}"),
            }
        }
        // Percent-encoded and sub-delimiter query text stays accepted.
        assert!(UpgradeRequest::build(HOST, 443, "/p", Some("a=%2F%20&b=c;d,e:f@g/h?i")).is_ok());
        assert!(UpgradeRequest::build(HOST, 443, "/p", Some("")).is_ok());
    }

    #[tokio::test]
    async fn the_request_buffer_is_zeroizing_and_overwritten_after_it_is_sent() {
        fn assert_zeroizing(_: &Zeroizing<Vec<u8>>) {}
        let (mut client, mut server) = duplex(64 * 1024);
        let mut built = request();
        assert_zeroizing(&built.bytes);
        let sent_len = built.bytes.len();
        assert!(sent_len > 0);
        let handle = tokio::spawn(async move {
            let text = read_request(&mut server).await;
            assert!(text.contains(TICKET), "the ticket reaches the wire");
            let key = key_of(&text);
            let _ = server.write_all(ok_head(&key, "").as_bytes()).await;
        });
        client_upgrade(&mut client, &mut built, LONG)
            .await
            .expect("upgrade succeeds");
        handle.await.expect("server task");
        assert_eq!(
            built.bytes.len(),
            sent_len,
            "buffer is overwritten in place"
        );
        assert!(
            built.bytes.iter().all(|byte| *byte == 0),
            "the request bytes must be zeroed once sent"
        );
    }

    #[tokio::test]
    async fn accepts_a_well_formed_101_with_case_insensitive_tokens() {
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: WebSocket\r\nCONNECTION: keep-alive, Upgrade\r\nsec-websocket-accept: {}\r\n\r\n",
            "{ACCEPT}"
        );
        let outcome = upgrade_with(LONG, move |mut server, key| {
            let head = head.replace("{ACCEPT}", &derive_accept_key(key.as_bytes()));
            Box::pin(async move {
                let _ = server.write_all(head.as_bytes()).await;
                std::future::pending::<()>().await;
            })
        })
        .await;
        assert_eq!(outcome.expect("valid 101"), Vec::<u8>::new());
    }

    #[tokio::test]
    async fn bytes_after_the_head_reach_the_frame_layer_when_they_arrive_in_the_same_read() {
        let (mut client, mut server) = duplex(64 * 1024);
        let mut built = request();
        let handle = tokio::spawn(async move {
            let text = read_request(&mut server).await;
            let key = key_of(&text);
            // Head plus a complete unmasked text frame ("hi") in one write.
            let mut bytes = ok_head(&key, "").into_bytes();
            bytes.extend_from_slice(&[0x81, 0x02, b'h', b'i']);
            let _ = server.write_all(&bytes).await;
            std::future::pending::<()>().await;
        });
        let leftover = client_upgrade(&mut client, &mut built, LONG)
            .await
            .expect("upgrade succeeds");
        assert_eq!(leftover, [0x81, 0x02, b'h', b'i']);
        let mut socket =
            WebSocketStream::from_partially_read(client, leftover, Role::Client, None).await;
        let message = tokio::time::timeout(LONG, socket.next())
            .await
            .expect("frame arrives")
            .expect("stream open")
            .expect("frame decodes");
        assert_eq!(message, Message::Text("hi".into()));
        handle.abort();
    }

    #[tokio::test]
    async fn a_head_dripped_one_byte_at_a_time_is_assembled_correctly() {
        let outcome = upgrade_with(LONG, |mut server, key| {
            let head = ok_head(&key, "").into_bytes();
            Box::pin(async move {
                for byte in head {
                    let _ = server.write_all(&[byte]).await;
                    let _ = server.flush().await;
                    tokio::task::yield_now().await;
                }
                std::future::pending::<()>().await;
            })
        })
        .await;
        assert_eq!(outcome.expect("valid 101 byte by byte"), Vec::<u8>::new());
    }

    #[tokio::test]
    async fn a_head_split_across_reads_keeps_the_frame_bytes_that_follow() {
        let (mut client, mut server) = duplex(64 * 1024);
        let mut built = request();
        let handle = tokio::spawn(async move {
            let text = read_request(&mut server).await;
            let key = key_of(&text);
            let head = ok_head(&key, "").into_bytes();
            let split = head.len() - 2; // inside the final CRLFCRLF
            let _ = server.write_all(&head[..split]).await;
            let _ = server.flush().await;
            tokio::task::yield_now().await;
            let mut rest = head[split..].to_vec();
            rest.extend_from_slice(&[0x81, 0x03, b'a', b'b', b'c']);
            let _ = server.write_all(&rest).await;
            std::future::pending::<()>().await;
        });
        let leftover = client_upgrade(&mut client, &mut built, LONG)
            .await
            .expect("upgrade succeeds");
        assert_eq!(leftover, [0x81, 0x03, b'a', b'b', b'c']);
        handle.abort();
    }

    #[tokio::test]
    async fn a_wrong_accept_value_is_refused() {
        for accept in ["AAAAAAAAAAAAAAAAAAAAAAAAAAA=", ""] {
            let head = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            let error = upgrade_with(LONG, reply(head.into_bytes()))
                .await
                .expect_err("wrong accept");
            assert!(
                matches!(error, WebSocketError::Protocol { .. }),
                "{error:?}"
            );
            assert_no_ticket(&error);
        }
    }

    #[tokio::test]
    async fn a_missing_or_duplicated_accept_is_refused() {
        let missing =
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let error = upgrade_with(LONG, reply(missing.as_bytes().to_vec()))
            .await
            .expect_err("no accept");
        assert!(
            matches!(error, WebSocketError::Protocol { .. }),
            "{error:?}"
        );

        let error = upgrade_with(LONG, |mut server, key| {
            let accept = derive_accept_key(key.as_bytes());
            let head = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            Box::pin(async move {
                let _ = server.write_all(head.as_bytes()).await;
                std::future::pending::<()>().await;
            })
        })
        .await
        .expect_err("two accept headers");
        assert!(
            matches!(error, WebSocketError::Protocol { .. }),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn missing_or_wrong_upgrade_and_connection_headers_are_refused() {
        for (upgrade, connection) in [
            (None, Some("Upgrade")),
            (Some("websocket"), None),
            (Some("h2c"), Some("Upgrade")),
            (Some("websocket"), Some("keep-alive")),
        ] {
            let error = upgrade_with(LONG, move |mut server, key| {
                let mut head = String::from("HTTP/1.1 101 Switching Protocols\r\n");
                if let Some(upgrade) = upgrade {
                    head.push_str(&format!("Upgrade: {upgrade}\r\n"));
                }
                if let Some(connection) = connection {
                    head.push_str(&format!("Connection: {connection}\r\n"));
                }
                head.push_str(&format!(
                    "Sec-WebSocket-Accept: {}\r\n\r\n",
                    derive_accept_key(key.as_bytes())
                ));
                Box::pin(async move {
                    let _ = server.write_all(head.as_bytes()).await;
                    std::future::pending::<()>().await;
                })
            })
            .await
            .expect_err("headers must be refused");
            assert!(
                matches!(error, WebSocketError::Protocol { .. }),
                "{upgrade:?}/{connection:?}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_status_other_than_101_is_a_rejected_handshake() {
        for status in [200u16, 204, 400, 401, 403, 404, 429, 500, 503] {
            let head = format!("HTTP/1.1 {status} Whatever\r\nContent-Length: 0\r\n\r\n");
            let error = upgrade_with(LONG, reply(head.into_bytes()))
                .await
                .expect_err("non-101");
            assert_eq!(error, WebSocketError::HandshakeRejected { status });
            assert_no_ticket(&error);
        }
    }

    #[tokio::test]
    async fn every_3xx_is_a_rejected_redirect_that_is_never_followed() {
        for status in [301u16, 302, 303, 307, 308] {
            let head = format!(
                "HTTP/1.1 {status} Moved\r\nLocation: wss://elsewhere.example.test/?{TICKET}\r\n\r\n"
            );
            let error = upgrade_with(LONG, reply(head.into_bytes()))
                .await
                .expect_err("redirect");
            assert_eq!(error, WebSocketError::RedirectRejected { status });
            assert_no_ticket(&error);
        }
    }

    #[tokio::test]
    async fn unrequested_extensions_or_subprotocols_are_refused() {
        for extra in [
            "Sec-WebSocket-Extensions: permessage-deflate\r\n",
            "sec-websocket-protocol: chat\r\n",
        ] {
            let error = upgrade_with(LONG, move |mut server, key| {
                let head = ok_head(&key, extra);
                Box::pin(async move {
                    let _ = server.write_all(head.as_bytes()).await;
                    std::future::pending::<()>().await;
                })
            })
            .await
            .expect_err("unrequested negotiation");
            assert!(
                matches!(error, WebSocketError::Protocol { .. }),
                "{extra}: {error:?}"
            );
            assert_no_ticket(&error);
        }
    }

    #[tokio::test]
    async fn malformed_or_non_http11_responses_are_refused() {
        for head in [
            "garbage\r\n\r\n",
            "HTTP/1.0 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\nBad Header Line\r\n\r\n",
        ] {
            let error = upgrade_with(LONG, reply(head.as_bytes().to_vec()))
                .await
                .expect_err("malformed");
            assert!(
                matches!(error, WebSocketError::Protocol { .. }),
                "{head:?}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_oversized_head_is_refused_with_or_without_a_terminator() {
        let filler = "X-Pad: ".to_string() + &"a".repeat(MAX_RESPONSE_HEAD_BYTES);
        // No terminator at all within the limit.
        let unterminated = format!("HTTP/1.1 101 Switching Protocols\r\n{filler}");
        let error = upgrade_with(LONG, reply(unterminated.into_bytes()))
            .await
            .expect_err("unterminated oversized head");
        assert!(
            matches!(error, WebSocketError::Protocol { .. }),
            "{error:?}"
        );
        // A terminator that sits beyond the limit is still too large.
        let terminated = format!("HTTP/1.1 101 Switching Protocols\r\n{filler}\r\n\r\n");
        let error = upgrade_with(LONG, reply(terminated.into_bytes()))
            .await
            .expect_err("terminated oversized head");
        assert!(
            matches!(error, WebSocketError::Protocol { .. }),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_peer_that_stalls_mid_head_hits_the_deadline() {
        let error = upgrade_with(Duration::from_millis(150), |mut server, _key| {
            Box::pin(async move {
                let _ = server.write_all(b"HTTP/1.1 101 Switching").await;
                std::future::pending::<()>().await;
            })
        })
        .await
        .expect_err("slow-loris head");
        assert_eq!(error, WebSocketError::ConnectTimeout);
    }

    #[tokio::test]
    async fn a_peer_that_closes_before_finishing_the_head_is_a_connect_failure() {
        let error = upgrade_with(LONG, |mut server, _key| {
            Box::pin(async move {
                let _ = server.write_all(b"HTTP/1.1 101").await;
                drop(server);
            })
        })
        .await
        .expect_err("early close");
        assert!(matches!(error, WebSocketError::Connect { .. }), "{error:?}");
        assert_no_ticket(&error);
    }
}
