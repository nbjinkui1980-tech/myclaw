//! Outbound rendering: DingTalk robot message parameters and chunking.
//!
//! `msgKey`/`msgParam` shapes follow the examples in the official Go SDK
//! (`alibabacloud-go/dingtalk`, `robot_1_0/client.go`): `sampleText` carries
//! `{"content"}`; `msgParam` is a JSON **string**. Markdown is not a declared
//! surface (`supports_markdown = false`), so no markdown renderer exists. The per-message length limit is
//! UNVERIFIED (ADR §8 item 6), so [`MAX_CHUNK_CHARS`] is a conservative host-side choice.
use serde_json::json;

/// Largest chunk, counted in Unicode scalar values (never bytes).
pub(crate) const MAX_CHUNK_CHARS: usize = 3_000;

pub(crate) const TEXT_MSG_KEY: &str = "sampleText";

/// Split `text` into chunks of at most [`MAX_CHUNK_CHARS`] characters, always
/// on character boundaries. Empty input yields no chunks.
pub(crate) fn chunk_text(text: &str) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let end = rest
            .char_indices()
            .nth(MAX_CHUNK_CHARS)
            .map_or(rest.len(), |(index, _)| index);
        let (chunk, tail) = rest.split_at(end);
        chunks.push(chunk);
        rest = tail;
    }
    chunks
}

/// `msgParam` for `sampleText`.
pub(crate) fn render_text_param(content: &str) -> String {
    json!({ "content": content }).to_string()
}
