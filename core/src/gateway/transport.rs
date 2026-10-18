//! Bound the SDK's line buffer and reject lossy SDK catalog decoding. The SDK
//! still owns MCP framing, correlation, protocol negotiation and dispatch.
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};
pub(super) struct LimitedRead<R> {
    inner: R,
    line: Vec<u8>,
}
impl<R> LimitedRead<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            line: Vec::new(),
        }
    }
}
fn validate_catalog(bytes: &[u8]) -> std::io::Result<()> {
    let invalid = || std::io::Error::other("unsupported MCP catalog representation");
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Ok(());
    };
    if let Some(tools) = value.get("result").and_then(|r| r.get("tools")) {
        let tools = tools.as_array().ok_or_else(invalid)?;
        let typed = tools
            .iter()
            .map(|raw| {
                let tool: rmcp::model::Tool =
                    serde_json::from_value(raw.clone()).map_err(|_| invalid())?;
                serde_json::to_value(tool).map_err(|_| invalid())
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        // In particular rmcp ignores unknown annotation keys and explicit nulls.
        // Refuse those forms rather than silently omit part of the security pin.
        if super::canonical_tools(tools).map_err(|_| invalid())?
            != super::canonical_tools(&typed).map_err(|_| invalid())?
        {
            return Err(invalid());
        }
    }
    Ok(())
}
impl<R: AsyncRead + Unpin> AsyncRead for LimitedRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                let valid = (|| -> std::io::Result<()> {
                    if buffer.filled().len() == before && !self.line.is_empty() {
                        validate_catalog(&self.line)?;
                        self.line.clear();
                    }
                    for byte in &buffer.filled()[before..] {
                        if *byte == b'\n' {
                            validate_catalog(&self.line)?;
                            self.line.clear();
                        } else {
                            if self.line.len() >= 16 * 1024 * 1024 {
                                return Err(std::io::Error::other("MCP frame too large"));
                            }
                            self.line.push(*byte);
                        }
                    }
                    Ok(())
                })();
                if valid.is_err() {
                    // AsyncRead must not report initialized bytes alongside an error.
                    buffer.set_filled(before);
                }
                Poll::Ready(valid)
            }
            other => other,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn catalogs_never_silently_drop_approved_fields() {
        let mut value = json!({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","inputSchema":{},"annotations":{"title":"safe"}}]}});
        assert!(validate_catalog(&serde_json::to_vec(&value).unwrap()).is_ok());
        value["result"]["tools"][0]["annotations"]["unknownSecurityHint"] = json!(true);
        assert!(validate_catalog(&serde_json::to_vec(&value).unwrap()).is_err());
        value["result"]["tools"][0]["annotations"] = serde_json::Value::Null;
        assert!(validate_catalog(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[tokio::test]
    async fn final_catalog_without_newline_is_also_guarded() {
        use tokio::io::AsyncReadExt;
        let frame = br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","inputSchema":{},"annotations":{"unknownSecurityHint":true}}]}}"#;
        let mut reader = LimitedRead::new(std::io::Cursor::new(frame));
        assert!(reader.read_to_end(&mut Vec::new()).await.is_err());
    }
    #[tokio::test]
    async fn frame_limit_applies_across_reads() {
        use tokio::io::AsyncReadExt;
        let data = std::io::Cursor::new(vec![b'x'; 16 * 1024 * 1024 + 1]);
        let mut limited = LimitedRead::new(data);
        let mut sink = Vec::new();
        assert!(limited.read_to_end(&mut sink).await.is_err());
    }
}
