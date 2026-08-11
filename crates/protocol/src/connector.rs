// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Default [`UpstreamConnector`] implementation.

use async_trait::async_trait;
use praxis_filter::{BoxedIo, TcpFilterContext, UpstreamConnector};

use crate::tcp::proxy::connect_upstream;

/// Default upstream connector that opens a direct TCP connection.
///
/// Tries [`TcpFilterContext::upstream_addr`] first, then falls back to
/// [`TcpFilterContext::original_dst`].
pub struct DirectConnector {
    /// Allow upstream connections to private/reserved IP addresses
    /// (`insecure_options.allow_private_upstreams`).
    allow_private_upstreams: bool,
}

impl DirectConnector {
    /// Create a connector honoring `insecure_options.allow_private_upstreams`.
    pub const fn new(allow_private_upstreams: bool) -> Self {
        Self {
            allow_private_upstreams,
        }
    }
}

#[async_trait]
impl UpstreamConnector for DirectConnector {
    async fn connect(&self, ctx: &TcpFilterContext<'_>) -> std::io::Result<BoxedIo> {
        // The address can come from a filter that read it off the wire (an
        // `H2` CONNECT authority, a PROXY protocol header), so it goes
        // through the same resolve + private-address guard as the built-in
        // TCP proxy rather than a bare `TcpStream::connect`.
        if let Some(addr) = ctx.upstream_addr.as_deref() {
            return connect_upstream(addr, self.allow_private_upstreams)
                .await
                .map(|stream| -> BoxedIo { Box::new(stream) })
                .ok_or_else(|| std::io::Error::other(format!("upstream {addr} connect failed")));
        }

        // `SO_ORIGINAL_DST` was chosen by the operator's REDIRECT rules, not
        // by the client, so it is not an SSRF surface and needs no guard.
        if let Some(dst) = ctx.original_dst {
            return connect_upstream(&dst.to_string(), true)
                .await
                .map(|stream| -> BoxedIo { Box::new(stream) })
                .ok_or_else(|| std::io::Error::other(format!("original destination {dst} connect failed")));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no upstream address or original destination",
        ))
    }
}
