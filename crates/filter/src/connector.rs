// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pluggable upstream transport for connection filters.

use async_trait::async_trait;

use crate::{io::BoxedIo, tcp_filter::TcpFilterContext};

/// Pluggable upstream connection strategy.
///
/// The protocol crate supplies the default `DirectConnector`, which resolves
/// [`TcpFilterContext::upstream_addr`] (falling back to
/// [`TcpFilterContext::original_dst`]) and opens a plain TCP socket. Downstream
/// projects can supply connectors for network-namespace awareness, connection
/// pooling, or alternative transports.
///
/// A connector is a transport, not a policy exit: it is handed the resolved
/// address and is expected to honor the same private-address posture as the
/// built-in upstream path (see `praxis_core::connectivity`). Implementors that
/// resolve a hostname must re-check the resolved address, or they become an
/// SSRF path around the checks the rest of the proxy performs.
#[async_trait]
pub trait UpstreamConnector: Send + Sync {
    /// Open a connection to the upstream, returning a type-erased IO stream.
    async fn connect(&self, ctx: &TcpFilterContext<'_>) -> std::io::Result<BoxedIo>;
}
