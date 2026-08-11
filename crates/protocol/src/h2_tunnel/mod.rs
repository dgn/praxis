// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! `H2` CONNECT tunnel.
//!
//! An `h2_tunnel` listener is an ordinary stream listener: Pingora accepts
//! the connection on the same [`Service`] that serves raw TCP listeners, and
//! the chain's [`H2TunnelFilter`] connection filter takes it over, performs
//! the HTTP/2 handshake, and demuxes each CONNECT stream into a
//! bidirectional tunnel. Framing therefore lives in a filter rather than in a
//! second protocol adapter, and the tunnel inherits everything the TCP
//! service already provides: admission control, `max_connections`, listener
//! metrics, TLS with hot-reloadable pipelines, and the SSRF-guarded
//! [`DirectConnector`].
//!
//! [`Service`]: pingora_core::services::listening::Service
//! [`DirectConnector`]: crate::DirectConnector
//! [`H2TunnelFilter`]: crate::h2_tunnel::H2TunnelFilter

/// `H2` CONNECT tunnel as a [`ConnectionFilter`](praxis_filter::ConnectionFilter).
mod filter;

pub use filter::H2TunnelFilter;

/// Headers from an `H2` CONNECT request, inserted into [`TcpFilterContext::extensions`]
/// by [`H2TunnelFilter`].
///
/// Filters can retrieve protocol-specific headers (e.g. `x-original-src`)
/// via `ctx.extensions.get::<H2ConnectHeaders>()`.
///
/// [`TcpFilterContext::extensions`]: praxis_filter::TcpFilterContext::extensions
/// [`H2TunnelFilter`]: crate::h2_tunnel::H2TunnelFilter
#[derive(Clone)]
pub struct H2ConnectHeaders(pub http::HeaderMap);
