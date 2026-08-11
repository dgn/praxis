// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Connection-level filters that own a raw stream.
//!
//! A [`ConnectionFilter`] is handed the accepted connection before any request
//! or byte is forwarded, so it can frame the transport (TLS, PROXY protocol) or
//! multiplex logical streams over it (`H2` CONNECT). Filters form a chain: a
//! wrapping filter transforms the stream and calls
//! [`ConnectionRuntime::next`], while a multiplexing filter runs the pipeline
//! once per logical stream.

use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;

use crate::{connector::UpstreamConnector, filter::FilterError, io::BoxedIo, pipeline::FilterPipeline};

/// Owned per-connection state backing the lifetime of
/// [`TcpFilterContext`](crate::TcpFilterContext) borrows.
pub struct ConnectionContext {
    /// Remote client address as a string (e.g. "10.0.0.1:12345").
    pub remote_addr: String,
    /// Local listener address as a string.
    pub local_addr: String,
    /// Authenticated peer identity (e.g. SPIFFE URI) from the mTLS handshake.
    pub peer_identity: Option<String>,
}

/// Runtime services available to a [`ConnectionFilter`] during `serve()`.
pub struct ConnectionRuntime<'a> {
    /// Sub-pipeline of TCP/HTTP filters to run per logical stream.
    pub pipeline: &'a FilterPipeline,

    /// Pluggable upstream connector.
    pub connector: &'a dyn UpstreamConnector,

    /// Shutdown signal.
    pub shutdown: watch::Receiver<bool>,

    /// Deadline for one logical session, from the listener's
    /// `tcp_session_timeout_ms`.
    ///
    /// A multiplexing filter applies it per logical stream, the same way the
    /// TCP proxy applies it to the connection it forwards.
    pub session_timeout: Option<Duration>,

    /// Hard cap on one logical session, from the listener's
    /// `tcp_max_duration_secs`.
    pub max_duration: Option<Duration>,

    /// Remaining connection filters in the chain (after this one).
    remaining_filters: &'a [Box<dyn ConnectionFilter>],
}

impl<'a> ConnectionRuntime<'a> {
    /// Create a new runtime with the given connection filter chain tail.
    #[expect(clippy::too_many_arguments, reason = "per-connection services and session limits")]
    pub fn new(
        pipeline: &'a FilterPipeline,
        connector: &'a dyn UpstreamConnector,
        shutdown: watch::Receiver<bool>,
        session_timeout: Option<Duration>,
        max_duration: Option<Duration>,
        remaining_filters: &'a [Box<dyn ConnectionFilter>],
    ) -> Self {
        Self {
            pipeline,
            connector,
            shutdown,
            session_timeout,
            max_duration,
            remaining_filters,
        }
    }

    /// Invoke the next connection filter in the chain with a (possibly transformed) stream.
    ///
    /// Wrapping filters (TLS, PROXY protocol) call this after transforming the stream.
    ///
    /// # Errors
    ///
    /// Returns a [`FilterError`] when the chain has no remaining filter to
    /// invoke, or when the invoked filter reports a connection-level failure.
    pub async fn next(&self, stream: BoxedIo, ctx: ConnectionContext) -> Result<(), FilterError> {
        let (head, tail) = self
            .remaining_filters
            .split_first()
            .ok_or_else(|| FilterError::from("no remaining connection filters in chain"))?;

        let child_runtime = ConnectionRuntime {
            pipeline: self.pipeline,
            connector: self.connector,
            shutdown: self.shutdown.clone(),
            session_timeout: self.session_timeout,
            max_duration: self.max_duration,
            remaining_filters: tail,
        };

        head.serve(stream, ctx, &child_runtime).await
    }

    /// Whether there are more connection filters after the current one.
    pub fn has_next(&self) -> bool {
        !self.remaining_filters.is_empty()
    }
}

/// A filter that takes over a raw connection for protocol framing.
///
/// Connection filters handle protocol-level concerns (H2 CONNECT demux,
/// TLS termination, PROXY protocol) and run the sub-pipeline per logical
/// stream or request.
///
/// Two kinds of connection filters:
/// - **Wrapping** (TLS, PROXY protocol): transform the stream, call `runtime.next()`
/// - **Multiplexing** (H2 CONNECT): spawn sub-streams, run sub-pipeline per stream
#[async_trait]
pub trait ConnectionFilter: Send + Sync {
    /// Unique name identifying this filter type.
    fn name(&self) -> &'static str;

    /// Take ownership of the connection and serve it.
    ///
    /// Returning `Err` means the connection itself failed (H2 GOAWAY, TLS alert).
    /// Per-stream errors should be handled internally.
    async fn serve(
        &self,
        stream: BoxedIo,
        ctx: ConnectionContext,
        runtime: &ConnectionRuntime<'_>,
    ) -> Result<(), FilterError>;
}
