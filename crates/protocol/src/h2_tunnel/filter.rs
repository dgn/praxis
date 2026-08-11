// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! `H2` CONNECT tunnel as a [`ConnectionFilter`].
//!
//! Runs on an ordinary `h2_tunnel` TCP listener: the filter takes the
//! accepted connection, performs the HTTP/2 handshake, and demuxes each
//! CONNECT stream into a bidirectional tunnel. Per stream it runs the
//! chain's TCP sub-pipeline — so `tcp_access_log`, ACLs, and metrics behave
//! as they do for a raw TCP session — connects through the runtime's
//! [`UpstreamConnector`], and relays under HTTP/2 flow control.
//!
//! The filter takes no configuration of its own. Session limits come from
//! the listener (`tcp_session_timeout_ms`, `tcp_max_duration_secs`) and
//! apply per CONNECT stream, the same way they apply per connection to the
//! built-in TCP proxy.
//!
//! # YAML configuration
//!
//! ```yaml
//! listeners:
//!   - name: tunnel
//!     address: "0.0.0.0:15008"
//!     protocol: h2_tunnel
//!     filter_chains: [tunnels]
//!
//! filter_chains:
//!   - name: tunnels
//!     connection_filters:
//!       - filter: h2_tunnel
//!     filters:
//!       - filter: tcp_access_log
//! ```
//!
//! [`ConnectionFilter`]: praxis_filter::ConnectionFilter
//! [`UpstreamConnector`]: praxis_filter::UpstreamConnector

use std::{borrow::Cow, future::poll_fn, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use futures::{StreamExt as _, stream::FuturesUnordered};
use praxis_filter::{
    BoxedIo, ConnectionContext, ConnectionFilter, ConnectionRuntime, EmptyFilterConfig, FilterAction, FilterError,
    TcpFilterContext, parse_filter_config,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tracing::{debug, warn};

use super::H2ConnectHeaders;
use crate::tcp::proxy::release_selected_endpoint;

/// Relay copy buffer size (16 KiB).
const RELAY_BUF_SIZE: usize = 16 * 1024;

/// Connection filter that demuxes `H2` CONNECT streams.
///
/// Performs the HTTP/2 handshake on the raw connection, accepts CONNECT
/// requests, and runs the TCP sub-pipeline per logical stream.
pub struct H2TunnelFilter;

impl H2TunnelFilter {
    /// Create from YAML config.
    ///
    /// Accepts no options; see the [module docs](crate::h2_tunnel) for the listener
    /// fields that bound a tunnel session.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the config contains unknown keys.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn ConnectionFilter>, FilterError> {
        let _: EmptyFilterConfig = parse_filter_config("h2_tunnel", config)?;
        Ok(Box::new(Self))
    }

    /// Handle a single CONNECT stream through the filter pipeline.
    #[expect(
        clippy::too_many_lines,
        reason = "linear stream lifecycle: validate, filter, connect, relay, disconnect"
    )]
    async fn handle_stream(
        request: http::Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
        conn_ctx: &ConnectionContext,
        runtime: &ConnectionRuntime<'_>,
    ) {
        if request.method() != http::Method::CONNECT {
            send_error(&mut respond, 405);
            return;
        }

        let authority = extract_authority(request.uri(), request.headers());
        if authority.is_empty() {
            send_error(&mut respond, 400);
            return;
        }

        let connect_time = std::time::Instant::now();
        let headers = H2ConnectHeaders(request.headers().clone());
        let health_registry = runtime.pipeline.health_registry().cloned();

        let mut ctx = TcpFilterContext {
            remote_addr: &conn_ctx.remote_addr,
            local_addr: &conn_ctx.local_addr,
            sni: None,
            upstream_addr: Some(Cow::Borrowed(&authority)),
            // The CONNECT authority is the routing decision, so there is no
            // listener cluster to select a load-balancing strategy from.
            cluster: None,
            health_registry: health_registry.as_ref(),
            kv_stores: runtime.pipeline.kv_stores(),
            original_dst: None,
            connect_time,
            bytes_in: 0,
            bytes_out: 0,
            peer_identity: conn_ctx.peer_identity.as_deref(),
            extensions: http::Extensions::new(),
        };
        ctx.extensions.insert(headers);

        // Every action but `Reject` lets the stream proceed, as in the TCP
        // proxy: a stream has no response body to return, so a terminal
        // action from a sub-pipeline filter carries no meaning here.
        match runtime.pipeline.execute_tcp_connect(&mut ctx).await {
            Ok(
                FilterAction::Continue
                | FilterAction::Release
                | FilterAction::BodyDone
                | FilterAction::TerminalResponse(_)
                | FilterAction::StreamingTerminalResponse(_),
            ) => {},
            Ok(FilterAction::Reject(r)) => {
                warn!(
                    remote = %conn_ctx.remote_addr,
                    status = r.status,
                    "H2 tunnel stream rejected by filter"
                );
                release_selected_endpoint(runtime.pipeline, &mut ctx).await;
                send_error(&mut respond, 403);
                return;
            },
            Err(e) => {
                warn!(
                    remote = %conn_ctx.remote_addr,
                    error = %e,
                    "H2 tunnel connect filter error"
                );
                release_selected_endpoint(runtime.pipeline, &mut ctx).await;
                send_error(&mut respond, 500);
                return;
            },
        }

        let upstream = match runtime.connector.connect(&ctx).await {
            Ok(s) => s,
            Err(e) => {
                let addr = ctx.upstream_addr.as_deref().unwrap_or("unknown");
                warn!(upstream = %addr, error = %e, "H2 tunnel upstream connect failed");
                send_error(&mut respond, 502);
                return;
            },
        };

        let Some(send_stream) = send_ok(&mut respond) else {
            return;
        };
        let recv_stream = request.into_body();

        let (bytes_in, bytes_out) = relay_with_limits(
            runtime.session_timeout,
            runtime.max_duration,
            send_stream,
            recv_stream,
            upstream,
        )
        .await;

        ctx.bytes_in = bytes_in;
        ctx.bytes_out = bytes_out;
        drop(runtime.pipeline.execute_tcp_disconnect(&mut ctx).await);
    }
}

#[async_trait]
impl ConnectionFilter for H2TunnelFilter {
    fn name(&self) -> &'static str {
        "h2_tunnel"
    }

    #[expect(
        clippy::large_stack_frames,
        reason = "one inlined stream handler per accepted connection"
    )]
    async fn serve(
        &self,
        stream: BoxedIo,
        ctx: ConnectionContext,
        runtime: &ConnectionRuntime<'_>,
    ) -> Result<(), FilterError> {
        let mut conn = h2::server::handshake(stream)
            .await
            .map_err(|e| -> FilterError { format!("H2 handshake failed: {e}").into() })?;

        let mut shutdown_rx = runtime.shutdown.clone();
        let mut streams = FuturesUnordered::new();

        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => break,
                Some(_) = streams.next(), if !streams.is_empty() => {},
                result = conn.accept() => match result {
                    Some(Ok((req, resp))) => {
                        streams.push(H2TunnelFilter::handle_stream(req, resp, &ctx, runtime));
                    }
                    Some(Err(e)) => {
                        debug!(error = %e, "H2 tunnel accept error");
                        break;
                    }
                    None => break,
                },
            }
        }

        // Drain remaining in-flight streams.
        while streams.next().await.is_some() {}
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Relay with backpressure-aware H2 flow control
// -----------------------------------------------------------------------------

/// Relay one stream under the listener's session limits.
///
/// Mirrors the built-in TCP proxy: `session_timeout` bounds the exchange and
/// `max_duration` caps it from above. Both apply to a single CONNECT stream,
/// not to the HTTP/2 connection carrying it. A stream cut short by either
/// limit reports zero bytes, because the relay halves are cancelled before
/// they can report totals.
async fn relay_with_limits(
    session_timeout: Option<Duration>,
    max_duration: Option<Duration>,
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    upstream: BoxedIo,
) -> (u64, u64) {
    let within_session_timeout = async {
        let relay = relay_h2_io(send, recv, upstream);
        match session_timeout {
            Some(timeout) => tokio::time::timeout(timeout, relay).await.ok().and_then(Result::ok),
            None => relay.await.ok(),
        }
    };

    let relayed = match max_duration {
        Some(max_dur) => tokio::time::timeout(max_dur, within_session_timeout)
            .await
            .ok()
            .flatten(),
        None => within_session_timeout.await,
    };

    relayed.unwrap_or((0, 0))
}

/// Relay data bidirectionally between an `H2` CONNECT stream and an upstream IO stream.
///
/// Waits for `H2` flow control capacity via `poll_capacity()` before calling
/// `send_data()`, so a stalled peer applies backpressure to the opposite
/// direction instead of letting data accumulate in the `H2` send queue.
async fn relay_h2_io(
    h2_send: h2::SendStream<Bytes>,
    h2_recv: h2::RecvStream,
    upstream: BoxedIo,
) -> std::io::Result<(u64, u64)> {
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let (bytes_in, bytes_out) = tokio::join!(
        relay_h2_to_io(h2_recv, upstream_write),
        relay_io_to_h2(upstream_read, h2_send),
    );

    let bytes_in = bytes_in.unwrap_or(0);
    let bytes_out = bytes_out.unwrap_or(0);
    debug!(bytes_in, bytes_out, "h2 tunnel relay complete");
    Ok((bytes_in, bytes_out))
}

/// Forward data from an H2 receive stream to an upstream writer.
async fn relay_h2_to_io(
    mut h2_recv: h2::RecvStream,
    mut writer: tokio::io::WriteHalf<BoxedIo>,
) -> Result<u64, std::io::Error> {
    let mut total = 0_u64;
    loop {
        match h2_recv.data().await {
            Some(Ok(chunk)) => {
                let len = chunk.len();
                drop(h2_recv.flow_control().release_capacity(len));
                writer.write_all(&chunk).await?;
                total += len as u64;
            },
            Some(Err(e)) => return Err(std::io::Error::other(e)),
            None => break,
        }
    }
    drop(writer.shutdown().await);
    Ok(total)
}

/// Forward data from an upstream reader to an H2 send stream.
///
/// Waits for H2 flow control capacity before sending, so a stalled downstream
/// peer stops this read loop — and therefore the upstream socket — rather than
/// buffering the unread data in the H2 send queue.
async fn relay_io_to_h2(
    mut reader: tokio::io::ReadHalf<BoxedIo>,
    mut h2_send: h2::SendStream<Bytes>,
) -> Result<u64, std::io::Error> {
    let mut total = 0_u64;
    let mut buf = vec![0_u8; RELAY_BUF_SIZE];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            drop(h2_send.send_data(Bytes::new(), true));
            break;
        }

        send_with_flow_control(&mut h2_send, &buf, n).await?;
        total += n as u64;
    }
    Ok(total)
}

/// Send `buf[..n]` on an `H2` stream, waiting for flow control capacity.
///
/// Capacity is requested for the bytes still pending and consumed
/// incrementally. `send_data()` on its own would queue anything larger than the
/// current window, so waiting here is what bounds the relay's memory and makes
/// a stalled peer pay for its own backlog.
async fn send_with_flow_control(
    h2_send: &mut h2::SendStream<Bytes>,
    buf: &[u8],
    n: usize,
) -> Result<(), std::io::Error> {
    let mut sent = 0;
    while sent < n {
        h2_send.reserve_capacity(n - sent);
        let capacity = poll_fn(|cx| h2_send.poll_capacity(cx))
            .await
            .ok_or_else(|| std::io::Error::other("h2 stream closed during send"))?
            .map_err(std::io::Error::other)?;
        if capacity == 0 {
            continue;
        }
        let end = std::cmp::min(sent + capacity, n);
        let chunk = buf
            .get(sent..end)
            .ok_or_else(|| std::io::Error::other("h2 send window past the read buffer"))?;
        h2_send
            .send_data(Bytes::copy_from_slice(chunk), false)
            .map_err(std::io::Error::other)?;
        sent = end;
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Extract the CONNECT target authority from the request.
///
/// Takes the URI and headers rather than the request so the fallback order is
/// testable without a live `H2` stream.
fn extract_authority(uri: &http::Uri, headers: &http::HeaderMap) -> String {
    uri.authority()
        .map(ToString::to_string)
        .or_else(|| headers.get("host").and_then(|v| v.to_str().ok()).map(String::from))
        .unwrap_or_default()
}

/// Send an H2 error response and end the stream.
fn send_error(respond: &mut h2::server::SendResponse<Bytes>, status: u16) {
    if let Ok(response) = http::Response::builder().status(status).body(()) {
        drop(respond.send_response(response, true));
    }
}

/// Send a 200 OK response and return the send stream for relaying.
fn send_ok(respond: &mut h2::server::SendResponse<Bytes>) -> Option<h2::SendStream<Bytes>> {
    let response = http::Response::builder().status(200).body(()).ok()?;
    respond.send_response(response, false).ok()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::map_with_unused_argument_over_ranges,
    clippy::panic,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use praxis_filter::{FilterFactory, FilterPipeline, FilterRegistry, Rejection, UpstreamConnector};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    // -----------------------------------------------------------------------
    // Harness
    // -----------------------------------------------------------------------

    /// Connector handing out pre-made sockets in order and recording the
    /// address each CONNECT asked to be dialed. An exhausted queue stands in
    /// for an unreachable upstream.
    struct StubConnector {
        handed: Mutex<VecDeque<BoxedIo>>,
        dialed: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl UpstreamConnector for StubConnector {
        async fn connect(&self, ctx: &TcpFilterContext<'_>) -> std::io::Result<BoxedIo> {
            self.dialed
                .lock()
                .unwrap()
                .push(ctx.upstream_addr.as_deref().unwrap_or("<none>").to_owned());
            self.handed
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| std::io::Error::other("stub connector exhausted"))
        }
    }

    /// One `H2` tunnel connection under test: an `h2` client on one end of a
    /// duplex socket, [`H2TunnelFilter::serve`] on the other, and the peers of
    /// the sockets the runtime's connector handed out as upstreams.
    struct Tunnel {
        client: h2::client::SendRequest<Bytes>,
        upstreams: Vec<tokio::io::DuplexStream>,
        dialed: Arc<Mutex<Vec<String>>>,
        serve: tokio::task::JoinHandle<()>,
        shutdown: tokio::sync::watch::Sender<bool>,
    }

    impl Tunnel {
        /// Tunnel with one live upstream socket and no session limits.
        async fn start(pipeline: FilterPipeline) -> Self {
            Self::build(pipeline, None, None, 1).await
        }

        /// Tunnel over `upstreams` upstream sockets; `0` makes every
        /// upstream connect fail.
        async fn build(
            pipeline: FilterPipeline,
            session_timeout: Option<Duration>,
            max_duration: Option<Duration>,
            upstreams: usize,
        ) -> Self {
            let (handed, peers): (VecDeque<BoxedIo>, Vec<_>) = (0..upstreams)
                .map(|_| {
                    let (for_filter, peer) = tokio::io::duplex(64 * 1024);
                    let boxed: BoxedIo = Box::new(for_filter);
                    (boxed, peer)
                })
                .unzip();
            let mut tunnel = Self::spawn(pipeline, handed, session_timeout, max_duration).await;
            tunnel.upstreams = peers;
            tunnel
        }

        /// Tunnel whose connector hands out `handed`, in order. Lets a test
        /// supply an upstream whose two directions it can close separately.
        async fn spawn(
            pipeline: FilterPipeline,
            handed: VecDeque<BoxedIo>,
            session_timeout: Option<Duration>,
            max_duration: Option<Duration>,
        ) -> Self {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let dialed = Arc::new(Mutex::new(Vec::new()));
            let connector = StubConnector {
                handed: Mutex::new(handed),
                dialed: Arc::clone(&dialed),
            };
            let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);

            let serve = tokio::spawn(async move {
                let runtime =
                    ConnectionRuntime::new(&pipeline, &connector, shutdown_rx, session_timeout, max_duration, &[]);
                let ctx = ConnectionContext {
                    remote_addr: "192.0.2.7:9999".to_owned(),
                    local_addr: "127.0.0.1:15008".to_owned(),
                    peer_identity: None,
                };
                let stream: BoxedIo = Box::new(server_io);
                drop(H2TunnelFilter.serve(stream, ctx, &runtime).await);
            });

            let (client, conn) = h2::client::handshake(client_io).await.expect("h2 client handshake");
            tokio::spawn(async move {
                drop(conn.await);
            });

            Self {
                client,
                upstreams: Vec::new(),
                dialed,
                serve,
                shutdown,
            }
        }

        /// Open a CONNECT stream at `authority`, returning its response status
        /// and the two stream halves.
        async fn connect(&mut self, authority: &str) -> (u16, h2::SendStream<Bytes>, h2::RecvStream) {
            let request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri(format!("http://{authority}"))
                .header("x-role", "edge")
                .body(())
                .expect("build CONNECT request");
            let (response, send) = self.client.send_request(request, false).expect("send CONNECT request");
            let response = response.await.expect("CONNECT response");
            (response.status().as_u16(), send, response.into_body())
        }

        /// Status of a request that is not a CONNECT.
        async fn get_status(&mut self) -> u16 {
            let request = http::Request::get("http://example.invalid/")
                .body(())
                .expect("build GET request");
            let (response, _send) = self.client.send_request(request, true).expect("send GET request");
            response.await.expect("GET response").status().as_u16()
        }

        /// The addresses the connector was asked to dial, in call order.
        fn dialed(&self) -> Vec<String> {
            self.dialed.lock().unwrap().clone()
        }
    }

    /// Build a pipeline from the named filters, registering each with the
    /// supplied hook before the build.
    fn pipeline_with(names: &[&str], register: impl FnOnce(&mut FilterRegistry)) -> FilterPipeline {
        let mut registry = FilterRegistry::with_builtins();
        register(&mut registry);
        let yaml: String = names.iter().map(|name| format!("- filter: {name}\n")).collect();
        let mut entries: Vec<praxis_core::config::FilterEntry> = serde_yaml::from_str(&yaml).unwrap();
        FilterPipeline::build(&mut entries, &registry).unwrap()
    }

    fn empty_pipeline() -> FilterPipeline {
        pipeline_with(&[], |_| {})
    }

    /// Read `want` bytes off an `H2` receive stream, releasing flow-control
    /// capacity as they arrive so the proxy can keep sending.
    async fn read_exact_h2(stream: &mut h2::RecvStream, want: usize) -> Vec<u8> {
        let mut got = Vec::new();
        while got.len() < want {
            let chunk = stream
                .data()
                .await
                .expect("stream ended before the payload arrived")
                .expect("no stream error");
            let len = chunk.len();
            stream.flow_control().release_capacity(len).expect("release capacity");
            got.extend_from_slice(&chunk);
        }
        got
    }

    // -----------------------------------------------------------------------
    // CONNECT request handling
    // -----------------------------------------------------------------------

    #[test]
    fn extract_authority_prefers_the_uri_authority() {
        let request = http::Request::builder()
            .uri("http://10.0.0.1:5432")
            .header("host", "ignored:1234")
            .body(())
            .unwrap();
        assert_eq!(
            extract_authority(request.uri(), request.headers()),
            "10.0.0.1:5432",
            "the :authority pseudo-header is the routing decision"
        );
    }

    #[test]
    fn extract_authority_falls_back_to_the_host_header() {
        let request = http::Request::builder()
            .uri("http://10.0.0.1:5432")
            .header("host", "db.internal:5432")
            .body(())
            .unwrap();
        let without_authority = http::Uri::from_static("/no-authority");
        assert_eq!(
            extract_authority(&without_authority, request.headers()),
            "db.internal:5432",
            "a request without :authority falls back to host"
        );
    }

    #[test]
    fn extract_authority_is_empty_when_neither_is_present() {
        let request = http::Request::builder().uri("http://10.0.0.1:5432").body(()).unwrap();
        let uri = http::Uri::from_static("/no-authority");
        assert_eq!(
            extract_authority(&uri, request.headers()),
            "",
            "no authority and no host must not invent a target"
        );
    }

    #[test]
    fn from_config_accepts_an_empty_config_and_rejects_options() {
        assert!(
            H2TunnelFilter::from_config(&serde_yaml::Value::Null).is_ok(),
            "the tunnel filter takes no options"
        );
        let invalid: serde_yaml::Value = serde_yaml::from_str("upstream: 10.0.0.1:5432").unwrap();
        assert!(
            H2TunnelFilter::from_config(&invalid).is_err(),
            "an unknown option must be a config error, not a silent ignore"
        );
    }

    #[tokio::test]
    async fn non_connect_request_is_refused() {
        let mut tunnel = Tunnel::start(empty_pipeline()).await;
        assert_eq!(
            tunnel.get_status().await,
            405,
            "an h2_tunnel listener serves CONNECT and nothing else"
        );
    }

    #[tokio::test]
    async fn unreachable_upstream_is_bad_gateway() {
        let mut tunnel = Tunnel::build(empty_pipeline(), None, None, 0).await;
        assert_eq!(
            tunnel.connect("127.0.0.1:5432").await.0,
            502,
            "a failed upstream connect must be answered on the stream, not by dropping the connection"
        );
        assert_eq!(
            tunnel.dialed(),
            vec!["127.0.0.1:5432".to_owned()],
            "the CONNECT authority is the address the connector dials"
        );
    }

    // -----------------------------------------------------------------------
    // Sub-pipeline integration
    // -----------------------------------------------------------------------

    /// What the per-stream TCP sub-pipeline saw for one CONNECT.
    #[derive(Default)]
    struct Seen {
        upstream_addr: Option<String>,
        connect_header: Option<String>,
        bytes: (u64, u64),
        connects: usize,
        disconnects: usize,
    }

    /// Records the translated [`TcpFilterContext`] on connect and the relayed
    /// byte totals on disconnect.
    struct RecordingTcpFilter {
        seen: Arc<Mutex<Seen>>,
    }

    #[async_trait]
    impl praxis_filter::TcpFilter for RecordingTcpFilter {
        fn name(&self) -> &'static str {
            "test_h2_record"
        }

        async fn on_connect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            let mut seen = self.seen.lock().unwrap();
            seen.connects += 1;
            seen.upstream_addr = ctx.upstream_addr.as_deref().map(str::to_owned);
            seen.connect_header = ctx
                .extensions
                .get::<H2ConnectHeaders>()
                .and_then(|headers| headers.0.get("x-role"))
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            Ok(FilterAction::Continue)
        }

        async fn on_disconnect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<(), FilterError> {
            let mut seen = self.seen.lock().unwrap();
            seen.disconnects += 1;
            seen.bytes = (ctx.bytes_in, ctx.bytes_out);
            Ok(())
        }
    }

    /// Stands in for `tcp_load_balancer`: selects an endpoint, then a filter
    /// behind it rejects, which is the case that must release the selection.
    struct RejectingTcpFilter;

    #[async_trait]
    impl praxis_filter::TcpFilter for RejectingTcpFilter {
        fn name(&self) -> &'static str {
            "test_h2_reject"
        }

        async fn on_connect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Reject(Rejection::status(403)))
        }
    }

    #[tokio::test]
    async fn connect_stream_runs_the_tcp_sub_pipeline() {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let shared = Arc::clone(&seen);
        let pipeline = pipeline_with(&["test_h2_record"], move |registry| {
            registry
                .register(
                    "test_h2_record",
                    FilterFactory::Tcp(Arc::new(move |_config| {
                        Ok(Box::new(RecordingTcpFilter {
                            seen: Arc::clone(&shared),
                        }))
                    })),
                )
                .unwrap();
        });

        let mut tunnel = Tunnel::start(pipeline).await;
        let (status, mut downstream, mut recv) = tunnel.connect("10.0.0.1:5432").await;
        assert_eq!(status, 200, "an accepted CONNECT is answered 200");

        downstream.send_data(Bytes::from_static(b"q"), false).unwrap();
        tunnel.upstreams[0].write_all(b"a").await.unwrap();
        read_exact_h2(&mut recv, 1).await;

        let dialed = tunnel.dialed();
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.upstream_addr.as_deref(),
            Some("10.0.0.1:5432"),
            "the CONNECT authority becomes the sub-pipeline's upstream address"
        );
        assert_eq!(
            seen.connect_header.as_deref(),
            Some("edge"),
            "CONNECT headers reach TCP filters through H2ConnectHeaders"
        );
        assert_eq!(seen.connects, 1, "one CONNECT stream runs one connect phase");
        assert_eq!(dialed, vec!["10.0.0.1:5432".to_owned()]);
    }

    #[tokio::test]
    async fn rejected_connect_stream_runs_disconnect_hooks() {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let shared = Arc::clone(&seen);
        let pipeline = pipeline_with(&["test_h2_record", "test_h2_reject"], move |registry| {
            registry
                .register(
                    "test_h2_record",
                    FilterFactory::Tcp(Arc::new(move |_config| {
                        Ok(Box::new(RecordingTcpFilter {
                            seen: Arc::clone(&shared),
                        }))
                    })),
                )
                .unwrap();
            registry
                .register(
                    "test_h2_reject",
                    FilterFactory::Tcp(Arc::new(|_config| Ok(Box::new(RejectingTcpFilter)))),
                )
                .unwrap();
        });

        let mut tunnel = Tunnel::start(pipeline).await;
        assert_eq!(
            tunnel.connect("10.0.0.1:5432").await.0,
            403,
            "a filter rejection is answered on the stream"
        );

        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.disconnects, 1,
            "a rejected stream must run the disconnect hooks so a selected endpoint's \
             in-flight counter is released, exactly as the TCP proxy does"
        );
        assert_eq!(
            tunnel.dialed(),
            Vec::<String>::new(),
            "a rejected stream must never reach the connector"
        );
    }

    // -----------------------------------------------------------------------
    // Relay
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn connect_stream_relays_bytes_both_directions() {
        let mut tunnel = Tunnel::start(empty_pipeline()).await;
        let (status, mut downstream, mut recv) = tunnel.connect("127.0.0.1:6379").await;
        assert_eq!(status, 200, "an accepted CONNECT is answered 200");

        downstream.send_data(Bytes::from_static(b"PING\r\n"), false).unwrap();
        let mut from_client = [0_u8; 6];
        tunnel.upstreams[0].read_exact(&mut from_client).await.unwrap();
        assert_eq!(&from_client, b"PING\r\n", "client bytes reach the upstream");

        tunnel.upstreams[0].write_all(b"+PONG\r\n").await.unwrap();
        let echoed = read_exact_h2(&mut recv, 7).await;
        assert_eq!(echoed, b"+PONG\r\n", "upstream bytes reach the client");
        assert_eq!(
            tunnel.dialed(),
            vec!["127.0.0.1:6379".to_owned()],
            "the CONNECT authority is the dial target"
        );
    }

    #[tokio::test]
    async fn two_connect_streams_relay_independently() {
        let mut tunnel = Tunnel::build(empty_pipeline(), None, None, 2).await;

        let (status_a, mut send_a, mut recv_a) = tunnel.connect("127.0.0.1:6379").await;
        let (status_b, mut send_b, mut recv_b) = tunnel.connect("127.0.0.1:6380").await;
        assert_eq!((status_a, status_b), (200, 200), "both streams are accepted");

        send_a.send_data(Bytes::from_static(b"first"), false).unwrap();
        send_b.send_data(Bytes::from_static(b"second"), false).unwrap();

        let mut a = [0_u8; 5];
        let mut b = [0_u8; 6];
        tunnel.upstreams[0].read_exact(&mut a).await.unwrap();
        tunnel.upstreams[1].read_exact(&mut b).await.unwrap();
        assert_eq!(&a, b"first", "the first stream keeps its own upstream");
        assert_eq!(&b, b"second", "the second stream keeps its own upstream");

        tunnel.upstreams[1].write_all(b"B").await.unwrap();
        tunnel.upstreams[0].write_all(b"A").await.unwrap();
        assert_eq!(read_exact_h2(&mut recv_a, 1).await, b"A", "streams do not cross");
        assert_eq!(read_exact_h2(&mut recv_b, 1).await, b"B", "streams do not cross");
        assert_eq!(
            tunnel.dialed(),
            vec!["127.0.0.1:6379".to_owned(), "127.0.0.1:6380".to_owned()],
            "one connection carries both tunnels, dialed per stream"
        );
    }

    #[tokio::test]
    async fn upstream_to_client_relay_forwards_a_bulk_payload() {
        let mut tunnel = Tunnel::start(empty_pipeline()).await;
        let (_status, _send, mut recv) = tunnel.connect("127.0.0.1:6379").await;

        // Twice the default 64 KiB stream window, so the relay has to drain it
        // and pick up again on the capacity the client releases.
        let payload = vec![b'z'; 128 * 1024];
        let want = payload.len();
        let upstream = &mut tunnel.upstreams[0];
        let write = async {
            upstream.write_all(&payload).await.expect("upstream write");
        };
        let read = async { read_exact_h2(&mut recv, want).await };

        let ((), got) = tokio::join!(write, read);
        assert_eq!(got.len(), want, "the whole payload arrives");
        assert!(got.iter().all(|byte| *byte == b'z'), "and arrives intact");
    }

    #[tokio::test]
    async fn a_client_that_never_reads_stalls_the_upstream() {
        let mut tunnel = Tunnel::start(empty_pipeline()).await;
        let (_status, _send, _recv) = tunnel.connect("127.0.0.1:6379").await;

        // Far more than the 64 KiB stream window plus the 64 KiB the upstream
        // socket can hold. `send_data` accepts anything below a whole window
        // and queues the rest, so only a relay that waits for capacity stops
        // draining the upstream socket — and a stalled client must not turn
        // into an unbounded buffer inside the proxy.
        let payload = vec![b'z'; 512 * 1024];
        let upstream = &mut tunnel.upstreams[0];
        let written = tokio::time::timeout(Duration::from_millis(500), upstream.write_all(&payload)).await;
        assert!(
            written.is_err(),
            "a client that stops reading must push back on the upstream, not buffer"
        );
    }

    #[tokio::test]
    async fn client_to_upstream_relay_forwards_a_bulk_payload() {
        let mut tunnel = Tunnel::start(empty_pipeline()).await;
        let (_status, mut downstream, _recv) = tunnel.connect("127.0.0.1:6379").await;

        let payload = vec![b'k'; 32 * 1024];
        let want = payload.len();
        let upstream = &mut tunnel.upstreams[0];
        let send = async {
            downstream.send_data(Bytes::from(payload), false).unwrap();
            downstream.send_data(Bytes::new(), true).unwrap();
        };
        let read = async {
            let mut got = vec![0_u8; want];
            upstream.read_exact(&mut got).await.expect("upstream read");
            got
        };

        let ((), got) = tokio::join!(send, read);
        assert_eq!(got.len(), want, "the whole payload reaches the upstream");
        assert!(got.iter().all(|byte| *byte == b'k'), "and arrives intact");
    }

    /// Poll `seen` until `done` holds, for work the tunnel does after it has
    /// already answered the stream.
    async fn wait_until(seen: &Arc<Mutex<Seen>>, done: impl Fn(&Seen) -> bool) {
        for _ in 0..250 {
            if done(&seen.lock().unwrap()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the disconnect hook never ran");
    }

    #[tokio::test]
    async fn disconnect_hook_sees_the_relayed_byte_totals() {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let shared = Arc::clone(&seen);
        let pipeline = pipeline_with(&["test_h2_record"], move |registry| {
            registry
                .register(
                    "test_h2_record",
                    FilterFactory::Tcp(Arc::new(move |_config| {
                        Ok(Box::new(RecordingTcpFilter {
                            seen: Arc::clone(&shared),
                        }))
                    })),
                )
                .unwrap();
        });

        // One duplex per direction: dropping the test's writer gives the relay
        // a real end of file, so it finishes and reports its totals instead of
        // being cancelled with them still uncounted.
        let (proxy_read, mut from_client) = tokio::io::duplex(64 * 1024);
        let (proxy_write, mut to_client) = tokio::io::duplex(64 * 1024);
        let upstream: BoxedIo = Box::new(tokio::io::join(proxy_read, proxy_write));
        let mut tunnel = Tunnel::spawn(pipeline, VecDeque::from([upstream]), None, None).await;

        let (_status, mut downstream, mut recv) = tunnel.connect("127.0.0.1:6379").await;
        downstream.send_data(Bytes::from_static(b"hello"), true).unwrap();
        let mut onward = [0_u8; 5];
        to_client.read_exact(&mut onward).await.expect("upstream read");
        assert_eq!(&onward, b"hello", "the client payload reaches the upstream");

        from_client.write_all(b"abc").await.expect("upstream write");
        read_exact_h2(&mut recv, 3).await;
        drop(from_client);

        wait_until(&seen, |seen| seen.disconnects == 1).await;
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.bytes,
            (5, 3),
            "bytes_in counts client to upstream and bytes_out the reverse, so byte \
             counters and access logs see the same fields they do for a TCP session"
        );
    }

    // -----------------------------------------------------------------------
    // Session limits and shutdown
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_limits_close_a_stalled_stream() {
        for (label, session_timeout, max_duration) in [
            ("tcp_session_timeout_ms", Some(Duration::from_millis(50)), None),
            ("tcp_max_duration_secs", None, Some(Duration::from_millis(50))),
        ] {
            let mut tunnel = Tunnel::build(empty_pipeline(), session_timeout, max_duration, 1).await;
            let (_status, _send, mut recv) = tunnel.connect("127.0.0.1:6379").await;

            // Neither side ever writes and neither closes: only the listener's
            // limit can end this stream.
            match tokio::time::timeout(Duration::from_secs(5), recv.data()).await {
                Err(_elapsed) => panic!("{label}: the limit must close the stalled stream"),
                Ok(Some(Ok(chunk))) => {
                    panic!(
                        "{label}: a limited stream must not carry {} bytes of payload",
                        chunk.len()
                    );
                },
                // Reset (the relay was cancelled) or a clean end of stream.
                Ok(Some(Err(_)) | None) => {},
            }
        }
    }

    #[tokio::test]
    async fn shutdown_ends_the_connection() {
        let tunnel = Tunnel::start(empty_pipeline()).await;
        tunnel.shutdown.send(true).expect("send shutdown");
        let served = tokio::time::timeout(Duration::from_secs(5), tunnel.serve)
            .await
            .expect("serve() must return once shutdown is signalled");
        assert!(matches!(served, Ok(())), "a shutdown close is not an error");
    }
}
