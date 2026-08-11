// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End-to-end tests for the `h2_tunnel` connection filter.
//!
//! The unit tests in `crates/protocol/src/h2_tunnel` drive the filter over an
//! in-memory socket with a stubbed connector. These tests run the same filter
//! through the real server: Pingora's TCP service accepts the connection, the
//! connection filter performs the HTTP/2 handshake, and each CONNECT stream is
//! dialed by the production connector.

use std::{collections::HashMap, time::Duration};

use bytes::Bytes;
use praxis_test_utils::{
    ProxyGuard, free_port, load_example_config, start_full_proxy, start_tcp_tagged_backend, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Harness
// -----------------------------------------------------------------------------

/// The example config, with its listener moved to a free port.
fn example_proxy(proxy_port: u16) -> ProxyGuard {
    let config = load_example_config(
        "protocols/h2-tunnel.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:15008", proxy_port)]),
    );
    let proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    proxy
}

/// An HTTP/2 connection to an `h2_tunnel` listener.
struct Tunnel {
    client: h2::client::SendRequest<Bytes>,
}

impl Tunnel {
    async fn connect(proxy_port: u16) -> Self {
        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
            .await
            .expect("connect to the tunnel listener");
        let (client, conn) = h2::client::handshake(tcp).await.expect("h2 handshake");
        tokio::spawn(async move {
            drop(conn.await);
        });
        Self { client }
    }

    /// Ask for a tunnel to `authority`. On an accepted stream, send `payload`
    /// through it and return the first bytes the upstream sent back.
    async fn tunnel(&mut self, authority: &str, payload: &[u8]) -> (u16, Vec<u8>) {
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("http://{authority}"))
            .body(())
            .expect("build CONNECT request");
        let (response, mut send) = self.client.send_request(request, false).expect("send CONNECT");
        let response = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .expect("CONNECT response")
            .expect("CONNECT response frame");
        let status = response.status().as_u16();
        let mut recv = response.into_body();
        if status != 200 {
            return (status, Vec::new());
        }

        send.send_data(Bytes::copy_from_slice(payload), false)
            .expect("send payload");
        let frame = tokio::time::timeout(Duration::from_secs(5), recv.data())
            .await
            .expect("relayed upstream bytes")
            .expect("no stream error")
            .expect("stream stays open until the payload arrives");
        (status, frame.to_vec())
    }

    /// Send a request the tunnel cannot serve.
    async fn get_status(&mut self) -> u16 {
        let request = http::Request::get("http://example.invalid/")
            .body(())
            .expect("build GET request");
        let (response, _send) = self.client.send_request(request, true).expect("send GET");
        tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .expect("GET response")
            .expect("GET response frame")
            .status()
            .as_u16()
    }
}

/// Run `body` on a current-thread runtime, the suite's pattern for async clients.
fn block_on_async<T>(body: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build test runtime")
        .block_on(body)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn h2_tunnel_example_carries_a_connect_stream() {
    let backend_port = start_tcp_tagged_backend("tunneled");
    let proxy_port = free_port();
    let _proxy = example_proxy(proxy_port);

    let (status, relayed) = block_on_async(async move {
        Tunnel::connect(proxy_port)
            .await
            .tunnel(&format!("127.0.0.1:{backend_port}"), b"hello")
            .await
    });

    assert_eq!(status, 200, "an accepted CONNECT is answered 200");
    assert_eq!(
        relayed,
        b"tunneled:hello".to_vec(),
        "the example's tunnel must reach the upstream and relay its bytes"
    );
}

#[test]
fn h2_tunnel_dials_the_authority_of_each_stream() {
    let first_backend = start_tcp_tagged_backend("first");
    let second_backend = start_tcp_tagged_backend("second");
    let proxy_port = free_port();
    let _proxy = example_proxy(proxy_port);

    let (first, second) = block_on_async(async move {
        let mut tunnel = Tunnel::connect(proxy_port).await;
        let first = tunnel.tunnel(&format!("127.0.0.1:{first_backend}"), b"a").await;
        let second = tunnel.tunnel(&format!("127.0.0.1:{second_backend}"), b"b").await;
        (first, second)
    });

    assert_eq!(
        first,
        (200, b"first:a".to_vec()),
        "the first stream follows its own authority"
    );
    assert_eq!(
        second,
        (200, b"second:b".to_vec()),
        "a second stream on the same connection gets its own upstream"
    );
}

#[test]
fn h2_tunnel_refuses_requests_that_are_not_connect() {
    let proxy_port = free_port();
    let _proxy = example_proxy(proxy_port);

    let status = block_on_async(async { Tunnel::connect(proxy_port).await.get_status().await });

    assert_eq!(status, 405, "an h2_tunnel listener serves CONNECT and nothing else");
}

#[test]
fn h2_tunnel_reports_an_unreachable_authority_as_bad_gateway() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let _proxy = example_proxy(proxy_port);

    let (status, _) = block_on_async(async move {
        Tunnel::connect(proxy_port)
            .await
            .tunnel(&format!("127.0.0.1:{dead_port}"), b"hello")
            .await
    });

    assert_eq!(
        status, 502,
        "a failed upstream dial must surface as 502, not a hung stream"
    );
}
