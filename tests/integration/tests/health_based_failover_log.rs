// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Access-log integration test for the health-based failover example.
//!
//! The example logs `fallback_chain` next to the effective `cluster`, per
//! request: one keep-alive connection sees `-`, then the walked chain, then
//! `-` again as the primary goes down and recovers. Reading the log back
//! means installing a process-global tracing subscriber (via
//! `praxis::init_tracing`), so this runs as its own test binary instead of
//! inside the shared `suite` process, where it would capture every other
//! test's logs. The proxy runs in-process rather than as `praxis_bin()`, which
//! may be a build without the `health-based-failover` feature. The routing
//! half of the example is covered by `suite/examples/health_based_failover.rs`.

#![cfg(feature = "health-based-failover")]
#![allow(
    clippy::allow_attributes_without_reason,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::clone_on_ref_ptr,
    clippy::cognitive_complexity,
    clippy::default_trait_access,
    clippy::disallowed_methods,
    clippy::doc_markdown,
    clippy::doc_nested_refdefs,
    clippy::expect_used,
    clippy::format_push_string,
    clippy::indexing_slicing,
    clippy::iter_over_hash_type,
    clippy::items_after_statements,
    clippy::len_zero,
    clippy::manual_is_multiple_of,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::map_with_unused_argument_over_ranges,
    clippy::min_ident_chars,
    clippy::needless_raw_string_hashes,
    clippy::needless_raw_strings,
    clippy::panic,
    clippy::print_stderr,
    clippy::redundant_closure_for_method_calls,
    clippy::shadow_unrelated,
    clippy::single_char_lifetime_names,
    clippy::string_add,
    clippy::struct_field_names,
    clippy::tests_outside_test_module,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::used_underscore_binding,
    clippy::useless_format,
    clippy::wildcard_enum_match_arm,
    reason = "test code"
)]

use std::{
    collections::HashMap,
    fs,
    io::Write as _,
    net::TcpStream,
    path::Path,
    time::{Duration, Instant},
};

use praxis_core::config::{LogOutput, LoggingConfig};
use praxis_test_utils::{
    HealthToggleBackend, free_port, http_get, load_example_config, parse_body, parse_status, read_full_response,
    start_full_proxy, start_health_toggle_backend, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The example config under test.
const EXAMPLE: &str = "traffic-management/health-based-failover.yaml";

/// The example's endpoints, each with the cluster it belongs to.
const ENDPOINTS: [(&str, &str); 6] = [
    ("127.0.0.1:3001", "app-primary"),
    ("127.0.0.1:3002", "app-primary"),
    ("127.0.0.1:3011", "app-secondary"),
    ("127.0.0.1:3012", "app-secondary"),
    ("127.0.0.1:3021", "app-tertiary"),
    ("127.0.0.1:3022", "app-tertiary"),
];

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn health_based_failover_example_logs_the_fallback_chain_per_request() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("proxy.log");
    // Each backend answers with its cluster's name, healthy or not.
    let backends = ENDPOINTS.map(|(_, cluster)| (cluster, start_health_toggle_backend("/healthz", cluster)));
    let proxy_port = free_port();
    let port_map: HashMap<&str, u16> = ENDPOINTS
        .iter()
        .zip(&backends)
        .map(|((address, _), (_, backend))| (*address, backend.port()))
        .chain([("127.0.0.1:9090", free_port())])
        .collect();

    let mut config = load_example_config(EXAMPLE, proxy_port, port_map);
    for check in config
        .clusters
        .iter_mut()
        .filter_map(|cluster| cluster.health_check.as_mut())
    {
        check.interval_ms = 200;
        check.timeout_ms = 150;
        check.healthy_threshold = 1;
        check.unhealthy_threshold = 2;
    }
    config.runtime.logging = LoggingConfig {
        output: LogOutput::File,
        file_path: Some(log_path.display().to_string()),
        non_blocking: false,
        buffer_size: None,
    };
    // Keep access records at info even when RUST_LOG is stricter.
    config
        .runtime
        .log_overrides
        .insert("praxis_filter".to_owned(), "info".to_owned());

    let _tracing = praxis::init_tracing(&config).expect("tracing init");
    let _proxy = start_full_proxy(&config);
    let proxy = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&proxy);
    let mut connection = TcpStream::connect(&proxy).expect("connect to proxy");
    connection
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    assert_eq!(
        get_on(&mut connection, "/before"),
        "app-primary",
        "a healthy primary serves"
    );
    wait_for_record(&log_path, "app-primary", "-", "/before");

    set_cluster_health(&backends, "app-primary", false);
    wait_for_cluster(&proxy, "app-secondary");
    assert_eq!(
        get_on(&mut connection, "/during"),
        "app-secondary",
        "an all-down primary falls back"
    );
    wait_for_record(&log_path, "app-secondary", "app-primary,app-secondary", "/during");

    set_cluster_health(&backends, "app-primary", true);
    wait_for_cluster(&proxy, "app-primary");
    assert_eq!(
        get_on(&mut connection, "/after"),
        "app-primary",
        "a recovered primary serves again"
    );
    wait_for_record(&log_path, "app-primary", "-", "/after");
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Make every backend of `cluster` pass or fail its probe.
fn set_cluster_health(backends: &[(&str, HealthToggleBackend)], cluster: &str, healthy: bool) {
    backends
        .iter()
        .filter(|(name, _)| *name == cluster)
        .for_each(|(_, backend)| backend.set_healthy(healthy));
}

/// Send `GET path` on the open keep-alive `connection` and return the
/// serving cluster's name.
fn get_on(connection: &mut TcpStream, path: &str) -> String {
    connection
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .expect("write request");
    let raw = read_full_response(connection);
    assert_eq!(
        parse_status(&raw),
        200,
        "the keep-alive connection should serve {path}: {raw}"
    );
    parse_body(&raw)
}

/// Retry `GET /` on fresh connections until `cluster` serves it.
fn wait_for_cluster(proxy: &str, cluster: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (status, served) = http_get(proxy, "/", None);
        assert_eq!(status, 200, "every request should be served: {served}");
        if served == cluster {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{cluster} never served; last response from {served}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Wait for the access record of `GET path` to name `cluster` and
/// `fallback_chain`; records land after the response is sent.
fn wait_for_record(log_path: &Path, cluster: &str, fallback_chain: &str, path: &str) {
    // The record's keys are sorted, so these four are adjacent.
    let needle = format!(r#""cluster":"{cluster}","fallback_chain":"{fallback_chain}","method":"GET","path":"{path}""#);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let log = fs::read_to_string(log_path).unwrap_or_default();
        if log.contains(&needle) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the access log never recorded {needle}: {log}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
