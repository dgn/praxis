// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the health-based failover example
//! configuration.
//!
//! Every backend answers the example's `/healthz` probe with a switchable
//! status and every other request with its own name, even while failing its
//! probe, so each response names the endpoint that served it. Each step waits
//! for `/api/stats` to report the switched health before sending traffic.
//! The access-log half of the example runs in `tests/health_based_failover_log.rs`.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use praxis_test_utils::{
    HealthToggleBackend, ProxyGuard, free_port, http_get, http_send, parse_body, parse_header_all, parse_status,
    start_full_proxy, start_health_toggle_backend, wait_for_tcp,
};
use serde_json::Value;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The example config under test.
const EXAMPLE: &str = "traffic-management/health-based-failover.yaml";

/// The example's clusters in fallback order, each with its endpoints.
const TIERS: [(&str, [&str; 2]); 3] = [
    ("app-primary", ["127.0.0.1:3001", "127.0.0.1:3002"]),
    ("app-secondary", ["127.0.0.1:3011", "127.0.0.1:3012"]),
    ("app-tertiary", ["127.0.0.1:3021", "127.0.0.1:3022"]),
];

/// Index of `app-primary` in [`TIERS`].
const PRIMARY: usize = 0;

/// Index of `app-secondary` in [`TIERS`].
const SECONDARY: usize = 1;

/// Index of `app-tertiary` in [`TIERS`].
const TERTIARY: usize = 2;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn health_based_failover_example_walks_the_chain_and_recovers() {
    let example = FailoverExample::start();
    assert_eq!(example.get(None).cluster(), "app-primary", "a healthy primary serves");

    example.set_tier_health(PRIMARY, false);
    assert_eq!(
        example.get(None).cluster(),
        "app-secondary",
        "an all-down primary falls back one hop"
    );

    example.set_tier_health(SECONDARY, false);
    assert_eq!(
        example.get(None).cluster(),
        "app-tertiary",
        "an all-down secondary falls back again"
    );

    example.set_tier_health(TERTIARY, false);
    let series = [
        r#"praxis_lb_fallback_total{cluster="app-primary",fallback="app-secondary"}"#,
        r#"praxis_lb_fallback_total{cluster="app-secondary",fallback="app-tertiary"}"#,
        r#"praxis_lb_panic_mode_total{cluster="app-tertiary"}"#,
    ];
    let before = series.map(|name| example.counter(name));
    assert_eq!(
        example.get(None).cluster(),
        "app-tertiary",
        "the last tier serves in panic mode once every tier is down"
    );
    let after = series.map(|name| example.counter(name));
    for ((name, before), after) in series.iter().zip(before).zip(after) {
        assert!(
            after > before,
            "{name} should count the all-down walk: {before} -> {after}"
        );
    }

    (0..TIERS.len()).for_each(|tier| example.set_tier_health(tier, true));
    assert_eq!(
        example.get(None).cluster(),
        "app-primary",
        "a recovered primary serves again"
    );
}

#[test]
fn health_based_failover_example_keeps_the_primary_session_across_failover() {
    let example = FailoverExample::start();
    let first = example.get(None);
    assert_eq!(first.cluster(), "app-primary", "a healthy primary serves");
    let session = first
        .cookie("_praxis_primary")
        .expect("the primary pins the session under its own cookie");

    example.set_endpoint_health(PRIMARY, first.endpoint(), false);
    for _ in 0..2 {
        assert_eq!(
            example.get(Some(&session)).served_by,
            first.served_by,
            "failover: false keeps the pin while another primary endpoint is healthy"
        );
    }

    example.set_tier_health(PRIMARY, false);
    let failed_over = example.get(Some(&session));
    assert_eq!(
        failed_over.cluster(),
        "app-secondary",
        "an all-down primary drops the pin and falls back"
    );
    assert!(
        failed_over.cookie("_praxis_secondary").is_some(),
        "the fallback cluster pins under its own cookie: {:?}",
        failed_over.set_cookies
    );
    assert!(
        failed_over.cookie("_praxis_primary").is_none(),
        "the fallback must not replace the primary session: {:?}",
        failed_over.set_cookies
    );

    example.set_tier_health(PRIMARY, true);
    for _ in 0..2 {
        assert_eq!(
            example.get(Some(&session)).served_by,
            first.served_by,
            "recovery returns the session to its original primary endpoint"
        );
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// The example config running against switchable backends.
struct FailoverExample {
    /// Proxy listener address.
    proxy: String,

    /// Admin listener address.
    admin: String,

    /// Backends per tier, in [`TIERS`] order.
    tiers: Vec<Vec<HealthToggleBackend>>,

    /// Keeps the proxy running for the test's lifetime.
    _proxy: ProxyGuard,
}

impl FailoverExample {
    /// Start the example with every backend healthy and health checks fast
    /// enough to converge within a test.
    fn start() -> Self {
        let tiers: Vec<Vec<HealthToggleBackend>> = TIERS
            .iter()
            .map(|(cluster, endpoints)| {
                (0..endpoints.len())
                    .map(|index| start_health_toggle_backend("/healthz", &format!("{cluster}#{index}")))
                    .collect()
            })
            .collect();
        let proxy_port = free_port();
        let admin_port = free_port();
        let mut port_map = HashMap::from([("127.0.0.1:9090", admin_port)]);
        for ((_, endpoints), backends) in TIERS.iter().zip(&tiers) {
            port_map.extend(
                endpoints
                    .iter()
                    .copied()
                    .zip(backends.iter().map(HealthToggleBackend::port)),
            );
        }

        let mut config = super::load_example_config(EXAMPLE, proxy_port, port_map);
        for cluster in &mut config.clusters {
            let check = cluster
                .health_check
                .as_mut()
                .expect("every example cluster is health checked");
            check.interval_ms = 200;
            check.timeout_ms = 150;
            check.healthy_threshold = 1;
            check.unhealthy_threshold = 2;
        }

        let example = Self {
            proxy: format!("127.0.0.1:{proxy_port}"),
            admin: format!("127.0.0.1:{admin_port}"),
            tiers,
            _proxy: start_full_proxy(&config),
        };
        wait_for_tcp(&example.proxy);
        wait_for_tcp(&example.admin);
        example
    }

    /// Switch one endpoint's probe result and wait for the proxy to see it.
    fn set_endpoint_health(&self, tier: usize, endpoint: usize, healthy: bool) {
        self.tiers[tier][endpoint].set_healthy(healthy);
        self.wait_for_health();
    }

    /// Switch every endpoint of a tier and wait for the proxy to see it.
    fn set_tier_health(&self, tier: usize, healthy: bool) {
        self.tiers[tier].iter().for_each(|backend| backend.set_healthy(healthy));
        self.wait_for_health();
    }

    /// Wait until `/api/stats` reports every endpoint at its switched health.
    fn wait_for_health(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let (_, stats) = http_get(&self.admin, "/api/stats", None);
            if self.health_matches(&stats) {
                return;
            }
            assert!(Instant::now() < deadline, "health never converged: {stats}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Whether a `/api/stats` body reports every endpoint at its switched
    /// health.
    fn health_matches(&self, stats: &str) -> bool {
        let Ok(stats) = serde_json::from_str::<Value>(stats) else {
            return false;
        };
        TIERS.iter().zip(&self.tiers).all(|((cluster, _), backends)| {
            let rows = stats["clusters"]
                .as_array()
                .and_then(|clusters| clusters.iter().find(|row| row["name"] == *cluster))
                .and_then(|row| row["endpoints"].as_array());
            backends.iter().all(|backend| {
                let address = format!("127.0.0.1:{}", backend.port());
                rows.and_then(|rows| rows.iter().find(|row| row["address"] == address))
                    .is_some_and(|row| row["healthy"] == backend.is_healthy())
            })
        })
    }

    /// Send `GET /` through the proxy, presenting `cookie` if given.
    fn get(&self, cookie: Option<&str>) -> Exchange {
        let cookie = cookie.map(|pair| format!("Cookie: {pair}\r\n")).unwrap_or_default();
        let raw = http_send(
            &self.proxy,
            &format!("GET / HTTP/1.1\r\nHost: localhost\r\n{cookie}Connection: close\r\n\r\n"),
        );
        assert_eq!(parse_status(&raw), 200, "every request should be served: {raw}");
        Exchange {
            served_by: parse_body(&raw),
            set_cookies: parse_header_all(&raw, "set-cookie"),
        }
    }

    /// Current value of the counter `series` on `/metrics`, `0` while
    /// unrecorded.
    fn counter(&self, series: &str) -> u64 {
        let (_, metrics) = http_get(&self.admin, "/metrics", None);
        metrics
            .lines()
            .find_map(|line| line.strip_prefix(series)?.strip_prefix(' '))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0)
    }
}

/// What one proxied request returned.
struct Exchange {
    /// The serving backend's name, `<cluster>#<endpoint index>`.
    served_by: String,

    /// `Set-Cookie` values on the response.
    set_cookies: Vec<String>,
}

impl Exchange {
    /// The cluster that served the request.
    fn cluster(&self) -> &str {
        self.served_by.split('#').next().unwrap_or_default()
    }

    /// Index of the serving endpoint within its cluster.
    fn endpoint(&self) -> usize {
        self.served_by
            .split_once('#')
            .and_then(|(_, index)| index.parse().ok())
            .unwrap_or_else(|| panic!("unexpected backend name: {}", self.served_by))
    }

    /// The `name=value` pair of the response cookie `name`, if set.
    fn cookie(&self, name: &str) -> Option<String> {
        self.set_cookies
            .iter()
            .filter_map(|header| header.split(';').next())
            .find(|pair| pair.split_once('=').is_some_and(|(key, _)| key.trim() == name))
            .map(|pair| pair.trim().to_owned())
    }
}
