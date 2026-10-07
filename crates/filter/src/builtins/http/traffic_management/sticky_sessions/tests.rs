// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Unit tests for the sticky sessions filter.

#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::disallowed_methods, reason = "sync tests need thread::sleep")]

use super::*;

#[test]
fn from_config_parses_valid_cookie_config() {
    let yaml = serde_yaml::from_str(
        r#"
clusters:
  - name: backend
    type: cookie
    cookie_name: "_praxis_route"
    ttl_secs: 3600
    cookie_attributes:
      path: "/"
      http_only: true
      secure: true
    max_entries: 1000
"#,
    )
    .unwrap();
    let filter = StickySessionsFilter::from_config(&yaml);
    filter.unwrap();
}

#[test]
fn from_config_rejects_missing_cookie_name() {
    let yaml = serde_yaml::from_str(
        "
clusters:
  - name: backend
    type: cookie
    ttl_secs: 3600
",
    )
    .unwrap();
    let filter = StickySessionsFilter::from_config(&yaml);
    assert!(filter.is_err());
}

#[test]
fn from_config_rejects_missing_header_name() {
    let yaml = serde_yaml::from_str(
        "
clusters:
  - name: backend
    type: header
    ttl_secs: 3600
",
    )
    .unwrap();
    let filter = StickySessionsFilter::from_config(&yaml);
    assert!(filter.is_err());
}

#[test]
fn filter_owns_stores() {
    let yaml = serde_yaml::from_str(
        r#"
clusters:
  - name: cluster-a
    type: cookie
    cookie_name: "_sess"
    ttl_secs: 3600
    max_entries: 1000
"#,
    )
    .unwrap();
    let filter = StickySessionsFilter::from_config(&yaml);
    assert!(filter.is_ok(), "filter should be created successfully with stores");
}

#[test]
fn generate_session_id_is_unique() {
    let id1 = generate_session_id("10.0.0.1:80");
    std::thread::sleep(Duration::from_millis(1));
    let id2 = generate_session_id("10.0.0.1:80");
    assert_ne!(id1, id2);
    assert_eq!(id1.len(), 16);
}

#[test]
fn extract_session_key_header_mode() {
    let cfg = ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Header {
            header_name: "X-Session-Id".into(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
    };

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("x-session-id", http::HeaderValue::from_static("abc-123"));
    let ctx = crate::test_utils::make_filter_context(&req);

    let key = StickySessionsFilter::extract_session_key(&cfg, &ctx);
    assert_eq!(key.as_deref(), Some("abc-123"));
}

#[test]
fn extract_session_key_learn_mode_reads_cookie() {
    let cfg = ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Learn {
            cookie_name: "JSESSIONID".into(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
    };

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert(
        http::header::COOKIE,
        http::HeaderValue::from_static("JSESSIONID=sess42; other=val"),
    );
    let ctx = crate::test_utils::make_filter_context(&req);

    let key = StickySessionsFilter::extract_session_key(&cfg, &ctx);
    assert_eq!(key.as_deref(), Some("sess42"));
}

#[test]
fn extract_session_key_rejects_overlong_key() {
    let cfg = ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Header {
            header_name: "X-Session-Id".into(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
    };

    let long_key = "x".repeat(MAX_SESSION_KEY_LEN + 1);
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("x-session-id", http::HeaderValue::from_str(&long_key).unwrap());
    let ctx = crate::test_utils::make_filter_context(&req);

    let key = StickySessionsFilter::extract_session_key(&cfg, &ctx);
    assert!(
        key.is_none(),
        "should reject keys longer than {MAX_SESSION_KEY_LEN} bytes"
    );
}

#[test]
fn handle_learn_response_records_session() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.1:80");

    let cfg = Arc::new(ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Learn {
            cookie_name: "JSESSIONID".into(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
    });

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut resp = crate::test_utils::make_response();
    resp.headers.insert(
        http::header::SET_COOKIE,
        http::HeaderValue::from_static("JSESSIONID=learned123; Path=/"),
    );
    ctx.response_header = Some(&mut resp);

    StickySessionsFilter::handle_learn_response(&cfg, &ctx, &store, &endpoint);

    assert_eq!(store.get("learned123").as_deref(), Some("10.0.0.1:80"));
}

#[test]
fn handle_header_response_records_session() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.2:80");

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata(META_SESSION_KEY, "header-key-abc");

    StickySessionsFilter::handle_header_response(&ctx, &store, &endpoint);

    assert_eq!(store.get("header-key-abc").as_deref(), Some("10.0.0.2:80"));
}

#[test]
fn put_update_replaces_endpoint_without_duplicate_entry() {
    let store = SessionStore::new(100, Duration::from_millis(500), config::EvictionPolicy::Ttl);
    store.put("key1", "ep1".into());
    std::thread::sleep(Duration::from_millis(10));
    store.put("key1", "ep2".into());

    assert_eq!(
        store.get("key1").as_deref(),
        Some("ep2"),
        "update should replace the endpoint in place"
    );
    assert_eq!(store.len(), 1, "update must not create a duplicate map entry");
}

#[test]
fn opportunistic_sweep_fires_after_half_ttl() {
    let store = SessionStore::new(100, Duration::from_millis(20), config::EvictionPolicy::Lru);
    store.put("a", "ep1".into());
    store.put("b", "ep2".into());

    std::thread::sleep(Duration::from_millis(25));

    assert!(
        store.get("a").is_none(),
        "expired 'a' should be gone, and the miss should trigger a sweep"
    );
    assert_eq!(store.len(), 0, "the opportunistic sweep should also remove expired 'b'");
}

// -----------------------------------------------------------------------------
// Regression tests for review fixes
// -----------------------------------------------------------------------------

/// A cookie-mode cluster config for response-handling tests.
fn cookie_cfg() -> Arc<ClusterSessionConfig> {
    Arc::new(ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Cookie {
            cookie_name: "_praxis_route".into(),
            cookie_attributes: CookieAttributes::default(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
    })
}

#[test]
fn cookie_response_does_not_adopt_unknown_client_value() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.1:80");
    let cfg = cookie_cfg();

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert(
        http::header::COOKIE,
        http::HeaderValue::from_static("_praxis_route=attacker-chosen"),
    );
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata(META_SESSION_KEY, "attacker-chosen");
    let mut resp = crate::test_utils::make_response();
    ctx.response_header = Some(&mut resp);

    StickySessionsFilter::handle_cookie_response(&cfg, &mut ctx, &store, &endpoint);

    assert!(
        store.get("attacker-chosen").is_none(),
        "client-chosen keys must never be adopted into the store"
    );
    assert_eq!(store.len(), 1, "a fresh server-minted binding should exist");
}

#[test]
fn cookie_response_repins_known_value_after_failover() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    store.put("sessA", Arc::from("10.0.0.1:80"));
    let new_endpoint: Arc<str> = Arc::from("10.0.0.2:80");
    let cfg = cookie_cfg();

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata(META_SESSION_KEY, "sessA");
    let mut resp = crate::test_utils::make_response();
    ctx.response_header = Some(&mut resp);

    StickySessionsFilter::handle_cookie_response(&cfg, &mut ctx, &store, &new_endpoint);

    assert_eq!(
        store.get("sessA").as_deref(),
        Some("10.0.0.2:80"),
        "an established session should re-pin to the serving endpoint"
    );
    assert_eq!(store.len(), 1, "failover must not mint a second binding");
}

#[test]
fn cookie_response_skips_store_when_no_response_header() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.1:80");
    let cfg = cookie_cfg();

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    StickySessionsFilter::handle_cookie_response(&cfg, &mut ctx, &store, &endpoint);

    assert!(
        store.is_empty(),
        "no binding should be written when the exchange produced no response headers"
    );
}

#[test]
fn learn_response_repins_existing_binding_after_failover() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    store.put("sess1", Arc::from("10.0.0.1:80"));
    let new_endpoint: Arc<str> = Arc::from("10.0.0.2:80");

    let cfg = Arc::new(ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Learn {
            cookie_name: "JSESSIONID".into(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
    });

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata(META_SESSION_KEY, "sess1");
    let mut resp = crate::test_utils::make_response();
    ctx.response_header = Some(&mut resp);

    StickySessionsFilter::handle_learn_response(&cfg, &ctx, &store, &new_endpoint);

    assert_eq!(
        store.get("sess1").as_deref(),
        Some("10.0.0.2:80"),
        "existing learn-mode binding should re-pin to the serving endpoint"
    );
}

#[test]
fn learn_response_does_not_adopt_unknown_metadata_key() {
    let store = SessionStore::new(100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    let endpoint: Arc<str> = Arc::from("10.0.0.1:80");

    let cfg = Arc::new(ClusterSessionConfig {
        name: "backend".into(),
        persistence: PersistenceConfig::Learn {
            cookie_name: "JSESSIONID".into(),
        },
        ttl_secs: 3600,
        failover: true,
        max_entries: config::MaxEntries::try_from(1000).unwrap(),
        eviction: config::EvictionPolicy::Lru,
    });

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata(META_SESSION_KEY, "never-bound");
    let mut resp = crate::test_utils::make_response();
    ctx.response_header = Some(&mut resp);

    StickySessionsFilter::handle_learn_response(&cfg, &ctx, &store, &endpoint);

    assert!(
        store.is_empty(),
        "learn mode must not adopt client-presented keys that were never bound"
    );
}

#[test]
fn registry_preserves_store_across_reload_when_config_unchanged() {
    let registry = SessionStoreRegistry::new();
    let first = registry.get_or_create("backend", 100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    first.put("sess1", Arc::from("10.0.0.1:80"));

    let second = registry.get_or_create("backend", 100, Duration::from_secs(3600), config::EvictionPolicy::Lru);
    assert!(
        Arc::ptr_eq(&first, &second),
        "unchanged config must reuse the existing store"
    );
    assert_eq!(
        second.get("sess1").as_deref(),
        Some("10.0.0.1:80"),
        "session bindings must survive a reload"
    );

    let third = registry.get_or_create("backend", 100, Duration::from_secs(60), config::EvictionPolicy::Lru);
    assert!(!Arc::ptr_eq(&first, &third), "changed config must replace the store");
    assert!(third.get("sess1").is_none(), "replaced store starts empty");
}

#[test]
fn find_request_cookie_checks_all_cookie_headers() {
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .append(http::header::COOKIE, http::HeaderValue::from_static("other=1"));
    req.headers.append(
        http::header::COOKIE,
        http::HeaderValue::from_static("_praxis_route=split-value"),
    );
    let ctx = crate::test_utils::make_filter_context(&req);

    assert_eq!(
        StickySessionsFilter::find_request_cookie(&ctx, "_praxis_route").as_deref(),
        Some("split-value"),
        "cookie lookup must consider every Cookie header"
    );
}

// -----------------------------------------------------------------------------
// Health-Based Failover
// -----------------------------------------------------------------------------

#[cfg(feature = "health-based-failover")]
mod failover {
    //! `sticky_sessions` in front of a `load_balancer` whose two-endpoint
    //! `primary` cluster falls back to `backup`.

    #![expect(clippy::expect_used, reason = "tests")]

    use praxis_core::health::HealthRegistry;

    use super::*;
    use crate::{FilterPipeline, FilterRegistry, test_utils::multi_health_registry};

    const P1: &str = "10.0.0.1:80";
    const P2: &str = "10.0.0.2:80";
    const BACKUP: &str = "10.0.1.1:80";

    #[tokio::test]
    async fn cookie_failover_keeps_the_primary_cookie_for_recovery() {
        let harness = Harness::new(
            "
    - { name: primary, type: cookie, cookie_name: _praxis_primary, failover: false }
    - { name: backup, type: cookie, cookie_name: _praxis_backup }",
        );
        let key = harness
            .exchange(&health(&[]), &[], None)
            .await
            .pinned_on_primary("_praxis_primary");
        let primary_cookie = format!("_praxis_primary={key}");

        let failover = harness
            .exchange(&health(&[0, 1]), &[("cookie", &primary_cookie)], None)
            .await;

        failover.assert_served_by_backup();
        assert_eq!(
            failover.cookie("_praxis_primary"),
            None,
            "the client keeps its primary session"
        );
        let backup_key = failover
            .cookie("_praxis_backup")
            .expect("the fallback mints its own session");
        harness.assert_failover_bindings(&key, &backup_key);
        let cookies = format!("{primary_cookie}; _praxis_backup={backup_key}");
        let recovered = harness.exchange(&health(&[]), &[("cookie", &cookies)], None).await;
        assert_eq!(
            recovered.served, P1,
            "recovery reuses the primary cluster's original mapping"
        );
    }

    #[tokio::test]
    async fn header_failover_pins_the_fallback_store_and_recovers_the_primary_mapping() {
        let harness = Harness::new(
            "
    - { name: primary, type: header, header_name: x-session-id }
    - { name: backup, type: header, header_name: x-session-id }",
        );
        let session = [("x-session-id", "client-1")];
        assert_eq!(harness.exchange(&health(&[]), &session, None).await.served, P1);

        harness
            .exchange(&health(&[0, 1]), &session, None)
            .await
            .assert_served_by_backup();

        harness.assert_failover_bindings("client-1", "client-1");
        let recovered = harness.exchange(&health(&[]), &session, None).await;
        assert_eq!(
            recovered.served, P1,
            "recovery reuses the primary cluster's original mapping"
        );
    }

    #[tokio::test]
    async fn learn_failover_pins_the_fallback_store_and_recovers_the_primary_mapping() {
        let harness = Harness::new(
            "
    - { name: primary, type: learn, cookie_name: primary_session }
    - { name: backup, type: learn, cookie_name: backup_session }",
        );
        let first = harness.exchange(&health(&[]), &[], Some("primary_session=p-1")).await;
        assert_eq!(first.served, P1);

        let failover = harness
            .exchange(
                &health(&[0, 1]),
                &[("cookie", "primary_session=p-1")],
                Some("backup_session=b-1"),
            )
            .await;

        failover.assert_served_by_backup();
        harness.assert_failover_bindings("p-1", "b-1");
        let cookies = [("cookie", "primary_session=p-1; backup_session=b-1")];
        let recovered = harness.exchange(&health(&[]), &cookies, None).await;
        assert_eq!(
            recovered.served, P1,
            "recovery reuses the primary cluster's original mapping"
        );
    }

    #[tokio::test]
    async fn fallback_without_sticky_config_pins_nothing() {
        let harness = Harness::new(
            "
    - { name: primary, type: cookie, cookie_name: _praxis_primary }",
        );
        let key = harness
            .exchange(&health(&[]), &[], None)
            .await
            .pinned_on_primary("_praxis_primary");
        let primary_cookie = format!("_praxis_primary={key}");

        let failover = harness
            .exchange(&health(&[0, 1]), &[("cookie", &primary_cookie)], None)
            .await;

        failover.assert_served_by_backup();
        assert!(
            failover.set_cookies.is_empty(),
            "no session is minted for the unconfigured fallback"
        );
        assert!(
            harness.stores.get("backup").is_none(),
            "no store exists for the fallback cluster"
        );
        assert_eq!(harness.binding("primary", &key).as_deref(), Some(P1));
    }

    #[tokio::test]
    async fn disabled_sticky_failover_keeps_the_pin_until_every_primary_endpoint_is_down() {
        let harness = Harness::new(
            "
    - { name: primary, type: cookie, cookie_name: _praxis_primary, failover: false }",
        );
        let key = harness
            .exchange(&health(&[]), &[], None)
            .await
            .pinned_on_primary("_praxis_primary");
        let primary_cookie = format!("_praxis_primary={key}");

        let pinned = harness
            .exchange(&health(&[0]), &[("cookie", &primary_cookie)], None)
            .await;
        let failover = harness
            .exchange(&health(&[0, 1]), &[("cookie", &primary_cookie)], None)
            .await;

        assert_eq!(
            (pinned.served.as_str(), pinned.chain.as_str()),
            (P1, "-"),
            "with a healthy primary endpoint left, the disabled-failover pin still wins"
        );
        failover.assert_served_by_backup();
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// What one request/response exchange produced.
    struct Exchange {
        /// Address of the endpoint that served the request.
        served: String,
        /// The rendered `fallback_chain` access-log field.
        chain: String,
        /// `Set-Cookie` values in the response to the client.
        set_cookies: Vec<String>,
    }

    impl Exchange {
        /// The value of the `Set-Cookie` named `name`.
        fn cookie(&self, name: &str) -> Option<String> {
            self.set_cookies.iter().find_map(|header| {
                let pair = header.split(';').next()?;
                pair.strip_prefix(name)?.strip_prefix('=').map(str::to_owned)
            })
        }

        /// Assert the primary served and set the session cookie `name`;
        /// returns the session key.
        fn pinned_on_primary(&self, name: &str) -> String {
            assert_eq!(self.served, P1, "round robin starts on the first primary endpoint");
            self.cookie(name).expect("the primary pins a new session")
        }

        /// Assert the request failed over to the `backup` cluster.
        fn assert_served_by_backup(&self) {
            assert_eq!((self.served.as_str(), self.chain.as_str()), (BACKUP, "primary,backup"));
        }
    }

    /// A `router` → `sticky_sessions` → `load_balancer` pipeline and the
    /// session stores it writes.
    struct Harness {
        pipeline: FilterPipeline,
        stores: Arc<SessionStoreRegistry>,
    }

    impl Harness {
        /// Build the pipeline with `sticky_clusters` as the `sticky_sessions`
        /// cluster list.
        fn new(sticky_clusters: &str) -> Self {
            let yaml = format!(
                r#"
- filter: router
  routes:
    - {{ path_prefix: "/", cluster: primary }}
- filter: sticky_sessions
  clusters:{sticky_clusters}
- filter: load_balancer
  clusters:
    - {{ name: primary, endpoints: ["{P1}", "{P2}"], fallback_cluster: backup }}
    - {{ name: backup, endpoints: ["{BACKUP}"] }}
"#
            );
            let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&yaml).unwrap();
            Self {
                pipeline: FilterPipeline::build(&mut entries, &FilterRegistry::with_builtins()).unwrap(),
                stores: Arc::new(SessionStoreRegistry::new()),
            }
        }

        /// Run one request and response through the pipeline. The upstream
        /// answers with `upstream_set_cookie`, if any.
        async fn exchange(
            &self,
            health: &HealthRegistry,
            request_headers: &[(&'static str, &str)],
            upstream_set_cookie: Option<&str>,
        ) -> Exchange {
            let mut req = crate::test_utils::make_request(http::Method::GET, "/");
            for (name, value) in request_headers {
                req.headers.append(*name, http::HeaderValue::from_str(value).unwrap());
            }
            let mut resp = crate::test_utils::make_response();
            if let Some(cookie) = upstream_set_cookie {
                resp.headers
                    .append(http::header::SET_COOKIE, http::HeaderValue::from_str(cookie).unwrap());
            }
            let mut ctx = crate::test_utils::make_filter_context(&req);
            ctx.health_registry = Some(health);
            ctx.session_stores = Some(&self.stores);
            drop(self.pipeline.execute_http_request(&mut ctx).await.unwrap());
            let served = ctx
                .upstream
                .as_ref()
                .map(|upstream| upstream.address.to_string())
                .unwrap();
            let chain = ctx.fallback_chain_field();
            ctx.response_header = Some(&mut resp);
            drop(self.pipeline.execute_http_response(&mut ctx).await.unwrap());
            let set_cookies = resp.headers.get_all(http::header::SET_COOKIE).iter();
            let set_cookies = set_cookies.map(|value| value.to_str().unwrap().to_owned()).collect();
            Exchange {
                served,
                chain,
                set_cookies,
            }
        }

        /// The endpoint `cluster`'s session store binds `key` to.
        fn binding(&self, cluster: &str, key: &str) -> Option<Arc<str>> {
            self.stores.get(cluster)?.get(key)
        }

        /// Assert the fallback pinned `backup_key` into its own store while
        /// the primary store still holds only the original `primary_key`.
        fn assert_failover_bindings(&self, primary_key: &str, backup_key: &str) {
            assert_eq!(self.binding("backup", backup_key).as_deref(), Some(BACKUP));
            assert_eq!(
                self.binding("primary", primary_key).as_deref(),
                Some(P1),
                "the primary store keeps the original mapping"
            );
            assert_eq!(
                self.stores.get("primary").unwrap().len(),
                1,
                "the primary store is untouched"
            );
        }
    }

    /// Health for both clusters, with the listed `primary` endpoints down.
    fn health(primary_down: &[usize]) -> HealthRegistry {
        multi_health_registry(&[("primary", &[P1, P2], primary_down), ("backup", &[BACKUP], &[])])
    }
}
