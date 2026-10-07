// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! TCP connection access log filter.

use async_trait::async_trait;

use crate::{
    EmptyFilterConfig,
    actions::FilterAction,
    filter::FilterError,
    parse_filter_config,
    tcp_filter::{TcpFilter, TcpFilterContext},
};

// -----------------------------------------------------------------------------
// TcpAccessLogFilter
// -----------------------------------------------------------------------------

/// Logs TCP connection events.
///
/// With the `health-based-failover` build feature, both records also include
/// `fallback_chain`: the walked cluster names joined by `,`, or `-` when no
/// failover occurred. A `tcp_load_balancer` that declares `fallback_cluster`
/// must run before this filter (enforced at config load) so the connect
/// record logs the upstream and `fallback_chain` it selected.
///
/// # YAML configuration
///
/// ```yaml
/// filter: tcp_access_log
/// # no configurable parameters
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::TcpAccessLogFilter;
///
/// let yaml = serde_yaml::Value::Null;
/// let filter = TcpAccessLogFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "tcp_access_log");
/// ```
pub struct TcpAccessLogFilter;

impl TcpAccessLogFilter {
    /// Create from YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError> {
        let _: EmptyFilterConfig = parse_filter_config("tcp_access_log", config)?;
        Ok(Box::new(Self))
    }
}

#[async_trait]
impl TcpFilter for TcpAccessLogFilter {
    fn name(&self) -> &'static str {
        "tcp_access_log"
    }

    async fn on_connect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        info_with_fallback_chain!(
            ctx,
            {
                remote = ctx.remote_addr,
                local = ctx.local_addr,
                upstream = ctx.upstream_addr.as_deref().unwrap_or("-"),
                sni = ctx.sni.unwrap_or("-"),
            },
            "TCP connection accepted"
        );
        Ok(FilterAction::Continue)
    }

    async fn on_disconnect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<(), FilterError> {
        let duration_ms = u64::try_from(ctx.connect_time.elapsed().as_millis()).unwrap_or(u64::MAX);
        info_with_fallback_chain!(
            ctx,
            {
                remote = ctx.remote_addr,
                upstream = ctx.upstream_addr.as_deref().unwrap_or("-"),
                sni = ctx.sni.unwrap_or("-"),
                duration_ms,
                bytes_in = ctx.bytes_in,
                bytes_out = ctx.bytes_out,
            },
            "TCP connection closed"
        );
        Ok(())
    }
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
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn from_config_succeeds() {
        let filter = TcpAccessLogFilter::from_config(&serde_yaml::Value::Null).unwrap();
        assert_eq!(filter.name(), "tcp_access_log", "filter name should be tcp_access_log");
    }

    #[test]
    fn from_config_rejects_unknown_fields() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("bogus: true").unwrap();
        let result = TcpAccessLogFilter::from_config(&yaml);
        assert!(result.is_err(), "unknown fields should be rejected");
    }

    #[tokio::test]
    async fn on_connect_returns_ok() {
        let filter = TcpAccessLogFilter;
        let mut ctx = test_ctx();
        let action = filter.on_connect(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "on_connect should continue");
    }

    #[tokio::test]
    async fn on_disconnect_returns_ok() {
        let filter = TcpAccessLogFilter;
        let mut ctx = TcpFilterContext {
            bytes_in: 1024,
            bytes_out: 2048,
            ..test_ctx()
        };
        filter.on_disconnect(&mut ctx).await.unwrap();
    }

    #[test]
    #[cfg(feature = "health-based-failover")]
    fn records_log_the_fallback_chain() {
        use std::sync::Arc;

        let failed_over = TcpFilterContext {
            fallback_chain: Some(Arc::from(["tcp-a", "tcp-b"].map(Arc::<str>::from))),
            ..test_ctx()
        };
        for (mut ctx, chain) in [(test_ctx(), "-"), (failed_over, "tcp-a,tcp-b")] {
            let logs = connection_logs(&mut ctx);
            for record in ["TCP connection accepted", "TCP connection closed"] {
                let line = logs
                    .lines()
                    .find(|line| line.contains(record))
                    .unwrap_or_else(|| panic!("no {record:?} record: {logs}"));
                assert!(
                    line.contains(&format!("fallback_chain={chain}")),
                    "{record:?} should log fallback_chain={chain}: {line}"
                );
            }
        }
    }

    fn test_ctx() -> TcpFilterContext<'static> {
        TcpFilterContext {
            remote_addr: "127.0.0.1:12345",
            local_addr: "0.0.0.0:9000",
            sni: None,
            upstream_addr: Some(std::borrow::Cow::Borrowed("10.0.0.1:80")),
            cluster: None,
            #[cfg(feature = "health-based-failover")]
            fallback_chain: None,
            health_registry: None,
            kv_stores: None,
            connect_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    /// Run the connect and disconnect hooks for `ctx`, returning their logs.
    #[cfg(feature = "health-based-failover")]
    fn connection_logs(ctx: &mut TcpFilterContext<'_>) -> String {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        crate::test_utils::capture_logs(|| {
            runtime.block_on(async {
                let filter = TcpAccessLogFilter;
                let action = filter.on_connect(ctx).await.unwrap();
                assert!(matches!(action, FilterAction::Continue), "on_connect should continue");
                filter.on_disconnect(ctx).await.unwrap();
            });
        })
    }
}
