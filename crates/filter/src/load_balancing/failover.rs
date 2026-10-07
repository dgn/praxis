// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Health-based fallback chain walk shared by the HTTP and TCP load
//! balancers.
//!
//! Config-time validation (`Config::validate`) guarantees every
//! `fallback_cluster` chain is acyclic, locally resolvable, and bounded by
//! [`MAX_FALLBACK_CHAIN_EDGES`] edges, so the walk here only defends against
//! that invariant (an unexpectedly missing entry stops the walk rather than
//! panicking) and enforces the same bound defensively.

use std::sync::Arc;

use metrics::SharedString;
use praxis_core::config::MAX_FALLBACK_CHAIN_EDGES;

use crate::FilterError;

// -----------------------------------------------------------------------------
// FailoverSelection
// -----------------------------------------------------------------------------

/// Ordered cluster names actually walked for a request or connection after a
/// failover, from the originally routed cluster through the effective
/// cluster, inclusive of both.
#[derive(Clone, Debug)]
pub(crate) struct FailoverSelection {
    /// Walked cluster names; never shorter than two entries.
    chain: Arc<[Arc<str>]>,
}

impl FailoverSelection {
    /// The ordered chain of cluster names actually walked.
    pub(crate) fn chain(&self) -> &Arc<[Arc<str>]> {
        &self.chain
    }

    /// The cluster that should actually serve the request or connection.
    #[expect(clippy::expect_used, reason = "chain is never empty by construction")]
    pub(crate) fn effective_cluster(&self) -> &Arc<str> {
        self.chain.last().expect("chain is never empty")
    }

    /// The cluster originally selected by routing, before any failover.
    #[expect(clippy::expect_used, reason = "chain is never empty by construction")]
    pub(crate) fn routed_cluster(&self) -> &Arc<str> {
        self.chain.first().expect("chain is never empty")
    }

    /// Increment `praxis_lb_fallback_total` once per walked hop.
    pub(crate) fn record_hops(&self) {
        for (from, to) in self.chain.iter().zip(self.chain.iter().skip(1)) {
            crate::metrics::record_lb_fallback(
                SharedString::from(Arc::clone(from)),
                SharedString::from(Arc::clone(to)),
            );
        }
    }
}

/// Render a walked chain for access logs: cluster names joined by `,`
/// (routed first, effective last), or `-` when no failover occurred.
pub(crate) fn render_chain(chain: Option<&[Arc<str>]>) -> String {
    match chain {
        Some(chain) if chain.len() > 1 => chain.join(","),
        _ => "-".to_owned(),
    }
}

// -----------------------------------------------------------------------------
// walk
// -----------------------------------------------------------------------------

/// Walk the fallback chain starting at `start`.
///
/// `all_unhealthy(name)` reports whether every endpoint of cluster `name` is
/// currently unhealthy. `lookup(name)` returns the configured
/// `fallback_cluster` target for `name`, or `None` when the cluster has no
/// fallback configured (or, defensively, is unknown).
///
/// Returns `None` when no failover occurs: `start` is not entirely unhealthy
/// or has no fallback configured. No allocation occurs on that path.
///
/// # Errors
///
/// Returns a [`FilterError`] if the walk exceeds [`MAX_FALLBACK_CHAIN_EDGES`]
/// hops. Config-time validation makes this unreachable in a valid
/// configuration; this is a defensive bound against validation bugs or
/// programmatic (non-YAML) cluster construction.
pub(crate) fn walk<F, H>(
    start: &Arc<str>,
    mut all_unhealthy: H,
    mut lookup: F,
) -> Result<Option<FailoverSelection>, FilterError>
where
    F: FnMut(&str) -> Option<Arc<str>>,
    H: FnMut(&str) -> bool,
{
    if !all_unhealthy(start) {
        return Ok(None);
    }
    let Some(mut current) = lookup(start) else {
        return Ok(None);
    };

    let mut names: Vec<Arc<str>> = vec![Arc::clone(start)];
    while all_unhealthy(&current) {
        let Some(next) = lookup(&current) else {
            break;
        };
        if names.len() >= MAX_FALLBACK_CHAIN_EDGES {
            return Err(format!(
                "fallback chain from '{start}' exceeds the maximum of {MAX_FALLBACK_CHAIN_EDGES} edges"
            )
            .into());
        }
        names.push(current);
        current = next;
    }
    names.push(current);

    Ok(Some(FailoverSelection {
        chain: Arc::from(names),
    }))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn arc(s: &str) -> Arc<str> {
        Arc::from(s)
    }

    fn linear_chain(edges: usize) -> HashMap<String, String> {
        (0..edges).map(|i| (format!("n{i}"), format!("n{}", i + 1))).collect()
    }

    #[test]
    fn healthy_primary_takes_no_failover() {
        let start = arc("a");
        let selection = walk(&start, |_| false, |_| Some(arc("b"))).unwrap();
        assert!(selection.is_none(), "healthy start must not fail over");
    }

    #[test]
    fn unhealthy_primary_with_no_fallback_configured_stays_put() {
        let start = arc("a");
        let selection = walk(&start, |_| true, |_| None).unwrap();
        assert!(selection.is_none(), "no fallback configured means no failover");
    }

    #[test]
    fn unhealthy_primary_falls_over_to_healthy_fallback() {
        let fallback: HashMap<&str, &str> = [("a", "b")].into_iter().collect();
        let unhealthy: HashMap<&str, bool> = [("a", true), ("b", false)].into_iter().collect();
        let start = arc("a");
        let selection = walk(
            &start,
            |name| *unhealthy.get(name).unwrap_or(&false),
            |name| fallback.get(name).map(|s| arc(s)),
        )
        .unwrap()
        .expect("failover expected");
        assert_eq!(selection.routed_cluster().as_ref(), "a");
        assert_eq!(selection.effective_cluster().as_ref(), "b");
        assert_eq!(selection.chain().as_ref(), &[arc("a"), arc("b")]);
    }

    #[test]
    fn walks_two_unhealthy_tiers() {
        let fallback: HashMap<&str, &str> = [("a", "b"), ("b", "c")].into_iter().collect();
        let unhealthy: HashMap<&str, bool> = [("a", true), ("b", true), ("c", false)].into_iter().collect();
        let start = arc("a");
        let selection = walk(
            &start,
            |name| *unhealthy.get(name).unwrap_or(&false),
            |name| fallback.get(name).map(|s| arc(s)),
        )
        .unwrap()
        .expect("failover expected");
        assert_eq!(selection.chain().as_ref(), &[arc("a"), arc("b"), arc("c")]);
        assert_eq!(selection.effective_cluster().as_ref(), "c");
    }

    #[test]
    fn stops_at_last_cluster_when_all_unhealthy_and_no_further_fallback() {
        let fallback: HashMap<&str, &str> = [("a", "b")].into_iter().collect();
        let start = arc("a");
        // Both "a" and "b" are unhealthy, but "b" has no configured fallback.
        let selection = walk(&start, |_| true, |name| fallback.get(name).map(|s| arc(s)))
            .unwrap()
            .expect("failover expected");
        assert_eq!(selection.chain().as_ref(), &[arc("a"), arc("b")]);
        assert_eq!(selection.effective_cluster().as_ref(), "b");
    }

    #[test]
    fn exhausted_chain_beyond_max_edges_errors() {
        let fallback = linear_chain(MAX_FALLBACK_CHAIN_EDGES + 1);
        let start = arc("n0");
        let err = walk(&start, |_| true, |name| fallback.get(name).map(|s| arc(s))).unwrap_err();
        assert!(
            err.to_string().contains("exceeds the maximum of 16 edges"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn accepts_exactly_max_edges() {
        let fallback = linear_chain(MAX_FALLBACK_CHAIN_EDGES);
        let start = arc("n0");
        let selection = walk(&start, |_| true, |name| fallback.get(name).map(|s| arc(s)))
            .unwrap()
            .expect("failover expected");
        assert_eq!(selection.chain().len(), MAX_FALLBACK_CHAIN_EDGES + 1);
        assert_eq!(selection.effective_cluster().as_ref(), "n16");
    }

    #[test]
    fn walk_stops_at_first_healthy_tier_even_when_more_fallbacks_exist() {
        let fallback = linear_chain(4);
        let start = arc("n0");
        let selection = walk(&start, |name| name != "n2", |name| fallback.get(name).map(|s| arc(s)))
            .unwrap()
            .expect("failover expected");
        assert_eq!(selection.chain().as_ref(), &[arc("n0"), arc("n1"), arc("n2")]);
    }
}
