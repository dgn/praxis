// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Validation for `fallback_cluster` chains (health-based failover) and the
//! health contract that ties inline routing clusters back to a top-level
//! health declaration.
//!
//! Gated entirely behind the `health-based-failover` Cargo feature: with the
//! feature off, `fallback_cluster` does not exist on [`Cluster`] (rejected as
//! an unknown config field by `#[serde(deny_unknown_fields)]`), so none of
//! this runs.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use super::inline_clusters::for_each_inline_scope;
use crate::{
    config::{Cluster, Config, FilterEntry},
    errors::ProxyError,
};

/// Maximum number of `fallback_cluster` edges in a chain (17 clusters).
///
/// Enforced at config load and again, defensively, by the runtime walk.
pub const MAX_FALLBACK_CHAIN_EDGES: usize = 16;

// -----------------------------------------------------------------------------
// Structural validation: target exists, acyclic, bounded, protocol-consistent
// -----------------------------------------------------------------------------

/// Validate every `fallback_cluster` reference in one inline `clusters:` list.
///
/// Checked per scope (the list declared by a single `load_balancer` /
/// `tcp_load_balancer` filter entry): the target must exist in the same
/// list, must not be the cluster's own name, the chain must be acyclic and
/// no longer than [`MAX_FALLBACK_CHAIN_EDGES`] edges, and every edge's
/// source and target must declare identical `application_protocol` and
/// `application_provider`.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] on any of the above violations.
pub(super) fn validate_fallback_clusters(context: &str, clusters: &[Cluster]) -> Result<(), ProxyError> {
    let by_name: HashMap<&str, &Cluster> = clusters
        .iter()
        .map(|cluster| (cluster.name.as_ref(), cluster))
        .collect();

    for cluster in clusters {
        let Some(fallback) = cluster.fallback_cluster.as_deref() else {
            continue;
        };

        if fallback == cluster.name.as_ref() {
            return Err(ProxyError::Config(format!(
                "{context}: cluster '{}': fallback_cluster cannot reference itself",
                cluster.name
            )));
        }

        let Some(target) = by_name.get(fallback) else {
            return Err(ProxyError::Config(format!(
                "{context}: cluster '{}': fallback_cluster '{fallback}' is not defined in the same cluster list",
                cluster.name
            )));
        };

        validate_edge_protocol_match(context, cluster, target)?;
    }

    for cluster in clusters {
        if cluster.fallback_cluster.is_some() {
            walk_chain_for_cycles(context, cluster, &by_name)?;
        }
    }

    Ok(())
}

/// Require identical `application_protocol` / `application_provider` across
/// one fallback edge.
fn validate_edge_protocol_match(context: &str, source: &Cluster, target: &Cluster) -> Result<(), ProxyError> {
    if source.http.application_protocol != target.http.application_protocol {
        return Err(ProxyError::Config(format!(
            "{context}: fallback edge '{}' -> '{}': application_protocol mismatch ({:?} vs {:?})",
            source.name, target.name, source.http.application_protocol, target.http.application_protocol
        )));
    }
    if source.http.application_provider != target.http.application_provider {
        return Err(ProxyError::Config(format!(
            "{context}: fallback edge '{}' -> '{}': application_provider mismatch ({:?} vs {:?})",
            source.name, target.name, source.http.application_provider, target.http.application_provider
        )));
    }
    Ok(())
}

/// Walk the fallback chain starting at `start`, rejecting cycles and chains
/// longer than [`MAX_FALLBACK_CHAIN_EDGES`] edges.
fn walk_chain_for_cycles(context: &str, start: &Cluster, by_name: &HashMap<&str, &Cluster>) -> Result<(), ProxyError> {
    let mut visited: HashSet<&str> = HashSet::new();
    visited.insert(start.name.as_ref());
    let mut current = start;
    let mut edges = 0_usize;

    while let Some(next_name) = current.fallback_cluster.as_deref() {
        edges = edges.saturating_add(1);
        if edges > MAX_FALLBACK_CHAIN_EDGES {
            return Err(ProxyError::Config(format!(
                "{context}: fallback chain starting at '{}' exceeds the maximum of {MAX_FALLBACK_CHAIN_EDGES} edges",
                start.name
            )));
        }
        if !visited.insert(next_name) {
            return Err(ProxyError::Config(format!(
                "{context}: fallback chain starting at '{}' contains a cycle at '{next_name}'",
                start.name
            )));
        }
        // Existence was already validated by `validate_fallback_clusters`'s
        // first pass; a missing entry here would be a prior error.
        let Some(next) = by_name.get(next_name) else {
            return Ok(());
        };
        current = next;
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Config-wide rules
// -----------------------------------------------------------------------------

/// Validate the config-wide failover rules: `fallback_cluster` is rejected
/// on top-level declarations, and every inline scope must satisfy the
/// [`FallbackHealthContract`].
///
/// The per-scope structural rules ([`validate_fallback_clusters`]) run with
/// the inline-cluster validation pass.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] on a top-level `fallback_cluster` or a
/// health-contract violation.
pub(super) fn validate_failover(config: &Config) -> Result<(), ProxyError> {
    validate_no_fallback_on_health_declarations(&config.clusters)?;
    let contract = FallbackHealthContract::from_config(config)?;
    for chain in &config.filter_chains {
        validate_chain_entries_health_contract(&contract, &chain.name, &chain.filters)?;
    }
    Ok(())
}

/// Reject `fallback_cluster` on any top-level cluster declaration: the
/// top-level `clusters:` list exists to declare active-probe/passive health
/// state, not routable endpoints, so it is never itself a fallback-chain
/// member.
fn validate_no_fallback_on_health_declarations(clusters: &[Cluster]) -> Result<(), ProxyError> {
    for cluster in clusters {
        if cluster.fallback_cluster.is_some() {
            return Err(ProxyError::Config(format!(
                "cluster '{}': fallback_cluster is not valid on a top-level cluster declaration; \
                 it is valid only on an inline load_balancer/tcp_load_balancer routing cluster",
                cluster.name
            )));
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Health contract: inline fallback members must match a top-level health decl
// -----------------------------------------------------------------------------

/// The contract between top-level health declarations and inline routing
/// clusters, built once per config.
///
/// Health state lives in the shared `HealthRegistry`, which is keyed by
/// cluster name and built only from top-level declarations. Failover can
/// therefore judge an inline cluster only through a same-named top-level
/// `health_check` declaration with the same endpoint address set.
///
/// The contract is enforced only when failover is in use: when no inline
/// scope in the config declares a `fallback_cluster`, enabling the feature
/// leaves validation unchanged.
///
/// ```
/// use praxis_core::config::{
///     Config, FallbackHealthContract, validate_chain_entries_health_contract,
/// };
///
/// let config = Config::from_yaml(
///     r#"
/// listeners:
///   - name: web
///     address: "127.0.0.1:8080"
///     filter_chains: [main]
/// filter_chains:
///   - name: main
///     filters:
///       - filter: static_response
///         status: 200
/// "#,
/// )
/// .unwrap();
/// let contract = FallbackHealthContract::from_config(&config).unwrap();
///
/// // A bound chain that uses failover must still meet the contract: `b`
/// // has no top-level health declaration.
/// let entries: Vec<praxis_core::config::FilterEntry> = serde_yaml::from_str(
///     r#"
/// - filter: load_balancer
///   clusters:
///     - name: a
///       endpoints: ["10.0.0.1:80"]
///       fallback_cluster: b
///     - name: b
///       endpoints: ["10.0.0.2:80"]
/// "#,
/// )
/// .unwrap();
/// assert!(validate_chain_entries_health_contract(&contract, "outbound", &entries).is_err());
/// ```
#[derive(Debug)]
pub struct FallbackHealthContract {
    /// Cluster name -> canonical endpoint address set, for every top-level
    /// cluster with a `health_check`.
    addresses: HashMap<Arc<str>, BTreeSet<String>>,

    /// Whether any inline scope in the config declares a `fallback_cluster`.
    enforced: bool,
}

impl FallbackHealthContract {
    /// Build the contract from a config's top-level health declarations
    /// and its filter chains.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] if an inline `clusters:` list is
    /// malformed; never for a config that passed validation.
    pub fn from_config(config: &Config) -> Result<Self, ProxyError> {
        let addresses = config
            .clusters
            .iter()
            .filter(|cluster| cluster.health_check.is_some())
            .map(|cluster| (Arc::clone(&cluster.name), address_set(cluster)))
            .collect();
        let mut enforced = false;
        for chain in &config.filter_chains {
            enforced |= declares_fallback(&chain.name, &chain.filters)?;
        }
        Ok(Self { addresses, enforced })
    }

    /// The canonical address set for `name`, if it has a top-level health
    /// declaration.
    fn canonical(&self, name: &str) -> Option<&BTreeSet<String>> {
        self.addresses.get(name)
    }
}

/// Validate one chain's filter entries against the health contract,
/// including entries nested in inline branch chains and
/// `iterative_request_router` steps.
///
/// Used for `Config::filter_chains` and for inline outbound chains bound at
/// pipeline-build time, which never appear there. Applies only when the
/// config (see [`FallbackHealthContract`]) or `entries` themselves declare a
/// `fallback_cluster`. Then every fallback-chain member, including the
/// terminal one, needs a top-level health declaration and no inline
/// `health_check`, and every inline definition of a health-checked name
/// must match its declaration's endpoint address set.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] if an inline `clusters:` list is
/// malformed or any of the above rules is violated.
pub fn validate_chain_entries_health_contract(
    contract: &FallbackHealthContract,
    chain_name: &str,
    entries: &[FilterEntry],
) -> Result<(), ProxyError> {
    if !contract.enforced && !declares_fallback(chain_name, entries)? {
        return Ok(());
    }
    for_each_inline_scope(chain_name, entries, &mut |scope_chain, entry, clusters| {
        let context = format!("chain '{scope_chain}': filter '{}'", entry.filter_type);
        validate_chain_members(contract, &context, &clusters)?;
        validate_canonical_endpoints(contract, &context, &clusters)
    })
}

/// Whether any inline scope in `entries` declares a `fallback_cluster`.
fn declares_fallback(chain_name: &str, entries: &[FilterEntry]) -> Result<bool, ProxyError> {
    let mut found = false;
    for_each_inline_scope(chain_name, entries, &mut |_, _, clusters| {
        found |= clusters.iter().any(|cluster| cluster.fallback_cluster.is_some());
        Ok(())
    })?;
    Ok(found)
}

/// Require every fallback-chain member in one scope (the source or target
/// of an edge, including the terminal cluster) to have a top-level health
/// declaration and no inline `health_check` of its own.
fn validate_chain_members(
    contract: &FallbackHealthContract,
    context: &str,
    clusters: &[Cluster],
) -> Result<(), ProxyError> {
    let members: HashSet<&str> = clusters
        .iter()
        .filter_map(|cluster| {
            cluster
                .fallback_cluster
                .as_deref()
                .map(|target| [cluster.name.as_ref(), target])
        })
        .flatten()
        .collect();

    for cluster in clusters
        .iter()
        .filter(|cluster| members.contains(cluster.name.as_ref()))
    {
        if cluster.health_check.is_some() {
            return Err(ProxyError::Config(format!(
                "{context}: cluster '{}' is a fallback-chain member and must not declare its own health_check; \
                 only a top-level health declaration applies",
                cluster.name
            )));
        }
        if contract.canonical(&cluster.name).is_none() {
            return Err(ProxyError::Config(format!(
                "{context}: fallback-chain member '{}' has no matching top-level health_check declaration",
                cluster.name
            )));
        }
    }
    Ok(())
}

/// Require every inline definition of a health-checked name in one scope
/// to declare exactly its top-level declaration's endpoint address set,
/// whether or not it is a fallback-chain member: the name-keyed
/// `HealthRegistry` cannot tell two definitions apart.
fn validate_canonical_endpoints(
    contract: &FallbackHealthContract,
    context: &str,
    clusters: &[Cluster],
) -> Result<(), ProxyError> {
    for cluster in clusters {
        if contract
            .canonical(&cluster.name)
            .is_some_and(|canonical| *canonical != address_set(cluster))
        {
            return Err(ProxyError::Config(format!(
                "{context}: inline cluster '{}' endpoint set does not match its top-level health \
                 declaration's endpoint set",
                cluster.name
            )));
        }
    }
    Ok(())
}

/// A cluster's endpoint addresses as a canonical (sorted, deduplicated) set.
fn address_set(cluster: &Cluster) -> BTreeSet<String> {
    cluster
        .endpoints
        .iter()
        .map(|endpoint| endpoint.address().to_owned())
        .collect()
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
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use std::fmt::Write as _;

    use super::{FallbackHealthContract, MAX_FALLBACK_CHAIN_EDGES, validate_chain_entries_health_contract};
    use crate::config::{Config, FilterEntry};

    /// Base config: a `main` chain with a `load_balancer` whose inline
    /// `clusters:` block is spliced in, plus a top-level `clusters:` block
    /// (health declarations) also spliced in.
    fn config_with(inline_clusters_yaml: &str, top_level_clusters_yaml: &str) -> String {
        format!(
            r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: load_balancer
        clusters:
{inline_clusters_yaml}
clusters:
{top_level_clusters_yaml}
"#
        )
    }

    const HEALTH_CHECK: &str = "    health_check:\n      type: tcp\n";

    #[test]
    fn accept_fallback_cluster_valid_local_target() {
        let yaml = config_with(
            "          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n            fallback_cluster: b\n          - name: b\n            endpoints: [\"10.0.0.2:80\"]\n",
            &format!(
                "  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n{HEALTH_CHECK}  - name: b\n    endpoints: [\"10.0.0.2:80\"]\n{HEALTH_CHECK}"
            ),
        );
        Config::from_yaml(&yaml).expect("valid local fallback target should be accepted");
    }

    #[test]
    fn reject_fallback_cluster_missing_target() {
        let yaml = config_with(
            "          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n            fallback_cluster: missing\n",
            "  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n    health_check:\n      type: tcp\n",
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("is not defined in the same cluster list"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_fallback_cluster_self_reference() {
        let yaml = config_with(
            "          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n            fallback_cluster: a\n",
            "  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n    health_check:\n      type: tcp\n",
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("cannot reference itself"), "got: {err}");
    }

    #[test]
    fn reject_fallback_cluster_two_node_cycle() {
        let yaml = config_with(
            "          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n            fallback_cluster: b\n          - name: b\n            endpoints: [\"10.0.0.2:80\"]\n            fallback_cluster: a\n",
            &format!(
                "  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n{HEALTH_CHECK}  - name: b\n    endpoints: [\"10.0.0.2:80\"]\n{HEALTH_CHECK}"
            ),
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("cycle"), "got: {err}");
    }

    #[test]
    fn reject_fallback_cluster_three_node_cycle() {
        let yaml = config_with(
            "          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n            fallback_cluster: b\n          - name: b\n            endpoints: [\"10.0.0.2:80\"]\n            fallback_cluster: c\n          - name: c\n            endpoints: [\"10.0.0.3:80\"]\n            fallback_cluster: a\n",
            &format!(
                "  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n{HEALTH_CHECK}  - name: b\n    endpoints: [\"10.0.0.2:80\"]\n{HEALTH_CHECK}  - name: c\n    endpoints: [\"10.0.0.3:80\"]\n{HEALTH_CHECK}"
            ),
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("cycle"), "got: {err}");
    }

    #[test]
    fn reject_top_level_fallback_cluster() {
        let yaml = config_with(
            "          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n",
            "  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n    health_check:\n      type: tcp\n    fallback_cluster: b\n  - name: b\n    endpoints: [\"10.0.0.2:80\"]\n",
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("not valid on a top-level cluster declaration"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_mismatched_application_protocol_on_fallback_edge() {
        let yaml = config_with(
            "          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n            fallback_cluster: b\n            http:\n              application_protocol: openai_chat_completions\n          - name: b\n            endpoints: [\"10.0.0.2:80\"]\n",
            &format!(
                "  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n{HEALTH_CHECK}  - name: b\n    endpoints: [\"10.0.0.2:80\"]\n{HEALTH_CHECK}"
            ),
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("application_protocol mismatch"), "got: {err}");
    }

    #[test]
    fn reject_mismatched_application_provider_on_fallback_edge() {
        let yaml = config_with(
            "          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n            fallback_cluster: b\n            http:\n              application_provider: vllm\n          - name: b\n            endpoints: [\"10.0.0.2:80\"]\n",
            &format!(
                "  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n{HEALTH_CHECK}  - name: b\n    endpoints: [\"10.0.0.2:80\"]\n{HEALTH_CHECK}"
            ),
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("application_provider mismatch"), "got: {err}");
    }

    /// A linear `c0 -> c1 -> ... -> c{edges}` chain: the inline clusters
    /// and their matching top-level health declarations.
    fn linear_chain(edges: usize) -> (String, String) {
        let mut inline = String::new();
        let mut top = String::new();
        for i in 0..=edges {
            let addr = format!("10.0.{i}.1:80");
            writeln!(inline, "          - name: c{i}\n            endpoints: [\"{addr}\"]").unwrap();
            if i < edges {
                writeln!(inline, "            fallback_cluster: c{}", i.saturating_add(1)).unwrap();
            }
            write!(top, "  - name: c{i}\n    endpoints: [\"{addr}\"]\n{HEALTH_CHECK}").unwrap();
        }
        (inline, top)
    }

    #[test]
    fn accept_sixteen_edge_chain() {
        let (inline, top) = linear_chain(MAX_FALLBACK_CHAIN_EDGES);
        let yaml = config_with(&inline, &top);
        Config::from_yaml(&yaml).expect("16-edge fallback chain should be accepted");
    }

    #[test]
    fn reject_seventeen_edge_chain() {
        let (inline, top) = linear_chain(MAX_FALLBACK_CHAIN_EDGES + 1);
        let yaml = config_with(&inline, &top);
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("exceeds the maximum"), "got: {err}");
    }

    #[test]
    fn reject_fallback_member_without_top_level_health_declaration() {
        let yaml = config_with(
            "          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n            fallback_cluster: b\n          - name: b\n            endpoints: [\"10.0.0.2:80\"]\n",
            &format!("  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n{HEALTH_CHECK}"),
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("no matching"),
            "terminal fallback member 'b' with no top-level health declaration must be rejected: {err}"
        );
    }

    #[test]
    fn reject_health_tracked_member_with_mismatched_endpoints() {
        let yaml = config_with(
            "          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n            fallback_cluster: b\n          - name: b\n            endpoints: [\"10.0.0.99:80\"]\n",
            &format!(
                "  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n{HEALTH_CHECK}  - name: b\n    endpoints: [\"10.0.0.2:80\"]\n{HEALTH_CHECK}"
            ),
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("does not") && err.to_string().contains("match"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_inline_health_check_on_fallback_member() {
        let yaml = config_with(
            "          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n            fallback_cluster: b\n            health_check:\n              type: tcp\n          - name: b\n            endpoints: [\"10.0.0.2:80\"]\n",
            &format!(
                "  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n{HEALTH_CHECK}  - name: b\n    endpoints: [\"10.0.0.2:80\"]\n{HEALTH_CHECK}"
            ),
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("must not declare its own health_check"),
            "got: {err}"
        );
    }

    #[test]
    fn accept_matching_top_level_declaration_for_every_member() {
        let yaml = config_with(
            "          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n            fallback_cluster: b\n          - name: b\n            endpoints: [\"10.0.0.2:80\"]\n            fallback_cluster: c\n          - name: c\n            endpoints: [\"10.0.0.3:80\"]\n",
            &format!(
                "  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n{HEALTH_CHECK}  - name: b\n    endpoints: [\"10.0.0.2:80\"]\n{HEALTH_CHECK}  - name: c\n    endpoints: [\"10.0.0.3:80\"]\n{HEALTH_CHECK}"
            ),
        );
        Config::from_yaml(&yaml).expect("every chain member including the terminal one has a matching declaration");
    }

    /// Top-level health declarations for `a` (10.0.0.1) and `b` (10.0.0.2).
    fn health_declarations_a_b() -> String {
        format!(
            "clusters:\n  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n{HEALTH_CHECK}  - name: b\n    endpoints: [\"10.0.0.2:80\"]\n{HEALTH_CHECK}"
        )
    }

    /// Inline `a -> b` failover clusters, indented to sit under a filter's
    /// `clusters:` key at `indent` spaces.
    fn inline_a_to_b(indent: usize, b_address: &str) -> String {
        let pad = " ".repeat(indent);
        format!(
            "{pad}- name: a\n{pad}  endpoints: [\"10.0.0.1:80\"]\n{pad}  fallback_cluster: b\n{pad}- name: b\n{pad}  endpoints: [\"{b_address}\"]\n"
        )
    }

    #[test]
    fn tcp_load_balancer_scope_enforces_health_contract() {
        let yaml = format!(
            "listeners:\n  - name: db\n    address: \"127.0.0.1:15432\"\n    protocol: tcp\n    filter_chains: [tcp]\nfilter_chains:\n  - name: tcp\n    filters:\n      - filter: tcp_load_balancer\n        clusters:\n{}{}",
            inline_a_to_b(10, "10.0.0.99:80"),
            health_declarations_a_b()
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("tcp_load_balancer") && err.to_string().contains("endpoint set does not"),
            "tcp_load_balancer fallback members must meet the health contract: {err}"
        );
    }

    #[test]
    fn tcp_load_balancer_scope_validates_fallback_structure() {
        let yaml = "listeners:\n  - name: db\n    address: \"127.0.0.1:15432\"\n    protocol: tcp\n    filter_chains: [tcp]\nfilter_chains:\n  - name: tcp\n    filters:\n      - filter: tcp_load_balancer\n        clusters:\n          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n            fallback_cluster: missing\n";
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("is not defined in the same cluster list"),
            "tcp_load_balancer fallback targets must be validated: {err}"
        );
    }

    #[test]
    fn branch_chain_scope_enforces_health_contract() {
        let yaml = format!(
            "listeners:\n  - name: web\n    address: \"127.0.0.1:18080\"\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: headers\n        request_add:\n          - name: x-a\n            value: b\n        branch_chains:\n          - name: br\n            chains:\n              - name: inline-sub\n                filters:\n                  - filter: load_balancer\n                    clusters:\n{}            rejoin: next\n{}",
            inline_a_to_b(22, "10.0.0.2:80"),
            "clusters:\n  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n    health_check:\n      type: tcp\n"
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("inline-sub") && err.to_string().contains("'b' has no matching"),
            "fallback members inside inline branch chains must meet the health contract: {err}"
        );
    }

    #[test]
    fn iterative_router_step_scope_enforces_health_contract() {
        let yaml = format!(
            "listeners:\n  - name: web\n    address: \"127.0.0.1:18080\"\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: iterative_request_router\n        steps:\n          - name: call\n            filters:\n              - filter: load_balancer\n                clusters:\n{}{}",
            inline_a_to_b(18, "10.0.0.2:80"),
            "clusters:\n  - name: a\n    endpoints: [\"10.0.0.1:80\"]\n    health_check:\n      type: tcp\n"
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("'b' has no matching"),
            "fallback members inside iterative_request_router steps must meet the health contract: {err}"
        );
    }

    /// Two chains: `main` declares `a -> b` failover (when `with_fallback`),
    /// `other` defines an inline `a` with a conflicting endpoint set.
    fn conflicting_definition_config(with_fallback: bool) -> String {
        let main_clusters = if with_fallback {
            inline_a_to_b(10, "10.0.0.2:80")
        } else {
            "          - name: b\n            endpoints: [\"10.0.0.2:80\"]\n".to_owned()
        };
        format!(
            "listeners:\n  - name: web\n    address: \"127.0.0.1:18080\"\n    filter_chains: [main]\n  - name: web2\n    address: \"127.0.0.1:18081\"\n    filter_chains: [other]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: load_balancer\n        clusters:\n{main_clusters}  - name: other\n    filters:\n      - filter: load_balancer\n        clusters:\n          - name: a\n            endpoints: [\"10.0.0.50:80\"]\n{}",
            health_declarations_a_b()
        )
    }

    #[test]
    fn reject_conflicting_same_name_definition_in_unrelated_scope_when_failover_used() {
        let err = Config::from_yaml(&conflicting_definition_config(true)).unwrap_err();
        assert!(
            err.to_string().contains("chain 'other'") && err.to_string().contains("endpoint set does not"),
            "a conflicting inline definition of a health-checked name must be rejected once failover is in use: {err}"
        );
    }

    #[test]
    fn accept_conflicting_same_name_definition_without_failover() {
        Config::from_yaml(&conflicting_definition_config(false))
            .expect("the health contract must not apply to configs that never declare fallback_cluster");
    }

    #[test]
    fn health_contract_rejects_inline_health_check_in_any_member_position() {
        let yaml = config_with(
            "          - name: a\n            endpoints: [\"10.0.0.1:80\"]\n            fallback_cluster: b\n          - name: b\n            endpoints: [\"10.0.0.2:80\"]\n            health_check:\n              type: tcp\n",
            &health_declarations_a_b().replace("clusters:\n", ""),
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("'b' is a fallback-chain member"),
            "the terminal member must not carry an inline health_check either: {err}"
        );
    }

    /// A config with top-level health declarations for `a` and `b` and no
    /// `fallback_cluster` anywhere.
    fn contract_without_failover() -> FallbackHealthContract {
        let yaml = format!(
            "listeners:\n  - name: web\n    address: \"127.0.0.1:18080\"\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: static_response\n        status: 200\n{}",
            health_declarations_a_b()
        );
        FallbackHealthContract::from_config(&Config::from_yaml(&yaml).unwrap()).unwrap()
    }

    /// Filter entries for a bound chain with one `load_balancer`.
    fn bound_entries(clusters_yaml: &str) -> Vec<FilterEntry> {
        serde_yaml::from_str(&format!("- filter: load_balancer\n  clusters:\n{clusters_yaml}")).unwrap()
    }

    #[test]
    fn bound_chain_health_contract_rejects_mismatched_member() {
        let contract = contract_without_failover();
        let entries = bound_entries(&inline_a_to_b(4, "10.0.0.99:80"));
        let err = validate_chain_entries_health_contract(&contract, "outbound", &entries).unwrap_err();
        assert!(
            err.to_string().contains("chain 'outbound'") && err.to_string().contains("endpoint set does not"),
            "a bound chain using failover must meet the health contract: {err}"
        );
    }

    #[test]
    fn bound_chain_health_contract_rejects_untracked_member() {
        let contract = contract_without_failover();
        let entries = bound_entries(
            "    - name: a\n      endpoints: [\"10.0.0.1:80\"]\n      fallback_cluster: z\n    - name: z\n      endpoints: [\"10.0.0.9:80\"]\n",
        );
        let err = validate_chain_entries_health_contract(&contract, "outbound", &entries).unwrap_err();
        assert!(err.to_string().contains("'z' has no matching"), "got: {err}");
    }

    #[test]
    fn bound_chain_health_contract_accepts_matching_members() {
        let contract = contract_without_failover();
        let entries = bound_entries(&inline_a_to_b(4, "10.0.0.2:80"));
        validate_chain_entries_health_contract(&contract, "outbound", &entries)
            .expect("bound chain members matching their declarations must pass");
    }

    #[test]
    fn bound_chain_without_failover_skips_health_contract() {
        let contract = contract_without_failover();
        let entries = bound_entries("    - name: a\n      endpoints: [\"10.0.0.50:80\"]\n");
        validate_chain_entries_health_contract(&contract, "outbound", &entries)
            .expect("no fallback_cluster anywhere: the contract must not apply");
    }
}
