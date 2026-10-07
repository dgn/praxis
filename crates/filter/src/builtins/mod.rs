// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Built-in filter implementations, organized by protocol and category.

/// `tracing::info!` with the access-log `fallback_chain` field appended
/// after `$fields` (rendered by `$ctx.fallback_chain_field()`).
#[cfg(feature = "health-based-failover")]
macro_rules! info_with_fallback_chain {
    ($ctx:ident, { $($fields:tt)* }, $message:literal) => {
        ::tracing::info!($($fields)* fallback_chain = %$ctx.fallback_chain_field(), $message)
    };
}

/// `tracing::info!` over `$fields`; the `fallback_chain` field only exists
/// with the `health-based-failover` build feature.
#[cfg(not(feature = "health-based-failover"))]
macro_rules! info_with_fallback_chain {
    ($ctx:ident, { $($fields:tt)* }, $message:literal) => {
        ::tracing::info!($($fields)* $message)
    };
}

pub mod http;
mod tcp;

#[cfg(feature = "basic-auth-filter")]
pub use http::BasicAuthFilter;
#[cfg(feature = "cloud-events-filter")]
pub use http::CloudEventsFilter;
#[cfg(feature = "iterative-request-router")]
pub use http::IterativeRequestRouterFilter;
#[cfg(feature = "spiffe")]
pub use http::PeerIdentityTrustFilter;
pub use http::{
    AccessLogFilter, CircuitBreakerFilter, CompressionFilter, ContainsValue, CorsFilter, CredentialInjectionFilter,
    CsrfFilter, DisallowedOriginMode, EndpointReselector, EndpointSelectorFilter, ForwardedHeadersFilter,
    GrpcDetectionFilter, GrpcStatusFilter, GrpcTimeoutFilter, GrpcWebFilter, GuardrailsAction, GuardrailsFilter,
    HeaderFilter, IpAclFilter, JsonBodyFieldFilter, JsonBodyFilter, JsonBodyOps, JsonRpcFilter, LoadBalancerFilter,
    PathRewriteFilter, PiiKind, RateLimitFilter, RateLimitMode, RedirectFilter, RedirectStatus, RequestIdFilter,
    RouterFilter, RuleTargetKind, SessionStore, SessionStoreRegistry, StaticResponseFilter, StickySessionsFilter,
    TimeoutFilter, TraceContextFilter, UrlRewriteFilter, access_record_already_emitted, bodyless_response,
    emit_access_record, encode_trailer_frame, has_dot_dot_traversal, mark_access_record_emitted,
    normalize_rewritten_path,
};
#[cfg(feature = "policy-engine")]
pub use http::{PolicyFilter, PolicyPluginFactoryFn, register_policy_plugin_factory};
pub use tcp::{SniRouterFilter, TcpAccessLogFilter, TcpLoadBalancerFilter};
