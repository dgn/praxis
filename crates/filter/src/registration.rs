// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Filter registration macros and utilities.
//!
//! This module provides macros for registering custom filters alongside
//! built-ins and exporting filters from external crates for build-time
//! auto-discovery.

// -----------------------------------------------------------------------------
// Custom Filter Registration
// -----------------------------------------------------------------------------

/// Macro for registering custom filters alongside built-ins.
///
/// ```ignore
/// use praxis_filter::register_filters;
///
/// pub struct MyAuthFilter { /* ... */ }
/// pub struct MyTcpLogger { /* ... */ }
///
/// register_filters! {
///     http "my_auth" => MyAuthFilter::from_config,
///     tcp  "my_tcp_logger" => MyTcpLogger::from_config,
/// }
/// ```
#[macro_export]
macro_rules! register_filters {
    ( @register $registry:ident, http $name:expr => $factory:expr ) => {
        $registry.register(
            $name,
            $crate::FilterFactory::Http(
                ::std::sync::Arc::new(move |config: &serde_yaml::Value| {
                    ($factory)(config)
                }),
            ),
        ).unwrap_or_else(|_| panic!("duplicate filter name: '{}'", $name));
    };
    ( @register $registry:ident, tcp $name:expr => $factory:expr ) => {
        $registry.register(
            $name,
            $crate::FilterFactory::Tcp(
                ::std::sync::Arc::new(move |config: &serde_yaml::Value| {
                    ($factory)(config)
                }),
            ),
        ).unwrap_or_else(|_| panic!("duplicate filter name: '{}'", $name));
    };
    ( @register $registry:ident, connection $name:expr => $factory:expr ) => {
        $registry.register(
            $name,
            $crate::FilterFactory::Connection(
                ::std::sync::Arc::new(move |config: &serde_yaml::Value| {
                    ($factory)(config)
                }),
            ),
        ).unwrap_or_else(|_| panic!("duplicate filter name: '{}'", $name));
    };
    ( $( $kind:ident $name:expr => $factory:expr ),* $(,)? ) => {
        /// Build a custom filter registry with builtins and user-registered filters.
        pub fn custom_registry() -> $crate::FilterRegistry {
            let mut registry = $crate::FilterRegistry::with_builtins();
            $(
                $crate::register_filters!(@register registry, $kind $name => $factory);
            )*
            registry
        }
    };
}

// -----------------------------------------------------------------------------
// External Filter Export
// -----------------------------------------------------------------------------

/// Macro for exporting filters from an external crate for build-time
/// auto-discovery.
///
/// External filter crates use this macro to declare which filters they
/// provide. The generated `register_filters` function is called
/// automatically by the Praxis server when the crate is listed as a
/// dependency with a `[package.metadata.praxis-filters]` marker in
/// its `Cargo.toml`.
///
/// ```ignore
/// use praxis_filter::export_filters;
///
/// export_filters! {
///     http "my_auth" => MyAuthFilter::from_config,
///     tcp  "my_tcp_logger" => MyTcpLogger::from_config,
/// }
/// ```
///
/// The external crate's `Cargo.toml` must also include:
///
/// ```toml
/// [package.metadata.praxis-filters]
/// ```
///
/// With these two pieces in place, adding the crate as a dependency
/// to the Praxis server is sufficient to make the filters available
/// in YAML configuration.
#[macro_export]
macro_rules! export_filters {
    ( $( $kind:ident $name:expr => $factory:expr ),* $(,)? ) => {
        /// Register this crate's filters into a Praxis [`FilterRegistry`].
        ///
        /// Called automatically by the Praxis build-time filter discovery
        /// system. Can also be called manually for testing or custom
        /// server builds.
        ///
        /// # Panics
        ///
        /// Panics if any filter name collides with an already-registered
        /// filter (built-in or from another external crate).
        ///
        /// [`FilterRegistry`]: $crate::FilterRegistry
        pub fn register_filters(registry: &mut $crate::FilterRegistry) {
            $(
                $crate::register_filters!(@register registry, $kind $name => $factory);
            )*
        }
    };
}

// -----------------------------------------------------------------------------
// Macro Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unnecessary_wraps,
    reason = "internal pub items re-exported selectively; test module"
)]
mod macro_tests {
    use async_trait::async_trait;

    use crate::{FilterAction, FilterError, HttpFilter, HttpFilterContext, TcpFilter};

    #[test]
    fn macro_registers_http_filter() {
        let registry = custom_registry();
        assert!(
            registry.available_filters().contains(&"dummy_http"),
            "registry should contain custom HTTP filter"
        );
    }

    #[test]
    fn macro_registers_tcp_filter() {
        let registry = custom_registry();
        assert!(
            registry.available_filters().contains(&"dummy_tcp"),
            "registry should contain custom TCP filter"
        );
    }

    #[test]
    fn macro_registers_http_filter_with_name_expression() {
        let mut registry = crate::FilterRegistry::with_builtins();
        let name = String::from("dummy_http_expr");
        register_filters!(@register registry, http name.as_str() => DummyHttpFilter::from_config);
        assert!(
            registry.available_filters().contains(&"dummy_http_expr"),
            "registry should contain custom HTTP filter registered with a name expression"
        );
    }

    #[test]
    fn macro_registers_tcp_filter_with_name_expression() {
        let mut registry = crate::FilterRegistry::with_builtins();
        let name = String::from("dummy_tcp_expr");
        register_filters!(@register registry, tcp name.as_str() => DummyTcpFilter::from_config);
        assert!(
            registry.available_filters().contains(&"dummy_tcp_expr"),
            "registry should contain custom TCP filter registered with a name expression"
        );
    }

    #[test]
    fn macro_preserves_builtins() {
        let registry = custom_registry();
        assert!(
            registry.available_filters().contains(&"router"),
            "registry should still contain built-in router"
        );
        assert!(
            registry.available_filters().contains(&"load_balancer"),
            "registry should still contain built-in load_balancer"
        );
    }

    #[test]
    fn macro_registered_http_filter_creates_successfully() {
        let registry = custom_registry();
        let result = registry.create("dummy_http", &serde_yaml::Value::Null);
        assert!(result.is_ok(), "custom HTTP filter should instantiate without error");
    }

    #[test]
    fn macro_registered_tcp_filter_creates_successfully() {
        let registry = custom_registry();
        let result = registry.create("dummy_tcp", &serde_yaml::Value::Null);
        assert!(result.is_ok(), "custom TCP filter should instantiate without error");
    }

    #[test]
    #[should_panic(expected = "duplicate filter name: 'router'")]
    fn macro_panics_on_builtin_collision() {
        let mut registry = crate::FilterRegistry::with_builtins();
        register_filters!(@register registry, http "router" => DummyHttpFilter::from_config);
    }

    // -------------------------------------------------------------------------
    // export_filters! tests
    // -------------------------------------------------------------------------

    #[test]
    fn export_filters_registers_http() {
        let mut registry = crate::FilterRegistry::with_builtins();
        export_test::register_filters(&mut registry);
        assert!(
            registry.available_filters().contains(&"exported_http"),
            "exported HTTP filter should be registered"
        );
    }

    #[test]
    fn export_filters_registers_tcp() {
        let mut registry = crate::FilterRegistry::with_builtins();
        export_test::register_filters(&mut registry);
        assert!(
            registry.available_filters().contains(&"exported_tcp"),
            "exported TCP filter should be registered"
        );
    }

    #[test]
    fn export_filters_preserves_builtins() {
        let mut registry = crate::FilterRegistry::with_builtins();
        export_test::register_filters(&mut registry);
        assert!(
            registry.available_filters().contains(&"router"),
            "built-in router should still be registered"
        );
    }

    #[test]
    fn export_filters_creates_http_filter_successfully() {
        let mut registry = crate::FilterRegistry::with_builtins();
        export_test::register_filters(&mut registry);
        let result = registry.create("exported_http", &serde_yaml::Value::Null);
        assert!(result.is_ok(), "exported HTTP filter should instantiate without error");
    }

    #[test]
    fn export_filters_creates_tcp_filter_successfully() {
        let mut registry = crate::FilterRegistry::with_builtins();
        export_test::register_filters(&mut registry);
        let result = registry.create("exported_tcp", &serde_yaml::Value::Null);
        assert!(result.is_ok(), "exported TCP filter should instantiate without error");
    }

    #[test]
    #[should_panic(expected = "duplicate filter name: 'router'")]
    fn export_filters_panics_on_builtin_collision() {
        mod collision {
            use super::*;

            export_filters! {
                http "router" => DummyHttpFilter::from_config,
            }
        }
        let mut registry = crate::FilterRegistry::with_builtins();
        collision::register_filters(&mut registry);
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    register_filters! {
        http "dummy_http" => DummyHttpFilter::from_config,
        tcp  "dummy_tcp"  => DummyTcpFilter::from_config,
    }

    mod export_test {
        use super::*;

        export_filters! {
            http "exported_http" => DummyHttpFilter::from_config,
            tcp  "exported_tcp"  => DummyTcpFilter::from_config,
        }
    }

    /// Dummy HTTP filter for macro testing.
    struct DummyHttpFilter;

    #[async_trait]
    impl HttpFilter for DummyHttpFilter {
        fn name(&self) -> &'static str {
            "dummy_http"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    impl DummyHttpFilter {
        fn from_config(_: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
            Ok(Box::new(Self))
        }
    }

    /// Dummy TCP filter for macro testing.
    struct DummyTcpFilter;

    #[async_trait]
    impl TcpFilter for DummyTcpFilter {
        fn name(&self) -> &'static str {
            "dummy_tcp"
        }
    }

    impl DummyTcpFilter {
        fn from_config(_: &serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError> {
            Ok(Box::new(Self))
        }
    }
}
