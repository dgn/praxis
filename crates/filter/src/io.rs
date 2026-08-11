// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Type-erased async IO for protocol-agnostic stream handling.

use tokio::io::{AsyncRead, AsyncWrite};

/// Marker trait for async IO streams.
pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}

/// A type-erased async IO stream.
pub type BoxedIo = Box<dyn IoStream>;
