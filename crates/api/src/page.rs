//! One page of a list that can grow.

use serde::{Deserialize, Serialize};

/// Some of a list, in its order, and where the rest begins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Page<T> {
    /// This page's items.
    pub items: Vec<T>,
    /// What to send as `cursor` for the next page, opaque; `null` on the last one.
    pub next_cursor: Option<String>,
}
