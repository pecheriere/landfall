//! JSON kept as its text.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// A JSON value kept as the text it was read from or written as, never as a tree: a tree of
/// hostile JSON takes many times its size in memory. Two are equal when their texts are.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RawJson(Box<RawValue>);

impl RawJson {
    /// `value`'s text.
    ///
    /// # Errors
    ///
    /// What serialising it gives, which for a `serde_json::Value` is nothing in practice.
    pub fn from_value(value: &serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::value::to_raw_value(value).map(Self)
    }

    /// The text, as it was read or written: hostile when it came from a controller.
    #[must_use]
    pub fn get(&self) -> &str {
        self.0.get()
    }
}

impl PartialEq for RawJson {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl Eq for RawJson {}
