use std::fmt;

use serde::{Deserialize, Serialize};

/// The position of an event in the change feed.
///
/// Cursors increase strictly with every event but may have gaps, so they are
/// only meaningful for ordering and resuming, never for counting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema), schema(value_type = i64))]
pub struct Cursor(i64);

impl Cursor {
    /// The cursor before every event.
    pub const START: Self = Self(0);

    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
