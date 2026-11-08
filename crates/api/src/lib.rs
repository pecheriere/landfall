//! The wire types of landfall's `/api/v1`: what the controller serialises and the CLI reads.
//! No I/O.
//!
//! Within `/api/v1`, fields and enum values are only ever added. So a type here ignores
//! fields it doesn't know when it reads an answer, and each enum that can grow has an
//! `Unknown` variant for a value from a newer controller, which no controller sends and the
//! schema leaves out. What a client sends is still refused if it has a field the controller
//! doesn't know.
//!
//! The `openapi` feature derives each type's OpenAPI schema. Core identifiers appear as
//! themselves, validated when they are read, and as strings in the schema.

mod page;
mod problem;
mod requests;

pub use page::Page;
pub use problem::{Problem, ProblemCode};
pub use requests::{
    ApprovalsView, Approved, AssertionBody, Cancelled, IntentView, NewApproval, NewRequest,
    RequestState, RequestView,
};

#[cfg(test)]
mod tests;
