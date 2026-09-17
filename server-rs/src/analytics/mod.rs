//! Analytics reads: the shared query layer every analytics route builds on,
//! ported from server/src/api/analytics/{types.ts,utils/,segments/}.
//!
//! Routes are ported later and must answer byte-identical JSON, so these
//! builders reproduce Node's SQL text exactly (same whitespace, same
//! `SqlString.escape` output, same ClickHouse parameter spellings) and the same
//! validation errors. Request values are taken as [`js::JsValue`] where Node
//! reads them straight off `request.query` (strings, or arrays of strings for a
//! repeated query param) so JavaScript coercions carry over.
#![allow(dead_code)] // consumed as the analytics routes are ported

pub mod js;
pub mod segments;
pub mod sql_string;
pub mod types;
pub mod utils;

#[cfg(test)]
mod parity_tests;
