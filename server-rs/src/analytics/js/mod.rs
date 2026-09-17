//! JavaScript semantics the analytics query layer depends on.
//!
//! The Node query builders lean on engine behaviour that has no counterpart in
//! Rust's standard library: `Number(string)`, `parseInt`, `Date.parse` (including
//! V8's legacy fallback parser), `new RegExp(pattern)` syntax errors, `Intl`
//! time zone validation, `JSON.parse` key ordering and zod's issue objects. Every
//! item here ports the V8 13.6 (Node 24, production) implementation so the SQL,
//! the validation errors and the JSON bodies built on top of it match Node byte
//! for byte. Differences that cannot be represented (Rust strings cannot hold
//! lone UTF-16 surrogates) are called out where they matter.

pub mod date;
pub mod intl;
pub mod json;
pub mod number;
pub mod regexp;
pub mod string;
pub(crate) mod unicode_tables;
pub mod value;
pub mod zod;

pub use value::{JsObject, JsValue};
