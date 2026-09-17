//! Feature flags, ported from server/src/services/featureFlags/ and the evaluate
//! request core of server/src/api/featureFlags/index.ts.
//!
//! - [`definitions`]: the per-Site definitions cache shared with Node in Redis
//! - [`evaluator`]: turning definitions and a visitor context into assignments
//! - [`regex`]: validating, compiling and caching regex targeting rules
//! - [`schemas`]: request body validation with zod's issue objects
//! - [`evaluate`]: `POST .../feature-flags/evaluate` minus the HTTP plumbing
//! - [`query`]: Node's `URLSearchParams` parsing for the evaluate body's querystring
//! - [`js`]: the JavaScript value semantics all of the above rely on
#![allow(dead_code)] // the evaluate and CRUD routes are wired in later phases

pub mod definitions;
pub mod evaluate;
pub mod evaluator;
pub mod js;
pub mod query;
pub mod regex;
pub mod schemas;

#[cfg(test)]
mod parity;

pub use definitions::has_feature_flags_for_runtime;
