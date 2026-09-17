//! The tracking pipeline glue, ported from server/src/services/tracker
//! (trackEvent, trackingRequest, ingestEvent, utils.createBasePayload and the queues).
#![allow(dead_code)] // wired into routes once the stage modules land

pub mod queue;
