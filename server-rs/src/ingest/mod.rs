//! The tracking pipeline glue, ported from server/src/services/tracker
//! (trackEvent, trackingRequest, ingestEvent, utils.createBasePayload and the
//! pageview and bot event queues). The stages themselves live in `tracking`,
//! `bot`, `identity` and `ua`; this module holds their order and the rows they
//! produce.

pub mod pipeline;
pub mod queue;
pub mod request;
pub mod rows;

use std::sync::Arc;

use redis::aio::ConnectionManager;
use serde_json::Value;
use tracing::info;

use crate::{
    bot::{BotBlocking, detection_stats::spawn_bot_detection_stats_flush, site_baseline::spawn_site_baseline_refresh},
    clickhouse::ClickHouse,
    identity::{IdentityBackfillQueue, SessionsService, UserIdService},
};
use queue::EventQueue;

/// Process-wide ingestion services (Node's module singletons).
pub struct Ingest {
    pub bot: BotBlocking,
    pub user_ids: UserIdService,
    pub sessions: SessionsService,
    pub backfill: IdentityBackfillQueue,
    /// `pageviewQueue`: every tracked event, into `events`
    pub events: Arc<EventQueue<Value>>,
    /// `botEventQueue`: enforced detections, into `bot_events`
    pub bot_events: Arc<EventQueue<Value>>,
    /// `botObservationQueue`: detections on sites that do not block bots
    pub bot_observations: Arc<EventQueue<Value>>,
}

impl Ingest {
    pub fn new(redis: ConnectionManager, clickhouse: ClickHouse) -> Self {
        Self {
            bot: BotBlocking::new(Some(redis)),
            user_ids: UserIdService::new(),
            sessions: SessionsService::new(),
            backfill: IdentityBackfillQueue::new(clickhouse),
            events: EventQueue::new("events", "pageview-queue"),
            bot_events: EventQueue::new("bot_events", "bot-event-queue"),
            bot_observations: EventQueue::new("bot_observations", "bot-observation-queue"),
        }
    }

    /// The timers Node starts at boot: queue flushes, the identity backfill flush,
    /// the site baseline refresh (Redis-locked, shared with Node) and bot stats.
    pub fn start(&self, redis: ConnectionManager, clickhouse: ClickHouse) {
        crate::ua::warm_up();
        self.events.spawn(clickhouse.clone());
        self.bot_events.spawn(clickhouse.clone());
        self.bot_observations.spawn(clickhouse.clone());
        self.backfill.start_flush_timer();
        spawn_site_baseline_refresh(self.bot.baselines(), redis.clone(), clickhouse);
        spawn_bot_detection_stats_flush(self.bot.stats.clone(), redis);
        info!("Ingestion services started");
    }

    /// After the listener stops: write what is still buffered. Node drains only the
    /// identity backfills and drops up to a second of events.
    pub async fn shutdown(&self, clickhouse: &ClickHouse) {
        self.events.drain(clickhouse).await;
        self.bot_events.drain(clickhouse).await;
        self.bot_observations.drain(clickhouse).await;
        self.backfill.drain_completely().await;
        info!("Ingestion queues drained");
    }
}
