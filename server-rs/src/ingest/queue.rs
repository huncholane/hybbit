//! Batched ClickHouse writers, ported from PageviewQueue
//! (server/src/services/tracker/pageviewQueue.ts) and BotEventQueue
//! (server/src/services/tracker/botBlocking/botEventQueue.ts).
//!
//! Rows accumulate in memory and are inserted as JSONEachRow once a second, at most
//! 5000 per insert. A failed insert drops its batch, as in Node. Unlike Node, the
//! process drains what is still buffered on shutdown instead of losing up to a
//! second of events on every deploy.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use serde::Serialize;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info};

use crate::clickhouse::ClickHouse;

pub const BATCH_SIZE: usize = 5000;
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(1000);

pub struct EventQueue<T> {
    table: &'static str,
    /// Node's service logger name, kept as the `queue` field of every log line
    name: &'static str,
    rows: Mutex<Vec<T>>,
    /// Held across a flush so the timer and a shutdown drain never insert concurrently
    flushing: tokio::sync::Mutex<()>,
}

impl<T: Serialize + Send + Sync + 'static> EventQueue<T> {
    pub fn new(table: &'static str, name: &'static str) -> Arc<Self> {
        Arc::new(Self { table, name, rows: Mutex::new(Vec::new()), flushing: tokio::sync::Mutex::new(()) })
    }

    pub fn add(&self, row: T) {
        self.lock().push(row);
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<T>> {
        self.rows.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Start the once-a-second flush timer.
    pub fn spawn(self: &Arc<Self>, clickhouse: ClickHouse) {
        let queue = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
            // setInterval skips ticks while a flush is still running
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                queue.flush_batch(&clickhouse).await;
            }
        });
        info!(queue = self.name, table = self.table, "Event queue started");
    }

    /// `processQueue`: insert up to one batch. Returns how many rows were taken.
    pub async fn flush_batch(&self, clickhouse: &ClickHouse) -> usize {
        let Ok(_guard) = self.flushing.try_lock() else { return 0 };
        let batch: Vec<T> = {
            let mut rows = self.lock();
            let take = rows.len().min(BATCH_SIZE);
            rows.drain(..take).collect()
        };
        if batch.is_empty() {
            return 0;
        }

        let count = batch.len();
        match clickhouse.insert(self.table, &batch).await {
            Ok(()) => debug!(queue = self.name, table = self.table, count, "Bulk insert to ClickHouse"),
            Err(error) => error!(queue = self.name, table = self.table, count, error = %error, "Error processing queue, batch dropped"),
        }
        count
    }

    /// Flush everything still buffered, batch by batch (shutdown).
    pub async fn drain(&self, clickhouse: &ClickHouse) {
        let pending = self.len();
        if pending == 0 {
            return;
        }
        info!(queue = self.name, table = self.table, pending, "Draining event queue");
        // Every pass removes a batch (inserted or dropped), so this terminates even
        // with ClickHouse down; waiting on the lock first lets an in-flight timer
        // flush finish instead of making flush_batch skip
        while self.len() > 0 {
            drop(self.flushing.lock().await);
            self.flush_batch(clickhouse).await;
        }
    }
}
