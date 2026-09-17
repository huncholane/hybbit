//! The identity backfill queue, ported from
//! server/src/services/tracker/identityBackfillQueue.ts.
//!
//! Each identify used to submit three `ALTER TABLE … UPDATE` mutations at once,
//! and mutation submission takes the MergeTree parts lock: at production identify
//! rates that lock was taken every ~12 seconds per table, stalling inserts and
//! selects. The queue collapses an interval's worth of identities into one
//! mutation per table, flushing every five minutes, early at 5000 identities, and
//! completely at shutdown.
//!
//! Every backend process owns its own queue (PORT_PLAN.md, background work): Node
//! flushes what Node accepted and Rust flushes what Rust accepted.

use std::{future::Future, sync::Arc, time::Duration};

use indexmap::IndexMap;
use tokio::task::JoinHandle;

use crate::clickhouse::ClickHouse;

/// `FLUSH_INTERVAL_MS`
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// `MAX_IDENTITIES_PER_MUTATION`: bounds one statement; crossing it at enqueue
/// triggers an early flush, and a larger backlog splits into several mutations.
pub const MAX_IDENTITIES_PER_MUTATION: usize = 5000;
/// `MAX_ATTEMPTS`: a permanently failing assignment must not circulate forever.
pub const MAX_ATTEMPTS: u32 = 3;
/// `BACKFILL_DAYS` in identifyService.ts: the routine window. Only an explicit
/// dashboard identify backfills the full history (`None`).
pub const BACKFILL_DAYS: u32 = 30;

/// `TABLES`: each table with its time column (`session_replay_metadata_v2` has
/// no `timestamp`, and naming one there throws UNKNOWN_IDENTIFIER).
const TABLES: [(&str, &str); 3] =
    [("events", "timestamp"), ("session_replay_events", "timestamp"), ("session_replay_metadata_v2", "start_time")];

/// `IdentityAssignment`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityAssignment {
    pub site_id: i32,
    pub anonymous_id: String,
    pub user_id: String,
}

#[derive(Clone, Debug)]
struct PendingIdentity {
    assignment: IdentityAssignment,
    attempts: u32,
}

/// Where mutations go: ClickHouse in production, a recorder in tests (the Node
/// tests mock `clickhouse.command`). `params` are `query_params` already
/// formatted the way @clickhouse/client formats them.
pub trait BackfillSink: Send + Sync + 'static {
    fn command(&self, query: String, params: Vec<(String, String)>) -> impl Future<Output = anyhow::Result<()>> + Send;
}

impl BackfillSink for ClickHouse {
    async fn command(&self, query: String, params: Vec<(String, String)>) -> anyhow::Result<()> {
        let params: Vec<(&str, String)> = params.iter().map(|(name, value)| (name.as_str(), value.clone())).collect();
        self.query::<serde_json::Value>(&query, &params).await?;
        Ok(())
    }
}

type PendingGroups = IndexMap<Option<u32>, IndexMap<String, PendingIdentity>>;

struct Inner<S> {
    sink: S,
    /// Grouped by backfill window, which is part of the mutation's WHERE clause:
    /// folding a full-history backfill in with the 30-day ones would widen them all.
    pending: std::sync::Mutex<PendingGroups>,
    /// Serialises flushes the way Node chains them on one promise: a flush that
    /// starts while another is running waits for it instead of returning early,
    /// so shutdown's flush really covers work in flight.
    chain: tokio::sync::Mutex<()>,
}

/// `IdentityBackfillQueue`. Cheap to clone; clones share one queue.
pub struct IdentityBackfillQueue<S: BackfillSink = ClickHouse> {
    inner: Arc<Inner<S>>,
}

impl<S: BackfillSink> Clone for IdentityBackfillQueue<S> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

/// `formatQueryParams` of @clickhouse/client for a string: tab, newline, carriage
/// return, single quote and backslash are backslash-escaped.
fn escape_param_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\t' => escaped.push_str("\\t"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\'' => escaped.push_str("\\'"),
            '\\' => escaped.push_str("\\\\"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// `formatQueryParams` for an array of strings: `['a','b']`.
pub(crate) fn format_string_array_param(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|value| format!("'{}'", escape_param_string(value))).collect();
    format!("[{}]", items.join(","))
}

/// `formatQueryParams` for an array of numbers: `[1,2]`.
pub(crate) fn format_number_array_param(values: &[i32]) -> String {
    let items: Vec<String> = values.iter().map(i32::to_string).collect();
    format!("[{}]", items.join(","))
}

/// The mutation Node submits, after @clickhouse/client's `query.trim()`.
pub(crate) fn backfill_mutation(table: &str, time_column: &str, days: Option<u32>) -> String {
    let window = match days {
        Some(_) => format!("\n              AND {time_column} >= now() - INTERVAL {{days: UInt16}} DAY"),
        None => String::new(),
    };
    format!(
        "ALTER TABLE {table}
            UPDATE identified_user_id = transform(
              concat(toString(site_id), ':', user_id),
              {{keys: Array(String)}},
              {{userIds: Array(String)}},
              identified_user_id
            )
            WHERE site_id IN {{siteIds: Array(UInt16)}}
              AND concat(toString(site_id), ':', user_id) IN {{keys: Array(String)}}
              AND identified_user_id = ''{window}"
    )
}

impl<S: BackfillSink> IdentityBackfillQueue<S> {
    pub fn new(sink: S) -> Self {
        Self {
            inner: Arc::new(Inner {
                sink,
                pending: std::sync::Mutex::new(IndexMap::new()),
                chain: tokio::sync::Mutex::new(()),
            }),
        }
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, PendingGroups> {
        self.inner.pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Starts the five-minute flush timer (Node's constructor `setInterval`). The
    /// first flush runs one interval after start. Call once at startup; drain with
    /// `drain_completely` at shutdown.
    pub fn start_flush_timer(&self) -> JoinHandle<()> {
        let queue = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + FLUSH_INTERVAL, FLUSH_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tracing::info!(interval_seconds = FLUSH_INTERVAL.as_secs(), "Identity backfill flush timer started");
            loop {
                ticker.tick().await;
                queue.flush().await;
            }
        })
    }

    /// `enqueue`: buffer one assignment; a group reaching the mutation size starts
    /// a flush in the background.
    pub fn enqueue(&self, assignment: IdentityAssignment, days: Option<u32>) {
        let group_size = self.add(PendingIdentity { assignment, attempts: 0 }, days);

        if group_size >= MAX_IDENTITIES_PER_MUTATION {
            tracing::debug!(identities = group_size, days, "Identity backfill group full, flushing early");
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => {
                    let queue = self.clone();
                    runtime.spawn(async move { queue.flush().await });
                }
                Err(_) => tracing::warn!("Identity backfill group full outside a runtime; waiting for the timer"),
            }
        }
    }

    /// `add`: the first assignment for a device wins within a window, matching the
    /// un-batched behaviour (the mutation only touches rows still unidentified).
    /// Returns the group's size afterwards.
    fn add(&self, entry: PendingIdentity, days: Option<u32>) -> usize {
        let key = format!("{}:{}", entry.assignment.site_id, entry.assignment.anonymous_id);
        let mut pending = self.pending();
        let group = pending.entry(days).or_default();
        group.entry(key).or_insert(entry);
        group.len()
    }

    /// `flush`: resolves once everything queued at call time has been attempted.
    pub async fn flush(&self) {
        let _chain = self.inner.chain.lock().await;
        self.drain().await;
    }

    /// `drainCompletely`: flush until nothing is left to retry, at most
    /// `MAX_ATTEMPTS` rounds. Only for shutdown, where there is no next interval.
    pub async fn drain_completely(&self) {
        for round in 0..MAX_ATTEMPTS {
            self.flush().await;
            if self.pending().is_empty() {
                tracing::info!(rounds = round + 1, "Identity backfill queue drained");
                return;
            }
        }
        let left: usize = self.pending().values().map(IndexMap::len).sum();
        tracing::warn!(identities = left, "Identity backfill queue not fully drained at shutdown");
    }

    /// How many assignments are waiting, across windows.
    pub fn pending_len(&self) -> usize {
        self.pending().values().map(IndexMap::len).sum()
    }

    /// Every waiting assignment with its window and attempt count, in queue order.
    #[cfg(test)]
    pub(crate) fn pending_snapshot(&self) -> Vec<(Option<u32>, IdentityAssignment, u32)> {
        self.pending()
            .iter()
            .flat_map(|(days, group)| group.values().map(|entry| (*days, entry.assignment.clone(), entry.attempts)))
            .collect()
    }

    async fn drain(&self) {
        let groups: Vec<(Option<u32>, Vec<PendingIdentity>)> = {
            let mut pending = self.pending();
            let taken = std::mem::take(&mut *pending);
            taken
                .into_iter()
                .filter(|(_, assignments)| !assignments.is_empty())
                .map(|(days, assignments)| (days, assignments.into_values().collect()))
                .collect()
        };
        if groups.is_empty() {
            return;
        }

        for (days, assignments) in groups {
            for chunk in assignments.chunks(MAX_IDENTITIES_PER_MUTATION) {
                self.run_backfill(days, chunk).await;
            }
        }
    }

    /// `runBackfill`: one mutation per table for a batch. Keys pair the Site with
    /// the anonymous id so one Site's list cannot match another Site's rows, while
    /// `site_id IN (…)` keeps the primary-key prefix usable.
    async fn run_backfill(&self, days: Option<u32>, assignments: &[PendingIdentity]) {
        let keys: Vec<String> = assignments
            .iter()
            .map(|entry| format!("{}:{}", entry.assignment.site_id, entry.assignment.anonymous_id))
            .collect();
        let user_ids: Vec<String> = assignments.iter().map(|entry| entry.assignment.user_id.clone()).collect();
        let mut site_ids: Vec<i32> = Vec::new();
        for entry in assignments {
            if !site_ids.contains(&entry.assignment.site_id) {
                site_ids.push(entry.assignment.site_id);
            }
        }

        let mut params = vec![
            ("keys".to_string(), format_string_array_param(&keys)),
            ("userIds".to_string(), format_string_array_param(&user_ids)),
            ("siteIds".to_string(), format_number_array_param(&site_ids)),
        ];
        if let Some(days) = days {
            params.push(("days".to_string(), days.to_string()));
        }

        let mut failed_tables: Vec<&str> = Vec::new();
        for (table, time_column) in TABLES {
            let query = backfill_mutation(table, time_column, days);
            if let Err(error) = self.inner.sink.command(query, params.clone()).await {
                failed_tables.push(table);
                tracing::error!(
                    table,
                    identities = assignments.len(),
                    days,
                    error = %format!("{error:#}"),
                    "Error backfilling identified_user_id"
                );
            }
        }

        if failed_tables.is_empty() {
            tracing::info!(identities = assignments.len(), days, "Flushed identity backfill");
            return;
        }

        // Requeue rather than drop: the alias row already exists, so a later
        // identify for the device never schedules another backfill.
        let mut requeued = 0;
        for entry in assignments {
            if entry.attempts + 1 < MAX_ATTEMPTS {
                self.add(PendingIdentity { assignment: entry.assignment.clone(), attempts: entry.attempts + 1 }, days);
                requeued += 1;
            }
        }
        let dropped = assignments.len() - requeued;

        tracing::warn!(
            failed_tables = ?failed_tables,
            requeued,
            dropped,
            days,
            "Identity backfill partially failed"
        );
        if dropped > 0 {
            tracing::error!(
                dropped,
                days,
                max_attempts = MAX_ATTEMPTS,
                "Giving up on identity backfill; those rows stay anonymous"
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! Port of server/src/services/tracker/identityBackfillQueue.test.ts.

    use std::{collections::VecDeque, sync::Mutex};

    use anyhow::anyhow;
    use tokio::sync::oneshot;

    use super::*;

    const TABLE_COUNT: usize = 3;

    #[derive(Clone, Debug)]
    pub(crate) struct Command {
        pub query: String,
        pub params: Vec<(String, String)>,
    }

    impl Command {
        pub fn param(&self, name: &str) -> Option<&str> {
            self.params.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
        }
    }

    enum Reply {
        Fail,
        Wait(oneshot::Receiver<()>),
    }

    /// Records commands; replies succeed unless scripted (`mockRejectedValueOnce`,
    /// `mockRejectedValue`, `mockReturnValueOnce(deferred)`).
    #[derive(Default)]
    pub(crate) struct RecordingSink {
        pub commands: Mutex<Vec<Command>>,
        once: Mutex<VecDeque<Reply>>,
        always_fail: Mutex<bool>,
    }

    impl RecordingSink {
        fn reset(&self) {
            self.commands.lock().unwrap().clear();
            self.once.lock().unwrap().clear();
            *self.always_fail.lock().unwrap() = false;
        }

        fn fail_once(&self) {
            self.once.lock().unwrap().push_back(Reply::Fail);
        }

        fn fail_always(&self) {
            *self.always_fail.lock().unwrap() = true;
        }

        fn wait_once(&self) -> oneshot::Sender<()> {
            let (sender, receiver) = oneshot::channel();
            self.once.lock().unwrap().push_back(Reply::Wait(receiver));
            sender
        }

        pub fn commands(&self) -> Vec<Command> {
            self.commands.lock().unwrap().clone()
        }

        fn count(&self) -> usize {
            self.commands.lock().unwrap().len()
        }
    }

    impl BackfillSink for Arc<RecordingSink> {
        fn command(
            &self,
            query: String,
            params: Vec<(String, String)>,
        ) -> impl Future<Output = anyhow::Result<()>> + Send {
            self.commands.lock().unwrap().push(Command { query, params });
            let reply = self.once.lock().unwrap().pop_front();
            let always_fail = *self.always_fail.lock().unwrap();
            async move {
                match reply {
                    Some(Reply::Fail) => Err(anyhow!("ClickHouse timeout")),
                    Some(Reply::Wait(receiver)) => {
                        let _ = receiver.await;
                        Ok(())
                    }
                    None if always_fail => Err(anyhow!("ClickHouse down")),
                    None => Ok(()),
                }
            }
        }
    }

    fn fixture() -> (Arc<RecordingSink>, IdentityBackfillQueue<Arc<RecordingSink>>) {
        let sink = Arc::new(RecordingSink::default());
        (sink.clone(), IdentityBackfillQueue::new(sink))
    }

    fn assignment(anonymous_id: &str, user_id: &str) -> IdentityAssignment {
        IdentityAssignment { site_id: 7, anonymous_id: anonymous_id.to_string(), user_id: user_id.to_string() }
    }

    #[tokio::test]
    async fn collapses_many_identifies_into_one_mutation_per_table() {
        let (sink, queue) = fixture();
        queue.enqueue(assignment("anon-a", "user-a"), Some(30));
        queue.enqueue(assignment("anon-b", "user-b"), Some(30));

        queue.flush().await;

        let commands = sink.commands();
        assert_eq!(commands.len(), TABLE_COUNT);
        for command in &commands {
            assert_eq!(command.param("keys"), Some("['7:anon-a','7:anon-b']"));
        }
    }

    #[tokio::test]
    async fn keeps_the_first_assignment_when_a_device_identifies_twice_in_a_window() {
        let (sink, queue) = fixture();
        queue.enqueue(assignment("anon-a", "first"), Some(30));
        queue.enqueue(assignment("anon-a", "second"), Some(30));

        queue.flush().await;

        assert_eq!(sink.commands()[0].param("userIds"), Some("['first']"));
    }

    #[tokio::test]
    async fn keeps_windows_apart_so_an_all_history_backfill_does_not_widen_the_routine_ones() {
        let (sink, queue) = fixture();
        queue.enqueue(assignment("anon-a", "user-a"), Some(30));
        queue.enqueue(assignment("anon-b", "user-b"), None);

        queue.flush().await;

        let commands = sink.commands();
        let windowed: Vec<_> = commands.iter().filter(|command| command.param("days") == Some("30")).collect();
        let unbounded: Vec<_> = commands.iter().filter(|command| command.param("days").is_none()).collect();
        assert_eq!(windowed.len(), TABLE_COUNT);
        assert_eq!(unbounded.len(), TABLE_COUNT);
        assert!(windowed[0].query.contains("INTERVAL {days: UInt16} DAY"));
        assert!(!unbounded[0].query.contains("INTERVAL"));
    }

    #[tokio::test]
    async fn retries_assignments_whose_mutation_failed_instead_of_dropping_them() {
        let (sink, queue) = fixture();
        sink.fail_once();

        queue.enqueue(assignment("anon-a", "user-a"), Some(30));
        queue.flush().await;
        assert_eq!(sink.count(), TABLE_COUNT);

        sink.reset();
        queue.flush().await;

        assert_eq!(sink.count(), TABLE_COUNT);
        assert_eq!(sink.commands()[0].param("keys"), Some("['7:anon-a']"));
    }

    #[tokio::test]
    async fn gives_up_after_repeated_failures_rather_than_retrying_forever() {
        let (sink, queue) = fixture();
        queue.enqueue(assignment("anon-a", "user-a"), Some(30));

        for _ in 0..3 {
            sink.reset();
            sink.fail_always();
            queue.flush().await;
            assert_eq!(sink.count(), TABLE_COUNT);
        }

        sink.reset();
        queue.flush().await;
        assert_eq!(sink.count(), 0);
    }

    #[tokio::test]
    async fn drains_identities_that_arrived_while_a_flush_was_in_progress() {
        let (sink, queue) = fixture();
        let release = sink.wait_once();

        queue.enqueue(assignment("anon-a", "user-a"), Some(30));
        let first = tokio::spawn({
            let queue = queue.clone();
            async move { queue.flush().await }
        });
        wait_for_commands(&sink, 1).await;

        // Arrives after the first flush took its snapshot
        queue.enqueue(assignment("anon-b", "user-b"), Some(30));

        release.send(()).unwrap();
        first.await.unwrap();
        queue.flush().await;

        let all_keys: String = sink.commands().iter().filter_map(|command| command.param("keys")).collect();
        assert!(all_keys.contains("7:anon-a"));
        assert!(all_keys.contains("7:anon-b"));
    }

    #[tokio::test]
    async fn waits_for_an_in_flight_flush_so_shutdown_does_not_abandon_it() {
        let (sink, queue) = fixture();
        let release = sink.wait_once();

        queue.enqueue(assignment("anon-a", "user-a"), Some(30));
        let first = tokio::spawn({
            let queue = queue.clone();
            async move { queue.flush().await }
        });
        wait_for_commands(&sink, 1).await;

        let shutdown = tokio::spawn({
            let queue = queue.clone();
            async move { queue.flush().await }
        });

        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!shutdown.is_finished());

        release.send(()).unwrap();
        first.await.unwrap();
        shutdown.await.unwrap();
    }

    #[tokio::test]
    async fn splits_an_oversized_backlog_across_several_mutations() {
        let (sink, queue) = fixture();
        let release = sink.wait_once();

        queue.enqueue(assignment("held", "u"), Some(30));
        let first = tokio::spawn({
            let queue = queue.clone();
            async move { queue.flush().await }
        });
        wait_for_commands(&sink, 1).await;

        for i in 0..5001 {
            queue.enqueue(assignment(&format!("anon-{i}"), &format!("user-{i}")), Some(30));
        }

        release.send(()).unwrap();
        first.await.unwrap();
        // Let the size-triggered flushes queue up behind the chain, then join its end
        tokio::task::yield_now().await;
        queue.flush().await;

        let commands = sink.commands();
        let mut covered = std::collections::HashSet::new();
        for command in &commands {
            let keys = command.param("keys").unwrap();
            let items: Vec<&str> = keys.trim_start_matches('[').trim_end_matches(']').split(',').collect();
            assert!(items.len() <= 5000);
            covered.extend(items.into_iter().map(|item| item.trim_matches('\'').to_string()));
        }
        for i in 0..5001 {
            assert!(covered.contains(&format!("7:anon-{i}")), "anon-{i}");
        }
        assert!(covered.contains("7:held"));
        assert_eq!(queue.pending_len(), 0);
    }

    #[tokio::test]
    async fn retries_a_shutdown_failure_instead_of_exiting_on_top_of_it() {
        let (sink, queue) = fixture();
        sink.fail_once();

        queue.enqueue(assignment("anon-a", "user-a"), Some(30));
        queue.drain_completely().await;

        assert_eq!(sink.count(), TABLE_COUNT * 2);

        sink.reset();
        queue.flush().await;
        assert_eq!(sink.count(), 0);
    }

    #[test]
    fn formats_params_like_clickhouse_client() {
        assert_eq!(
            format_string_array_param(&["7:it's".to_string(), "a\\b\tc\nd\re".to_string()]),
            r"['7:it\'s','a\\b\tc\nd\re']"
        );
        assert_eq!(format_number_array_param(&[7, 65000]), "[7,65000]");
        assert_eq!(format_string_array_param(&[]), "[]");
    }

    #[test]
    fn mutation_text_matches_node_after_trim() {
        assert_eq!(
            backfill_mutation("session_replay_metadata_v2", "start_time", Some(30)),
            "ALTER TABLE session_replay_metadata_v2\n            UPDATE identified_user_id = transform(\n              concat(toString(site_id), ':', user_id),\n              {keys: Array(String)},\n              {userIds: Array(String)},\n              identified_user_id\n            )\n            WHERE site_id IN {siteIds: Array(UInt16)}\n              AND concat(toString(site_id), ':', user_id) IN {keys: Array(String)}\n              AND identified_user_id = ''\n              AND start_time >= now() - INTERVAL {days: UInt16} DAY"
        );
        assert!(backfill_mutation("events", "timestamp", None).ends_with("AND identified_user_id = ''"));
    }

    async fn wait_for_commands(sink: &RecordingSink, count: usize) {
        for _ in 0..500 {
            if sink.count() >= count {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("sink never saw {count} commands");
    }
}
