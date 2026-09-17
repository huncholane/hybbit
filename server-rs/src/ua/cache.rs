//! The bounded LRU cache in front of the parser, ported from the `uaCache` Map in
//! server/src/services/tracker/utils.ts: 10,000 entries, a hit refreshes recency,
//! an insert past the bound evicts the least recently used entry.
//!
//! Node gets LRU order for free from `Map` insertion order; here it is a slab of
//! nodes in a doubly linked list so hits and evictions stay O(1) under the lock.

use std::{collections::HashMap, sync::Arc};

const NIL: usize = usize::MAX;

struct Node<V> {
    key: Arc<str>,
    value: V,
    prev: usize,
    next: usize,
}

pub(super) struct Lru<V> {
    capacity: usize,
    index: HashMap<Arc<str>, usize>,
    nodes: Vec<Node<V>>,
    /// Most recently used.
    head: usize,
    /// Least recently used, the next eviction.
    tail: usize,
}

impl<V: Clone> Lru<V> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self { capacity, index: HashMap::new(), nodes: Vec::new(), head: NIL, tail: NIL }
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Returns the cached value and marks it most recently used.
    pub fn get(&mut self, key: &str) -> Option<V> {
        let slot = *self.index.get(key)?;
        self.unlink(slot);
        self.push_front(slot);
        Some(self.nodes[slot].value.clone())
    }

    /// Inserts (or refreshes) a value, returning the key evicted to make room.
    pub fn insert(&mut self, key: &str, value: V) -> Option<Arc<str>> {
        if let Some(&slot) = self.index.get(key) {
            self.nodes[slot].value = value;
            self.unlink(slot);
            self.push_front(slot);
            return None;
        }
        let key: Arc<str> = Arc::from(key);
        if self.nodes.len() < self.capacity {
            let slot = self.nodes.len();
            self.nodes.push(Node { key: key.clone(), value, prev: NIL, next: NIL });
            self.index.insert(key, slot);
            self.push_front(slot);
            return None;
        }
        // full: reuse the least recently used slot
        let slot = self.tail;
        self.unlink(slot);
        let evicted = std::mem::replace(&mut self.nodes[slot].key, key.clone());
        self.nodes[slot].value = value;
        self.index.remove(&evicted);
        self.index.insert(key, slot);
        self.push_front(slot);
        Some(evicted)
    }

    fn unlink(&mut self, slot: usize) {
        let (prev, next) = (self.nodes[slot].prev, self.nodes[slot].next);
        if prev == NIL {
            self.head = next;
        } else {
            self.nodes[prev].next = next;
        }
        if next == NIL {
            self.tail = prev;
        } else {
            self.nodes[next].prev = prev;
        }
        self.nodes[slot].prev = NIL;
        self.nodes[slot].next = NIL;
    }

    fn push_front(&mut self, slot: usize) {
        self.nodes[slot].next = self.head;
        self.nodes[slot].prev = NIL;
        if self.head != NIL {
            self.nodes[self.head].prev = slot;
        }
        self.head = slot;
        if self.tail == NIL {
            self.tail = slot;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_least_recently_used() {
        let mut lru = Lru::new(3);
        assert_eq!(lru.insert("a", 1), None);
        assert_eq!(lru.insert("b", 2), None);
        assert_eq!(lru.insert("c", 3), None);
        // touching "a" makes "b" the oldest
        assert_eq!(lru.get("a"), Some(1));
        assert_eq!(lru.insert("d", 4).as_deref(), Some("b"));
        assert_eq!(lru.get("b"), None);
        assert_eq!(lru.len(), 3);
        assert_eq!(lru.insert("e", 5).as_deref(), Some("c"));
        assert_eq!(lru.insert("f", 6).as_deref(), Some("a"));
        assert_eq!((lru.get("d"), lru.get("e"), lru.get("f")), (Some(4), Some(5), Some(6)));
    }

    #[test]
    fn capacity_one_and_reinsert() {
        let mut lru = Lru::new(1);
        lru.insert("a", 1);
        assert_eq!(lru.insert("a", 2), None);
        assert_eq!(lru.get("a"), Some(2));
        assert_eq!(lru.insert("b", 3).as_deref(), Some("a"));
        assert_eq!(lru.get("a"), None);
        assert_eq!(lru.get("b"), Some(3));
    }

    #[test]
    fn stays_consistent_under_churn() {
        let mut lru = Lru::new(64);
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let key = format!("k{}", state % 200);
            if state.is_multiple_of(3) {
                lru.get(&key);
            } else {
                lru.insert(&key, state);
            }
            assert!(lru.len() <= 64);
        }
        // walk the list both ways: every indexed node exactly once
        let mut forward = 0;
        let mut slot = lru.head;
        while slot != NIL {
            forward += 1;
            slot = lru.nodes[slot].next;
        }
        let mut backward = 0;
        let mut slot = lru.tail;
        while slot != NIL {
            backward += 1;
            slot = lru.nodes[slot].prev;
        }
        assert_eq!((forward, backward), (lru.len(), lru.len()));
    }
}
