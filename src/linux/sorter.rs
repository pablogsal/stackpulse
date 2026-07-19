use std::cmp::Ordering;
use std::collections::BinaryHeap;

struct EventHeapItem<K: Ord, V> {
    key: K,
    sequence: u64,
    value: V,
}

// Invert ordering to make `BinaryHeap` a min-heap, preserving insertion order
// for records with identical timestamps.
impl<K: Ord, V> PartialEq for EventHeapItem<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.sequence == other.sequence
    }
}
impl<K: Ord, V> Eq for EventHeapItem<K, V> {}
impl<K: Ord, V> Ord for EventHeapItem<K, V> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key
            .cmp(&other.key)
            .then_with(|| self.sequence.cmp(&other.sequence))
            .reverse()
    }
}
impl<K: Ord, V> PartialOrd for EventHeapItem<K, V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Incremental round-robin sorter merging events from multiple ring buffers.
/// `G` is the ring-buffer identifier, `K` the sort key (typically a
/// timestamp), `V` the consumed event. Events are held until every group has
/// completed another read and their key is covered by the previous round's
/// high watermark.
pub struct EventSorter<G: Ord, K: Ord, V> {
    heap: BinaryHeap<EventHeapItem<K, V>>,
    current_group: Option<G>,
    next_sequence: u64,
    max_key: Option<K>,
    next_flush: Option<K>,
    flush_through: Option<K>,
}

impl<G: Ord, K: Clone + Ord, V> EventSorter<G, K, V> {
    pub fn new() -> Self {
        EventSorter {
            heap: BinaryHeap::new(),
            current_group: None,
            next_sequence: 0,
            max_key: None,
            next_flush: None,
            flush_through: None,
        }
    }

    /// True if events remain buffered. `pop` can return `None` while more
    /// events are still held back waiting for later rounds.
    pub fn has_more(&self) -> bool {
        !self.heap.is_empty()
    }

    /// Start a new round after the largest-identifier group has been read.
    pub fn advance_round(&mut self) {
        self.flush_through = self.next_flush.take();
        self.next_flush.clone_from(&self.max_key);
        self.current_group = None;
    }

    /// Begin a new group within the current round. Panics if `group` is not
    /// monotonically increasing.
    pub fn begin_group(&mut self, group: G) {
        assert!(
            Some(&group) >= self.current_group.as_ref(),
            "Group keys must be monotonically increasing"
        );
        self.current_group = Some(group);
    }

    /// Try to consume an event.
    pub fn pop(&mut self) -> Option<V> {
        if self.current_group.is_some() {
            return None;
        }
        let event = self.heap.peek()?;
        if self
            .flush_through
            .as_ref()
            .is_none_or(|key| &event.key > key)
        {
            return None;
        }
        self.heap.pop().map(|x| x.value)
    }

    /// Unconditionally pop the next event, ignoring round constraints.
    pub fn force_pop(&mut self) -> Option<V> {
        self.heap.pop().map(|x| x.value)
    }

    pub fn push_current_group(&mut self, key: K, value: V) {
        assert!(
            self.current_group.is_some(),
            "begin_group must be called before insertion"
        );
        if self.max_key.as_ref().is_none_or(|max| &key > max) {
            self.max_key = Some(key.clone());
        }
        let sequence = take_sequence(&mut self.next_sequence);
        self.heap.push(EventHeapItem {
            key,
            sequence,
            value,
        });
    }
}

impl<G: Ord, K: Clone + Ord, V> Extend<(K, V)> for EventSorter<G, K, V> {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        for (key, value) in iter {
            self.push_current_group(key, value);
        }
    }
}

fn take_sequence(next_sequence: &mut u64) -> u64 {
    let sequence = *next_sequence;
    *next_sequence = next_sequence
        .checked_add(1)
        .expect("event sorter sequence exhausted");
    sequence
}

#[cfg(test)]
mod tests {
    use super::EventSorter;

    #[test]
    fn equal_keys_keep_insertion_order() {
        let mut sorter = EventSorter::new();
        sorter.begin_group(1);
        sorter.extend([
            (10_u64, "mmap"),
            (10_u64, "fork"),
            (10_u64, "sample"),
            (10_u64, "exit"),
        ]);
        sorter.advance_round();
        assert_eq!(sorter.pop(), None);
        sorter.advance_round();

        let mut out = Vec::new();
        while let Some(event) = sorter.pop() {
            out.push(event);
        }

        assert_eq!(out, ["mmap", "fork", "sample", "exit"]);
    }

    #[test]
    fn completed_empty_round_releases_previous_round() {
        let mut sorter = EventSorter::new();
        sorter.begin_group(1);
        sorter.extend([(20_u64, "group 1")]);
        sorter.begin_group(2);
        sorter.extend([(10_u64, "group 2")]);

        assert_eq!(sorter.pop(), None);

        sorter.advance_round();

        assert_eq!(sorter.pop(), None);
        sorter.advance_round();

        assert_eq!(sorter.pop(), Some("group 2"));
        assert_eq!(sorter.pop(), Some("group 1"));
        assert_eq!(sorter.pop(), None);
        assert!(!sorter.has_more());
    }

    #[test]
    fn force_pop_releases_held_event() {
        let mut sorter = EventSorter::new();
        sorter.begin_group(1);
        sorter.extend([(10_u64, "held")]);

        assert_eq!(sorter.pop(), None);
        assert_eq!(sorter.force_pop(), Some("held"));
        assert!(!sorter.has_more());
    }

    #[test]
    fn groups_are_held_until_the_round_completes() {
        let mut sorter = EventSorter::new();
        sorter.begin_group(1);
        sorter.extend([(20_u64, "old group 1")]);
        sorter.begin_group(2);
        sorter.extend([(10_u64, "old group 2")]);
        sorter.advance_round();

        sorter.begin_group(1);

        assert_eq!(sorter.pop(), None);
        assert!(sorter.has_more());

        sorter.begin_group(2);

        assert_eq!(sorter.pop(), None);
        sorter.advance_round();

        assert_eq!(sorter.pop(), Some("old group 2"));
        assert_eq!(sorter.pop(), Some("old group 1"));
    }

    #[test]
    fn later_previous_round_event_waits_for_earlier_group_to_drain() {
        let mut sorter = EventSorter::new();
        sorter.begin_group(10);
        sorter.begin_group(20);
        sorter.extend([(20_u64, "fd20 sample")]);
        sorter.advance_round();

        assert_eq!(sorter.pop(), None);

        sorter.begin_group(10);
        sorter.extend([(15_u64, "fd10 mmap")]);

        assert_eq!(sorter.pop(), None);

        sorter.begin_group(20);
        assert_eq!(sorter.pop(), None);

        sorter.advance_round();

        assert_eq!(sorter.pop(), Some("fd10 mmap"));
        assert_eq!(sorter.pop(), Some("fd20 sample"));
    }

    #[test]
    fn sorted_events_wait_for_all_groups_in_round() {
        let mut sorter = EventSorter::new();
        sorter.begin_group(3);
        sorter.extend([(30_u64, "g3 t30"), (50_u64, "g3 t50")]);
        sorter.begin_group(7);
        sorter.extend([(10_u64, "g7 t10"), (40_u64, "g7 t40")]);

        assert_eq!(sorter.pop(), None);
        assert!(sorter.has_more());

        sorter.advance_round();

        assert_eq!(sorter.pop(), None);
        sorter.advance_round();

        let mut out = Vec::new();
        while let Some(event) = sorter.pop() {
            out.push(event);
        }

        assert_eq!(out, ["g7 t10", "g3 t30", "g7 t40", "g3 t50"]);
        assert!(!sorter.has_more());
    }

    #[test]
    fn current_round_events_do_not_overtake_previous_round() {
        let mut sorter = EventSorter::new();
        sorter.begin_group(1);
        sorter.extend([(20_u64, "old")]);
        sorter.advance_round();
        assert_eq!(sorter.pop(), None);
        sorter.begin_group(1);
        sorter.extend([(30_u64, "new")]);

        assert_eq!(sorter.pop(), None);
        assert!(sorter.has_more());

        sorter.advance_round();

        assert_eq!(sorter.pop(), Some("old"));
        assert_eq!(sorter.pop(), None);

        sorter.advance_round();

        assert_eq!(sorter.pop(), Some("new"));
        assert_eq!(sorter.pop(), None);
    }
}
