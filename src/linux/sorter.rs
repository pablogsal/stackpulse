use std::cmp::Ordering;
use std::collections::BinaryHeap;

struct EventHeapItem<G: Clone + Ord, K: Ord, V> {
    group: G,
    round: usize,
    key: K,
    sequence: u64,
    value: V,
}

// Invert ordering to make `BinaryHeap` a min-heap, preserving insertion order
// for records with identical timestamps.
impl<G: Clone + Ord, K: Ord, V> PartialEq for EventHeapItem<G, K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.sequence == other.sequence
    }
}
impl<G: Clone + Ord, K: Ord, V> Eq for EventHeapItem<G, K, V> {}
impl<G: Clone + Ord, K: Ord, V> Ord for EventHeapItem<G, K, V> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key
            .cmp(&other.key)
            .then_with(|| self.sequence.cmp(&other.sequence))
            .reverse()
    }
}
impl<G: Clone + Ord, K: Ord, V> PartialOrd for EventHeapItem<G, K, V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Incremental round-robin sorter merging events from multiple ring buffers.
/// `G` is the ring-buffer identifier, `K` the sort key (typically a
/// timestamp), `V` the consumed event. Per-group events are held back until
/// every other group has been read past them in the current round.
pub struct EventSorter<G: Clone + Ord, K: Ord, V> {
    heap: BinaryHeap<EventHeapItem<G, K, V>>,
    round: usize,
    current_group: Option<G>,
    next_sequence: u64,
}

impl<G: Clone + Ord, K: Ord, V> EventSorter<G, K, V> {
    pub fn new() -> Self {
        EventSorter {
            heap: BinaryHeap::new(),
            round: 0,
            current_group: None,
            next_sequence: 0,
        }
    }

    /// True if events remain buffered. `pop` can return `None` while more
    /// events are still held back waiting for later rounds.
    pub fn has_more(&self) -> bool {
        !self.heap.is_empty()
    }

    /// Start a new round after the largest-identifier group has been read.
    pub fn advance_round(&mut self) {
        self.round += 1;
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
        let event = self.heap.peek()?;
        let safe_round = event.round + 1;
        if safe_round > self.round {
            return None;
        }
        if safe_round == self.round {
            if let Some(current_group) = self.current_group.as_ref() {
                if &event.group > current_group {
                    return None;
                }
            }
        }
        self.heap.pop().map(|x| x.value)
    }

    /// Unconditionally pop the next event, ignoring round constraints.
    pub fn force_pop(&mut self) -> Option<V> {
        self.heap.pop().map(|x| x.value)
    }
}

impl<G: Clone + Ord, K: Ord, V> Extend<(K, V)> for EventSorter<G, K, V> {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        let group = self
            .current_group
            .clone()
            .expect("begin_group must be called before insertion");
        let round = self.round;
        let mut next_sequence = self.next_sequence;
        self.heap.extend(iter.into_iter().map(|(key, value)| {
            let sequence = next_sequence;
            next_sequence = next_sequence.saturating_add(1);
            EventHeapItem {
                group: group.clone(),
                round,
                key,
                sequence,
                value,
            }
        }));
        self.next_sequence = next_sequence;
    }
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
        sorter.begin_group(1);

        let mut out = Vec::new();
        while let Some(event) = sorter.pop() {
            out.push(event);
        }

        assert_eq!(out, ["mmap", "fork", "sample", "exit"]);
    }

    #[test]
    fn advance_round_releases_previous_round_without_next_group() {
        let mut sorter = EventSorter::new();
        sorter.begin_group(1);
        sorter.extend([(20_u64, "group 1")]);
        sorter.begin_group(2);
        sorter.extend([(10_u64, "group 2")]);

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
    fn later_group_is_held_until_group_is_reached() {
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

        sorter.begin_group(10);
        sorter.extend([(15_u64, "fd10 mmap")]);

        assert_eq!(sorter.pop(), None);

        sorter.begin_group(20);
        assert_eq!(sorter.pop(), None);

        sorter.advance_round();
        sorter.begin_group(10);

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
        sorter.begin_group(1);
        sorter.extend([(30_u64, "new")]);

        assert_eq!(sorter.pop(), Some("old"));
        assert_eq!(sorter.pop(), None);
        assert!(sorter.has_more());

        sorter.advance_round();

        assert_eq!(sorter.pop(), Some("new"));
        assert_eq!(sorter.pop(), None);
    }
}
