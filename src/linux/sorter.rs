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
        if (event.round + 1, Some(&event.group)) > (self.round, self.current_group.as_ref()) {
            return None;
        }
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
}
