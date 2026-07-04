use std::cmp::Reverse;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BinaryHeap, VecDeque};

struct QueuedEvent<K, V> {
    round: usize,
    key: K,
    sequence: u64,
    value: V,
}

struct GroupQueue<G, K, V> {
    group: G,
    events: VecDeque<QueuedEvent<K, V>>,
}

type HeadEntry<K> = Reverse<(K, u64, usize)>;

/// Incremental round-robin sorter merging events from multiple ring buffers.
/// `G` is the ring-buffer identifier, `K` the sort key (typically a
/// timestamp), `V` the consumed event. Per-group events are held back until
/// every other group has been read past them in the current round.
#[doc(hidden)]
pub struct EventSorter<G: Clone + Ord, K: Clone + Ord, V> {
    queues: Vec<GroupQueue<G, K, V>>,
    slots: BTreeMap<G, usize>,
    heads: BinaryHeap<HeadEntry<K>>,
    buffered: usize,
    round: usize,
    current_group: Option<(G, usize)>,
    next_sequence: u64,
}

impl<G: Clone + Ord, K: Clone + Ord, V> EventSorter<G, K, V> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        EventSorter {
            queues: Vec::new(),
            slots: BTreeMap::new(),
            heads: BinaryHeap::new(),
            buffered: 0,
            round: 0,
            current_group: None,
            next_sequence: 0,
        }
    }

    /// True if events remain buffered. `pop` can return `None` while more
    /// events are still held back waiting for later rounds.
    pub fn has_more(&self) -> bool {
        self.buffered > 0
    }

    /// Start a new round after the largest-identifier group has been read.
    pub fn advance_round(&mut self) {
        self.round += 1;
        self.current_group = None;
    }

    /// Begin a new group within the current round. Panics if `group` is not
    /// monotonically increasing.
    pub fn begin_group(&mut self, group: G) {
        let previous_group = self.current_group.as_ref().map(|(group, _)| group);
        assert!(
            Some(&group) >= previous_group,
            "Group keys must be monotonically increasing"
        );
        let slot = match self.slots.entry(group.clone()) {
            Entry::Occupied(occupied) => *occupied.get(),
            Entry::Vacant(vacant) => {
                let slot = self.queues.len();
                self.queues.push(GroupQueue {
                    group: group.clone(),
                    events: VecDeque::new(),
                });
                *vacant.insert(slot)
            }
        };
        self.current_group = Some((group, slot));
    }

    /// Insert a single event for the current group. Panics if `begin_group`
    /// has not been called.
    pub fn push(&mut self, key: K, value: V) {
        let slot = self
            .current_group
            .as_ref()
            .map(|(_, slot)| *slot)
            .expect("begin_group must be called before insertion");
        self.push_into_slot(slot, key, value);
    }

    fn push_into_slot(&mut self, slot: usize, key: K, value: V) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.insert(
            slot,
            QueuedEvent {
                round: self.round,
                key,
                sequence,
                value,
            },
        );
    }

    fn insert(&mut self, slot: usize, event: QueuedEvent<K, V>) {
        let queue = &mut self.queues[slot].events;
        let front_changed = match queue.back() {
            None => {
                queue.push_back(event);
                true
            }
            Some(back) if back.key <= event.key => {
                queue.push_back(event);
                false
            }
            Some(_) => {
                let position = queue.partition_point(|queued| queued.key <= event.key);
                queue.insert(position, event);
                position == 0
            }
        };
        if front_changed {
            let front = queue.front().expect("queue front exists after insert");
            self.heads
                .push(Reverse((front.key.clone(), front.sequence, slot)));
        }
        self.buffered += 1;
    }

    fn valid_top_slot(&mut self) -> Option<usize> {
        while let Some(&Reverse((_, sequence, slot))) = self.heads.peek() {
            match self.queues[slot].events.front() {
                Some(front) if front.sequence == sequence => return Some(slot),
                _ => {
                    self.heads.pop();
                }
            }
        }
        None
    }

    fn pop_front(&mut self, slot: usize) -> V {
        self.heads.pop();
        let queue = &mut self.queues[slot].events;
        let event = queue.pop_front().expect("validated front exists");
        if let Some(next) = queue.front() {
            self.heads
                .push(Reverse((next.key.clone(), next.sequence, slot)));
        }
        self.buffered -= 1;
        event.value
    }

    /// Try to consume an event.
    pub fn pop(&mut self) -> Option<V> {
        let slot = self.valid_top_slot()?;
        let queue = &self.queues[slot];
        let event = queue.events.front().expect("validated front exists");
        let safe_round = event.round + 1;
        if safe_round > self.round {
            return None;
        }
        if safe_round == self.round
            && self
                .current_group
                .as_ref()
                .is_some_and(|(current_group, _)| &queue.group > current_group)
        {
            return None;
        }
        Some(self.pop_front(slot))
    }

    /// Unconditionally pop the next event, ignoring round constraints.
    pub fn force_pop(&mut self) -> Option<V> {
        let slot = self.valid_top_slot()?;
        Some(self.pop_front(slot))
    }
}

impl<G: Clone + Ord, K: Clone + Ord, V> Extend<(K, V)> for EventSorter<G, K, V> {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        let slot = self
            .current_group
            .as_ref()
            .map(|(_, slot)| *slot)
            .expect("begin_group must be called before insertion");
        for (key, value) in iter {
            self.push_into_slot(slot, key, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EventSorter;

    fn drain(sorter: &mut EventSorter<i32, u64, &'static str>) -> Vec<&'static str> {
        std::iter::from_fn(|| sorter.pop()).collect()
    }

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

        assert_eq!(drain(&mut sorter), ["mmap", "fork", "sample", "exit"]);
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

        assert_eq!(drain(&mut sorter), ["g7 t10", "g3 t30", "g7 t40", "g3 t50"]);
        assert!(!sorter.has_more());
    }

    #[test]
    fn push_matches_extend_ordering_including_ties() {
        let group_3 = [
            (30_u64, "g3 t30 a"),
            (30_u64, "g3 t30 b"),
            (50_u64, "g3 t50"),
        ];
        let group_7 = [(10_u64, "g7 t10"), (30_u64, "g7 t30"), (40_u64, "g7 t40")];

        let mut extended = EventSorter::new();
        extended.begin_group(3);
        extended.extend(group_3);
        extended.begin_group(7);
        extended.extend(group_7);

        let mut pushed = EventSorter::new();
        pushed.begin_group(3);
        for (key, value) in group_3 {
            pushed.push(key, value);
        }
        pushed.begin_group(7);
        for (key, value) in group_7 {
            pushed.push(key, value);
        }

        assert_eq!(pushed.pop(), None);
        assert!(pushed.has_more());

        extended.advance_round();
        pushed.advance_round();

        let expected = drain(&mut extended);
        let got = drain(&mut pushed);

        assert_eq!(got, expected);
        assert_eq!(
            got,
            ["g7 t10", "g3 t30 a", "g3 t30 b", "g7 t30", "g7 t40", "g3 t50"]
        );
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

    #[test]
    fn out_of_order_keys_within_a_group_still_sort() {
        let mut sorter = EventSorter::new();
        sorter.begin_group(1);
        sorter.extend([(30_u64, "g1 t30"), (10_u64, "g1 t10"), (20_u64, "g1 t20")]);
        sorter.begin_group(2);
        sorter.extend([(25_u64, "g2 t25"), (5_u64, "g2 t5")]);
        sorter.advance_round();

        assert_eq!(
            drain(&mut sorter),
            ["g2 t5", "g1 t10", "g1 t20", "g2 t25", "g1 t30"]
        );
        assert!(!sorter.has_more());
    }
}
