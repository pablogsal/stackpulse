use std::fs;

#[must_use]
pub(super) fn online_cpu_ids() -> Vec<u32> {
    fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|list| parse_cpu_list(list.trim()))
        .filter(|ids| !ids.is_empty())
        .unwrap_or_else(fallback_cpu_ids)
}

pub(super) fn parse_cpu_list(list: &str) -> Option<Vec<u32>> {
    let cpus = list
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .try_fold(Vec::new(), |mut cpus, part| {
            if let Some((start, end)) = part.split_once('-') {
                let start = start.parse::<u32>().ok()?;
                let end = end.parse::<u32>().ok()?;
                if start > end {
                    return None;
                }
                cpus.extend(start..=end);
            } else {
                cpus.push(part.parse::<u32>().ok()?);
            }
            Some(cpus)
        })?;
    (!cpus.is_empty()).then_some(cpus)
}

fn fallback_cpu_ids() -> Vec<u32> {
    let cpu_count = std::thread::available_parallelism().map_or(1, usize::from);
    (0..cpu_count as u32).collect()
}

#[must_use]
pub(super) fn thread_perf_event_capacity(
    cpu_count: usize,
    thread_count: usize,
    per_thread_only: bool,
) -> usize {
    if per_thread_only {
        thread_count
    } else {
        cpu_count.saturating_mul(thread_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpu_list_rejects_empty_and_invalid_lists() {
        assert_eq!(parse_cpu_list(""), None);
        assert_eq!(parse_cpu_list(" , "), None);
        assert_eq!(parse_cpu_list("0,nope"), None);
        assert_eq!(parse_cpu_list("4-3"), None);
    }

    #[test]
    fn fallback_cpu_ids_are_zero_based_and_non_empty() {
        let ids = fallback_cpu_ids();

        assert!(!ids.is_empty());
        assert_eq!(ids[0], 0);
        assert_eq!(ids, (0..ids.len() as u32).collect::<Vec<_>>());
    }

    #[test]
    fn thread_perf_event_capacity_matches_event_layout() {
        assert_eq!(thread_perf_event_capacity(4, 3, false), 12);
        assert_eq!(thread_perf_event_capacity(4, 3, true), 3);
        assert_eq!(thread_perf_event_capacity(usize::MAX, 2, false), usize::MAX);
    }
}
