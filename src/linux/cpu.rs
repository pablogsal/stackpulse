use std::{fs, io};

pub(super) fn online_cpu_ids() -> io::Result<Vec<u32>> {
    if let Some(ids) = fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|list| parse_cpu_list(list.trim()))
    {
        return Ok(ids);
    }

    let stat = fs::read_to_string("/proc/stat")?;
    parse_proc_stat_cpu_ids(&stat).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no online CPU IDs found in sysfs or /proc/stat",
        )
    })
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

fn parse_proc_stat_cpu_ids(stat: &str) -> Option<Vec<u32>> {
    let mut ids: Vec<_> = stat
        .lines()
        .filter_map(|line| line.split_ascii_whitespace().next())
        .filter_map(|label| label.strip_prefix("cpu"))
        .filter(|suffix| !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()))
        .filter_map(|suffix| suffix.parse().ok())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    (!ids.is_empty()).then_some(ids)
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
    fn proc_stat_cpu_ids_preserve_sparse_kernel_labels() {
        let stat = "cpu  10 20 30 40\ncpu2 1 2 3 4\ncpu17 5 6 7 8\ncpu2 9 9 9 9\n\
                    cpufreq 0 0 0 0\nintr 123\n";

        assert_eq!(parse_proc_stat_cpu_ids(stat), Some(vec![2, 17]));
        assert_eq!(parse_proc_stat_cpu_ids("cpu 1 2 3 4\nintr 5\n"), None);
    }
}
