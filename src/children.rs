use std::path::Path;

/// Return every descendant of `root` currently visible in `/proc`, excluding
/// `root` itself.
///
/// The returned PIDs are a best-effort snapshot: processes that fork after the
/// scan completes are not included, and processes that exit during the scan
/// may be silently skipped. Prefers `/proc/<pid>/task/<tid>/children`
/// (cheap, one read per thread) and falls back to walking every `/proc/<pid>/stat`
/// when the kernel does not expose the `children` files.
pub fn discover_all_descendants(root: i32) -> Vec<i32> {
    descendants_via_proc_children(root).unwrap_or_else(|| descendants_via_stat(root))
}

fn descendants_via_proc_children(root: i32) -> Option<Vec<i32>> {
    let mut visited = std::collections::HashSet::from([root]);
    let mut stack = read_children_fast(root)?;
    let mut out = Vec::new();
    while let Some(pid) = stack.pop() {
        if !visited.insert(pid) {
            continue;
        }
        out.push(pid);
        stack.extend(read_children_fast(pid).unwrap_or_default());
    }
    Some(out)
}

fn read_children_fast(pid: i32) -> Option<Vec<i32>> {
    let entries = std::fs::read_dir(proc_pid_path(pid).join("task")).ok()?;
    discover_children_via_proc_children(entries)
}

fn discover_children_via_proc_children(entries: std::fs::ReadDir) -> Option<Vec<i32>> {
    let mut any_children_file_read = false;
    let mut children = Vec::new();
    for entry in entries.flatten() {
        let Ok(content) = std::fs::read_to_string(entry.path().join("children")) else {
            continue;
        };
        any_children_file_read = true;
        for token in content.split_whitespace() {
            if let Ok(pid) = token.parse::<i32>() {
                children.push(pid);
            }
        }
    }
    children.sort_unstable();
    children.dedup();
    any_children_file_read.then_some(children)
}

fn descendants_via_stat(root: i32) -> Vec<i32> {
    let mut children_of: std::collections::HashMap<i32, Vec<i32>> =
        std::collections::HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(proc_pid_path(pid).join("stat")) else {
            continue;
        };
        if let Some(ppid) = parse_parent_pid_from_stat(&stat) {
            children_of.entry(ppid).or_default().push(pid);
        }
    }

    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(pid) = stack.pop() {
        if let Some(kids) = children_of.get(&pid) {
            for &kid in kids {
                out.push(kid);
                stack.push(kid);
            }
        }
    }
    out
}

#[inline]
fn proc_pid_path(pid: i32) -> std::path::PathBuf {
    Path::new("/proc").join(pid.to_string())
}

fn parse_parent_pid_from_stat(stat: &str) -> Option<i32> {
    let after_comm = stat.rfind(')')?;
    stat.get(after_comm + 2..)?
        .split_whitespace()
        .nth(1)?
        .parse::<i32>()
        .ok()
}
