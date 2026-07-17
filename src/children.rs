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
    discover_descendant_edges(root)
        .into_iter()
        .map(|(child, _)| child)
        .collect()
}

/// Return visible descendants together with each child's immediate parent.
/// Parent edges precede any edges discovered below that child.
pub fn discover_descendant_edges(root: i32) -> Vec<(i32, i32)> {
    descendant_edges_via_proc_children(root).unwrap_or_else(|| descendant_edges_via_stat(root))
}

fn descendant_edges_via_proc_children(root: i32) -> Option<Vec<(i32, i32)>> {
    let mut visited = std::collections::HashSet::from([root]);
    let mut stack = vec![root];
    let mut out = Vec::new();
    while let Some(parent) = stack.pop() {
        let children = read_children_fast(parent)?;
        for child in children {
            if !visited.insert(child) {
                continue;
            }
            out.push((child, parent));
            stack.push(child);
        }
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

fn descendant_edges_via_stat(root: i32) -> Vec<(i32, i32)> {
    descendant_edges_via_stat_from_proc(root, Path::new("/proc"))
}

fn descendant_edges_via_stat_from_proc(root: i32, proc_root: &Path) -> Vec<(i32, i32)> {
    let mut children_of: std::collections::HashMap<i32, Vec<i32>> =
        std::collections::HashMap::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")) else {
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
                out.push((kid, pid));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{SleepChild, TempDir};
    use std::fs;

    #[test]
    fn parse_parent_pid_from_stat_handles_command_names_with_parens() {
        assert_eq!(
            parse_parent_pid_from_stat("123 (cmd ) with parens) S 456 1 2 3"),
            Some(456)
        );
    }

    #[test]
    fn parse_parent_pid_from_stat_rejects_malformed_stat_lines() {
        assert_eq!(parse_parent_pid_from_stat("123 (cmd S 456"), None);
        assert_eq!(parse_parent_pid_from_stat("123 (cmd) S"), None);
        assert_eq!(parse_parent_pid_from_stat("123 (cmd) S nope"), None);
    }

    #[test]
    fn discover_children_via_proc_children_sorts_dedupes_and_skips_bad_tokens() {
        let temp = TempDir::new("proc-children");
        let task = temp.path().join("task");
        fs::create_dir_all(task.join("10")).expect("create thread dir");
        fs::create_dir_all(task.join("11")).expect("create thread dir");
        fs::create_dir_all(task.join("12")).expect("create thread dir");
        fs::write(task.join("10").join("children"), "42 7 nope 42\n").expect("write children file");
        fs::write(task.join("11").join("children"), "100 7").expect("write children file");

        let children =
            discover_children_via_proc_children(fs::read_dir(&task).expect("read task dir"))
                .expect("children files read");

        assert_eq!(children, vec![7, 42, 100]);
    }

    #[test]
    fn discover_children_via_proc_children_returns_none_without_readable_files() {
        let temp = TempDir::new("proc-children-empty");
        let task = temp.path().join("task");
        fs::create_dir_all(task.join("10")).expect("create thread dir");

        assert_eq!(
            discover_children_via_proc_children(fs::read_dir(&task).expect("read task dir")),
            None
        );
    }

    #[test]
    fn descendant_edges_via_stat_preserve_immediate_parents() {
        let temp = TempDir::new("proc-stat");
        for (pid, stat) in [
            (10, "10 (root) S 1 1 1 1"),
            (11, "11 (child) S 10 1 1 1"),
            (12, "12 (child with ) paren) S 10 1 1 1"),
            (13, "13 (grandchild) S 11 1 1 1"),
            (14, "14 (unrelated) S 1 1 1 1"),
        ] {
            let dir = temp.path().join(pid.to_string());
            fs::create_dir_all(&dir).expect("create proc pid dir");
            fs::write(dir.join("stat"), stat).expect("write proc stat");
        }
        fs::create_dir_all(temp.path().join("self")).expect("create non-pid proc entry");

        let mut descendants = descendant_edges_via_stat_from_proc(10, temp.path());
        descendants.sort_unstable();

        assert_eq!(descendants, vec![(11, 10), (12, 10), (13, 11)]);
    }

    #[test]
    fn discover_descendants_includes_live_child_process() {
        let root = std::process::id() as i32;
        if fs::read_dir(proc_pid_path(root).join("task")).is_err() {
            return;
        }
        let child = SleepChild::spawn();

        let descendants = discover_all_descendants(root);

        assert!(descendants.contains(&child.pid_i32()));
        assert!(!descendants.contains(&root));
    }
}
