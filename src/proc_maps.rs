//! Parser for Linux `/proc/<pid>/maps` entries.

use std::ops::Range;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region<'a> {
    pub address: Range<u64>,
    pub is_executable: bool,
    pub file_offset: u64,
    pub inode: u64,
    pub path: &'a str,
}

#[cfg(test)]
pub fn parse(maps: &str) -> Vec<Region<'_>> {
    parse_iter(maps).collect()
}

pub fn parse_iter(maps: &str) -> impl Iterator<Item = Region<'_>> + '_ {
    maps.lines().filter_map(parse_line)
}

pub fn parse_line(line: &str) -> Option<Region<'_>> {
    let mut rest = line.trim();
    if rest.is_empty() {
        return None;
    }

    let range = next_field(&mut rest)?;
    let perms = next_field(&mut rest)?;
    let offset = next_field(&mut rest)?;
    let _dev = next_field(&mut rest)?;
    let inode = next_field(&mut rest)?;
    let path = normalize_path(rest.trim_start());

    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let file_offset = u64::from_str_radix(offset, 16).ok()?;
    let inode = inode.parse().ok()?;

    Some(Region {
        address: start..end,
        is_executable: perms.as_bytes().get(2).copied() == Some(b'x'),
        file_offset,
        inode,
        path,
    })
}

fn next_field<'a>(rest: &mut &'a str) -> Option<&'a str> {
    let trimmed = rest.trim_start();
    if trimmed.is_empty() {
        *rest = "";
        return None;
    }

    match trimmed.find(char::is_whitespace) {
        Some(idx) => {
            let field = &trimmed[..idx];
            *rest = &trimmed[idx..];
            Some(field)
        }
        None => {
            *rest = "";
            Some(trimmed)
        }
    }
}

fn normalize_path(path: &str) -> &str {
    path.strip_suffix(" (deleted)").unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sample_maps() {
        let maps = "\
00400000-0040c000 r-xp 00000000 08:02 1321238                            /usr/bin/cat
0060d000-0062e000 rw-p 00000000 00:00 0                                  [heap]
7ffff672c000-7ffff69db000 r--s 00001ac2 1f:33 1335289                    /usr/lib/locale/locale-archive
7ffff5600000-7ffff5800000 rw-p 00000000 00:00 0
";

        assert_eq!(
            parse(maps),
            vec![
                Region {
                    address: 0x00400000..0x0040c000,
                    is_executable: true,
                    file_offset: 0,
                    inode: 1321238,
                    path: "/usr/bin/cat",
                },
                Region {
                    address: 0x0060d000..0x0062e000,
                    is_executable: false,
                    file_offset: 0,
                    inode: 0,
                    path: "[heap]",
                },
                Region {
                    address: 0x7ffff672c000..0x7ffff69db000,
                    is_executable: false,
                    file_offset: 0x1ac2,
                    inode: 1335289,
                    path: "/usr/lib/locale/locale-archive",
                },
                Region {
                    address: 0x7ffff5600000..0x7ffff5800000,
                    is_executable: false,
                    file_offset: 0,
                    inode: 0,
                    path: "",
                },
            ]
        );
    }

    #[test]
    fn preserves_spaces_and_strips_deleted_suffix() {
        let line =
            "7f1234560000-7f1234570000 r-xp 00001000 08:01 12345 /tmp/a path/lib.so (deleted)";
        let region = parse_line(line).unwrap();
        assert_eq!(region.path, "/tmp/a path/lib.so");
    }

    #[test]
    fn skips_malformed_lines() {
        let maps = "not a valid line\n00400000-0040c000 r-xp 00000000 08:02 1321238 /usr/bin/cat\n";
        let regions = parse(maps);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].path, "/usr/bin/cat");
    }

    #[test]
    fn empty_input_yields_no_regions() {
        assert!(parse("").is_empty());
    }
}
