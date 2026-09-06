//! Parser for Linux `/proc/<pid>/maps` entries.

use std::ffi::OsStr;
use std::ops::Range;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Region<'a> {
    pub address: Range<u64>,
    pub is_executable: bool,
    pub file_offset: u64,
    pub inode: u64,
    pub device_major: u32,
    pub device_minor: u32,
    pub path: &'a Path,
}

#[cfg(test)]
fn parse(maps: &str) -> Vec<Region<'_>> {
    parse_iter(maps).collect()
}

pub(crate) fn parse_iter(
    maps: &(impl AsRef<[u8]> + ?Sized),
) -> impl Iterator<Item = Region<'_>> + '_ {
    maps.as_ref()
        .split(|&byte| byte == b'\n')
        .filter_map(parse_line)
}

fn parse_line(line: &(impl AsRef<[u8]> + ?Sized)) -> Option<Region<'_>> {
    let mut rest = line.as_ref();
    let range = next_field(&mut rest)?;
    let perms = next_field(&mut rest)?;
    let offset = next_field(&mut rest)?;
    let device = next_field(&mut rest)?;
    let inode = next_field(&mut rest)?;
    let path = Path::new(OsStr::from_bytes(rest.trim_ascii_start()));
    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    if start >= end {
        return None;
    }
    let file_offset = u64::from_str_radix(offset, 16).ok()?;
    let inode = inode.parse().ok()?;
    let (device_major, device_minor) = device.split_once(':')?;
    let device_major = u32::from_str_radix(device_major, 16).ok()?;
    let device_minor = u32::from_str_radix(device_minor, 16).ok()?;
    Some(Region {
        address: start..end,
        is_executable: perms.as_bytes().get(2).copied() == Some(b'x'),
        file_offset,
        inode,
        device_major,
        device_minor,
        path,
    })
}

fn next_field<'a>(rest: &mut &'a [u8]) -> Option<&'a str> {
    let trimmed = rest.trim_ascii_start();
    if trimmed.is_empty() {
        return None;
    }
    let end = trimmed
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(trimmed.len());
    let (field, remaining) = trimmed.split_at(end);
    *rest = remaining;
    std::str::from_utf8(field).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_non_utf8_mapping_paths() {
        let line = b"00400000-0040c000 r-xp 00000000 08:02 42 /tmp/\xff library.so";
        let region = parse_line(line).unwrap();
        assert_eq!(region.path.as_os_str().as_bytes(), b"/tmp/\xff library.so");
    }

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
                    device_major: 0x08,
                    device_minor: 0x02,
                    path: Path::new("/usr/bin/cat"),
                },
                Region {
                    address: 0x0060d000..0x0062e000,
                    is_executable: false,
                    file_offset: 0,
                    inode: 0,
                    device_major: 0,
                    device_minor: 0,
                    path: Path::new("[heap]"),
                },
                Region {
                    address: 0x7ffff672c000..0x7ffff69db000,
                    is_executable: false,
                    file_offset: 0x1ac2,
                    inode: 1335289,
                    device_major: 0x1f,
                    device_minor: 0x33,
                    path: Path::new("/usr/lib/locale/locale-archive"),
                },
                Region {
                    address: 0x7ffff5600000..0x7ffff5800000,
                    is_executable: false,
                    file_offset: 0,
                    inode: 0,
                    device_major: 0,
                    device_minor: 0,
                    path: Path::new(""),
                },
            ]
        );
    }

    #[test]
    fn preserves_path_suffixes_verbatim() {
        let line =
            "7f1234560000-7f1234570000 r-xp 00001000 08:01 12345 /tmp/a path/lib.so (deleted)";
        let region = parse_line(line).unwrap();
        assert_eq!(region.path, Path::new("/tmp/a path/lib.so (deleted)"));

        let line = "7f1234560000-7f1234570000 r-xp 00001000 08:01 12345 /tmp/trailing-space \t";
        let region = parse_line(line).unwrap();
        assert_eq!(region.path, Path::new("/tmp/trailing-space \t"));
    }

    #[test]
    fn skips_malformed_lines() {
        let maps = "not a valid line\n00400000-0040c000 r-xp 00000000 08:02 1321238 /usr/bin/cat\n";
        let regions = parse(maps);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].path, Path::new("/usr/bin/cat"));
    }

    #[test]
    fn empty_input_yields_no_regions() {
        assert!(parse("").is_empty());
    }
}
