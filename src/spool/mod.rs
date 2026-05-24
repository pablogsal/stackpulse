use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{self, BufWriter, Read, Write};
use std::ops::{Deref, Range};
use std::path::Path;
use std::sync::Arc;

use integer_encoding::{VarIntReader, VarIntWriter};
use memmap2::Mmap;
use rustc_hash::FxHashMap;

const MAGIC: &[u8; 8] = b"CHPERF2\0";
const REC_MODULE: u8 = 1;
const REC_FRAME: u8 = 2;
const REC_STACK: u8 = 3;
const REC_THREAD: u8 = 4;
const REC_SAMPLE: u8 = 5;
const REC_PROCESS_EXEC: u8 = 6;
const NONE_U32: u32 = u32::MAX;

/// File path or display name for a recorded module.
#[derive(Clone)]
pub struct ModulePath(ModulePathStorage);

#[derive(Clone)]
enum ModulePathStorage {
    Owned(Arc<str>),
    Mmap {
        mmap: Arc<Mmap>,
        range: Range<usize>,
    },
}

impl ModulePath {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            ModulePathStorage::Owned(path) => path,
            ModulePathStorage::Mmap { mmap, range } => std::str::from_utf8(&mmap[range.clone()])
                .expect("mmap-backed module path was validated while reading the spool"),
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }

    fn from_mmap(mmap: Arc<Mmap>, range: Range<usize>) -> io::Result<Self> {
        std::str::from_utf8(&mmap[range.clone()]).map_err(|err| invalid_data(err.to_string()))?;
        Ok(Self(ModulePathStorage::Mmap { mmap, range }))
    }
}

impl Deref for ModulePath {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for ModulePath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<std::ffi::OsStr> for ModulePath {
    fn as_ref(&self) -> &std::ffi::OsStr {
        std::ffi::OsStr::new(self.as_str())
    }
}

impl std::borrow::Borrow<str> for ModulePath {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<String> for ModulePath {
    fn from(path: String) -> Self {
        Self(ModulePathStorage::Owned(Arc::from(path.into_boxed_str())))
    }
}

impl From<&str> for ModulePath {
    fn from(path: &str) -> Self {
        Self(ModulePathStorage::Owned(Arc::from(path)))
    }
}

impl From<ModulePath> for std::rc::Rc<str> {
    fn from(path: ModulePath) -> Self {
        path.as_str().into()
    }
}

impl std::fmt::Debug for ModulePath {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(fmt)
    }
}

impl std::fmt::Display for ModulePath {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_str(self.as_str())
    }
}

impl PartialEq for ModulePath {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for ModulePath {}

impl Hash for ModulePath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

/// A code area recorded in a profile file.
#[derive(Clone, Debug)]
pub struct ModuleRecord {
    /// Stable module id within the profile.
    pub id: u32,
    /// Process that owned this code area, or a kernel marker for kernel code.
    pub process_id: i32,
    /// Start address in memory.
    pub start: u64,
    /// End address in memory.
    pub end: u64,
    /// File offset backing the start address.
    pub file_offset: u64,
    /// File inode, when available.
    pub inode: u64,
    /// File path or display name.
    pub path: ModulePath,
    /// Whether this record represents kernel code.
    pub is_kernel: bool,
}

/// Whether a frame came from user code or kernel code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameMode {
    /// User-space frame.
    User,
    /// Kernel-space frame.
    Kernel,
}

/// A raw frame stored in a profile file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameRecord {
    /// Module id when the frame was matched to a module.
    pub module_id: Option<u32>,
    /// Address relative to the matched module.
    pub rel_ip: u64,
    /// Absolute instruction pointer.
    pub abs_ip: u64,
    /// User/kernel mode for the frame.
    pub mode: FrameMode,
}

/// A sample record loaded from a profile file.
#[derive(Clone, Debug)]
pub struct OwnedSampleRecord {
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Process id for the sample.
    pub process_id: i32,
    /// Thread id for the sample.
    pub thread_id: u64,
    /// Stack id used with [`PerfSpoolReader::stack_frames`].
    pub stack_id: u32,
}

/// Marker for a process that executed during recording.
#[derive(Clone, Debug)]
pub struct ProcessExecRecord {
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Process id.
    pub process_id: i32,
    /// Whether the process looked like a Python runtime.
    pub is_python_runtime: bool,
}

pub struct SampleRecord<'a> {
    pub timestamp_ns: u64,
    pub process_id: i32,
    pub thread_id: u64,
    pub frames: &'a [FrameRecord],
}

#[derive(Clone, Copy, Debug)]
struct StackNodeRecord {
    prefix: Option<u32>,
    frame_id: u32,
    depth: usize,
}

pub struct PerfSpoolWriter<W: Write> {
    writer: W,
    last_timestamp_ns: u64,
    frame_cache: FxHashMap<FrameRecord, u32>,
    stack_cache: FxHashMap<(u32, u32), u32>,
    thread_cache: FxHashMap<(i32, u64), u32>,
}

impl PerfSpoolWriter<BufWriter<File>> {
    pub fn create<P: AsRef<Path>>(
        path: P,
        start_timestamp_us: u64,
        sample_interval_us: u64,
    ) -> io::Result<Self> {
        let mut writer = Self {
            writer: BufWriter::new(File::create(path)?),
            frame_cache: FxHashMap::default(),
            stack_cache: FxHashMap::default(),
            thread_cache: FxHashMap::default(),
            last_timestamp_ns: 0,
        };
        writer.writer.write_all(MAGIC)?;
        writer.writer.write_varint(start_timestamp_us)?;
        writer.writer.write_varint(sample_interval_us)?;
        Ok(writer)
    }
}

impl<W: Write> PerfSpoolWriter<W> {
    pub fn write_module(&mut self, module: &ModuleRecord) -> io::Result<()> {
        self.writer.write_all(&[REC_MODULE])?;
        self.writer.write_varint(module.id as u64)?;
        self.writer.write_varint(module.process_id as i64)?;
        self.writer.write_varint(module.start)?;
        self.writer.write_varint(module.end)?;
        self.writer.write_varint(module.file_offset)?;
        self.writer.write_varint(module.inode)?;
        self.writer.write_all(&[u8::from(module.is_kernel)])?;
        write_bytes(&mut self.writer, module.path.as_bytes())
    }

    pub fn write_sample(&mut self, sample: &SampleRecord<'_>) -> io::Result<()> {
        self.write_sample_frames(
            sample.timestamp_ns,
            sample.process_id,
            sample.thread_id,
            sample.frames.iter().copied(),
        )
        .map(drop)
    }

    pub fn write_sample_frames<I>(
        &mut self,
        timestamp_ns: u64,
        process_id: i32,
        thread_id: u64,
        frames: I,
    ) -> io::Result<Option<u32>>
    where
        I: IntoIterator<Item = FrameRecord>,
        I::IntoIter: DoubleEndedIterator,
    {
        let Some(stack_id) = self.intern_stack(frames)? else {
            return Ok(None);
        };
        let thread_id = self.intern_thread(process_id, thread_id)?;
        let delta = timestamp_ns as i64 - self.last_timestamp_ns as i64;
        self.last_timestamp_ns = timestamp_ns;

        self.writer.write_all(&[REC_SAMPLE])?;
        self.writer.write_varint(delta)?;
        self.writer.write_varint(u64::from(thread_id))?;
        self.writer.write_varint(u64::from(stack_id))?;
        Ok(Some(stack_id))
    }

    pub fn write_process_exec(
        &mut self,
        timestamp_ns: u64,
        process_id: i32,
        is_python_runtime: bool,
    ) -> io::Result<()> {
        self.writer.write_all(&[REC_PROCESS_EXEC])?;
        self.writer.write_varint(timestamp_ns)?;
        self.writer.write_varint(i64::from(process_id))?;
        self.writer.write_all(&[u8::from(is_python_runtime)])
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    fn intern_thread(&mut self, process_id: i32, thread_id: u64) -> io::Result<u32> {
        let key = (process_id, thread_id);
        if let Some(&id) = self.thread_cache.get(&key) {
            return Ok(id);
        }
        let id = self.thread_cache.len() as u32;
        self.writer.write_all(&[REC_THREAD])?;
        self.writer.write_varint(u64::from(id))?;
        self.writer.write_varint(i64::from(process_id))?;
        self.writer.write_varint(thread_id)?;
        self.thread_cache.insert(key, id);
        Ok(id)
    }

    fn intern_frame(&mut self, frame: &FrameRecord) -> io::Result<u32> {
        if let Some(&id) = self.frame_cache.get(frame) {
            return Ok(id);
        }
        let id = self.frame_cache.len() as u32;
        self.writer.write_all(&[REC_FRAME])?;
        self.writer.write_varint(u64::from(id))?;
        write_compact_frame(&mut self.writer, frame)?;
        self.frame_cache.insert(*frame, id);
        Ok(id)
    }

    fn intern_stack<I>(&mut self, frames: I) -> io::Result<Option<u32>>
    where
        I: IntoIterator<Item = FrameRecord>,
        I::IntoIter: DoubleEndedIterator,
    {
        let mut prefix = NONE_U32;
        let mut saw_frame = false;
        for frame in frames.into_iter().rev() {
            saw_frame = true;
            let frame_id = self.intern_frame(&frame)?;
            let key = (prefix, frame_id);
            if let Some(&stack_id) = self.stack_cache.get(&key) {
                prefix = stack_id;
                continue;
            }
            let stack_id = self.stack_cache.len() as u32;
            self.writer.write_all(&[REC_STACK])?;
            self.writer.write_varint(u64::from(stack_id))?;
            self.writer.write_varint(u64::from(prefix))?;
            self.writer.write_varint(u64::from(frame_id))?;
            self.stack_cache.insert(key, stack_id);
            prefix = stack_id;
        }
        Ok(saw_frame.then_some(prefix))
    }
}

/// Reader for profile files written by [`crate::PerfRecorder`].
pub struct PerfSpoolReader {
    start_timestamp_us: u64,
    modules: Vec<ModuleRecord>,
    frames: Vec<FrameRecord>,
    stack_nodes: Vec<StackNodeRecord>,
    samples: Vec<OwnedSampleRecord>,
    process_execs: Vec<ProcessExecRecord>,
}

/// Borrowed raw frames for one interned stack.
pub struct StackFrameRefs<'a> {
    frames: &'a [FrameRecord],
    stack_nodes: &'a [StackNodeRecord],
    current: Option<u32>,
    remaining: usize,
}

impl<'a> Iterator for StackFrameRefs<'a> {
    type Item = &'a FrameRecord;

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.current?;
        let node = self.stack_nodes.get(id as usize)?;
        self.current = node.prefix;
        self.remaining = self.remaining.saturating_sub(1);
        self.frames.get(node.frame_id as usize)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for StackFrameRefs<'_> {
    fn len(&self) -> usize {
        self.remaining
    }
}

impl PerfSpoolReader {
    /// Open and read a profile file.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let mmap = Arc::new(unsafe { Mmap::map(&file)? });
        let mut reader = MmapSpoolCursor::new(Arc::clone(&mmap));
        reader.check_magic()?;
        let start_timestamp_us = reader.read_varint::<u64>()?;
        let _sample_interval_us = reader.read_varint::<u64>()?;
        let (mut modules, mut frames, mut stack_nodes, mut threads, mut samples, mut process_execs) = (
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut last_timestamp_ns = 0_u64;
        while let Some(tag) = reader.read_tag()? {
            match tag {
                REC_MODULE => modules.push(read_module_mmap(&mut reader)?),
                REC_FRAME => frames.push(read_frame(&mut reader, &modules, frames.len())?),
                REC_STACK => {
                    stack_nodes.push(read_stack_node(&mut reader, &stack_nodes, frames.len())?)
                }
                REC_THREAD => threads.push(read_thread(&mut reader, threads.len())?),
                REC_SAMPLE => samples.push(read_sample(
                    &mut reader,
                    &threads,
                    stack_nodes.len(),
                    &mut last_timestamp_ns,
                )?),
                REC_PROCESS_EXEC => process_execs.push(read_process_exec(&mut reader)?),
                other => return Err(invalid_data(format!("unknown spool record tag {other}"))),
            }
        }
        Ok(Self {
            start_timestamp_us,
            modules,
            frames,
            stack_nodes,
            samples,
            process_execs,
        })
    }

    /// Return code areas recorded in the profile.
    pub fn modules(&self) -> &[ModuleRecord] {
        &self.modules
    }

    /// Return samples recorded in the profile.
    pub fn samples(&self) -> &[OwnedSampleRecord] {
        &self.samples
    }

    /// Return process execution markers recorded in the profile.
    pub fn process_execs(&self) -> &[ProcessExecRecord] {
        &self.process_execs
    }

    /// Return absolute kernel instruction pointers present in interned frame records.
    pub fn kernel_frame_addresses(&self) -> impl Iterator<Item = u64> + '_ {
        self.frames
            .iter()
            .filter_map(|frame| (frame.mode == FrameMode::Kernel).then_some(frame.abs_ip))
    }

    /// Borrow raw frames for `stack_id` without copying them.
    pub fn stack_frame_refs(&self, stack_id: u32) -> io::Result<StackFrameRefs<'_>> {
        let node = self.stack_nodes.get(stack_id as usize).ok_or_else(|| {
            invalid_data(format!("sample references missing stack node {stack_id}"))
        })?;
        Ok(StackFrameRefs {
            frames: &self.frames,
            stack_nodes: &self.stack_nodes,
            current: Some(stack_id),
            remaining: node.depth,
        })
    }

    /// Expand `stack_id` into raw frames.
    ///
    /// `out` is cleared before the frames are written.
    pub fn stack_frames(&self, stack_id: u32, out: &mut Vec<FrameRecord>) -> io::Result<()> {
        out.clear();
        out.extend(self.stack_frame_refs(stack_id)?.copied());
        Ok(())
    }

    /// Convert a sample timestamp to the profile timeline in microseconds.
    pub fn timestamp_us(&self, sample: &OwnedSampleRecord) -> u64 {
        let first = self
            .samples
            .first()
            .map_or(sample.timestamp_ns, |s| s.timestamp_ns);
        self.start_timestamp_us
            .saturating_add(sample.timestamp_ns.saturating_sub(first) / 1_000)
    }
}

struct MmapSpoolCursor {
    mmap: Arc<Mmap>,
    position: usize,
}

impl MmapSpoolCursor {
    fn new(mmap: Arc<Mmap>) -> Self {
        Self { mmap, position: 0 }
    }

    fn check_magic(&mut self) -> io::Result<()> {
        let mut magic = [0_u8; 8];
        self.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(invalid_data("invalid stackpulse spool magic"));
        }
        Ok(())
    }

    fn read_tag(&mut self) -> io::Result<Option<u8>> {
        if self.position == self.mmap.len() {
            return Ok(None);
        }
        let tag = *self
            .mmap
            .get(self.position)
            .ok_or_else(|| invalid_data("truncated spool record tag"))?;
        self.position += 1;
        Ok(Some(tag))
    }

    fn read_bytes_range(&mut self, len: usize) -> io::Result<Range<usize>> {
        let start = self.position;
        let end = start
            .checked_add(len)
            .ok_or_else(|| invalid_data("spool byte range overflow"))?;
        if end > self.mmap.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated spool byte range",
            ));
        }
        self.position = end;
        Ok(start..end)
    }
}

impl Read for MmapSpoolCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.mmap.len().saturating_sub(self.position);
        let len = available.min(buf.len());
        buf[..len].copy_from_slice(&self.mmap[self.position..self.position + len]);
        self.position += len;
        Ok(len)
    }
}

#[derive(Default)]
pub struct ModuleTable {
    modules: Vec<ModuleRecord>,
    active: Vec<bool>,
    index: ModuleIndex,
    index_dirty: bool,
}

impl ModuleTable {
    pub fn intern_module<W: Write>(
        &mut self,
        mut module: ModuleRecord,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<u32> {
        if module.end <= module.start {
            return Ok(u32::MAX);
        }
        if let Some((existing, _)) = self.modules.iter().zip(&self.active).find(|(m, &active)| {
            active
                && m.process_id == module.process_id
                && m.start == module.start
                && m.end == module.end
                && m.file_offset == module.file_offset
                && m.path == module.path
        }) {
            return Ok(existing.id);
        }
        let id = u32::try_from(self.modules.len()).unwrap_or(u32::MAX);
        module.id = id;
        writer.write_module(&module)?;
        self.modules.push(module);
        self.active.push(true);
        self.index_dirty = true;
        Ok(id)
    }

    pub fn deactivate_process_modules(&mut self, process_id: i32) {
        for (module, active) in self.modules.iter().zip(self.active.iter_mut()) {
            if module.process_id == process_id && !module.is_kernel {
                self.index_dirty |= *active;
                *active = false;
            }
        }
    }

    pub fn clone_process_modules<W: Write>(
        &mut self,
        parent_process_id: i32,
        child_process_id: i32,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<()> {
        let inherited: Vec<_> = self
            .modules
            .iter()
            .zip(&self.active)
            .filter(|(m, &active)| active && m.process_id == parent_process_id && !m.is_kernel)
            .map(|(m, _)| ModuleRecord {
                id: 0,
                process_id: child_process_id,
                ..m.clone()
            })
            .collect();
        for module in inherited {
            self.intern_module(module, writer)?;
        }
        Ok(())
    }

    pub fn resolve_frame(&mut self, process_id: i32, abs_ip: u64, mode: FrameMode) -> FrameRecord {
        self.rebuild_index_if_needed();
        let module = self
            .index
            .find(process_id, abs_ip)
            .and_then(|id| self.modules.get(id as usize).map(|module| (id, module)));
        let (module_id, rel_ip) = match module {
            Some((id, m)) => (Some(id), abs_ip.saturating_sub(m.start) + m.file_offset),
            None => (None, abs_ip),
        };
        FrameRecord {
            module_id,
            rel_ip,
            abs_ip,
            mode,
        }
    }

    fn rebuild_index_if_needed(&mut self) {
        if !self.index_dirty {
            return;
        }
        self.index = ModuleIndex::build(&self.modules, &self.active);
        self.index_dirty = false;
    }
}

#[derive(Default)]
struct ModuleIndex {
    by_process: FxHashMap<i32, ModuleIndexGroup>,
    kernel: ModuleIndexGroup,
}

impl ModuleIndex {
    fn build(modules: &[ModuleRecord], active: &[bool]) -> Self {
        let mut index = Self::default();
        for (module, &active) in modules.iter().zip(active) {
            if !active {
                continue;
            }
            let entry = ModuleIndexEntry {
                start: module.start,
                end: module.end,
                id: module.id,
            };
            if module.is_kernel {
                index.kernel.push(entry);
            } else {
                index
                    .by_process
                    .entry(module.process_id)
                    .or_default()
                    .push(entry);
            }
        }
        index.kernel.finish();
        for group in index.by_process.values_mut() {
            group.finish();
        }
        index
    }

    fn find(&self, process_id: i32, address: u64) -> Option<u32> {
        let process_module = self
            .by_process
            .get(&process_id)
            .and_then(|group| group.find(address));
        let kernel_module = self.kernel.find(address);
        process_module.into_iter().chain(kernel_module).max()
    }
}

#[derive(Default)]
struct ModuleIndexGroup {
    entries: Vec<ModuleIndexEntry>,
    has_overlaps: bool,
}

impl ModuleIndexGroup {
    fn push(&mut self, entry: ModuleIndexEntry) {
        self.entries.push(entry);
    }

    fn finish(&mut self) {
        let mut sorted = self.entries.clone();
        sorted.sort_by_key(|entry| (entry.start, entry.id));
        self.has_overlaps = sorted
            .windows(2)
            .any(|window| window[0].end > window[1].start);
        if !self.has_overlaps {
            self.entries = sorted;
        }
    }

    fn find(&self, address: u64) -> Option<u32> {
        if self.has_overlaps {
            return self
                .entries
                .iter()
                .rev()
                .find(|entry| entry.start <= address && address < entry.end)
                .map(|entry| entry.id);
        }
        let idx = self.entries.partition_point(|entry| entry.start <= address);
        let entry = self.entries.get(idx.checked_sub(1)?)?;
        (address < entry.end).then_some(entry.id)
    }
}

#[derive(Clone, Copy)]
struct ModuleIndexEntry {
    start: u64,
    end: u64,
    id: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writer() -> PerfSpoolWriter<Vec<u8>> {
        PerfSpoolWriter {
            writer: Vec::new(),
            last_timestamp_ns: 0,
            frame_cache: FxHashMap::default(),
            stack_cache: FxHashMap::default(),
            thread_cache: FxHashMap::default(),
        }
    }

    fn module(process_id: i32, start: u64, end: u64, path: &str, is_kernel: bool) -> ModuleRecord {
        ModuleRecord {
            id: 0,
            process_id,
            start,
            end,
            file_offset: 0,
            inode: 0,
            path: path.into(),
            is_kernel,
        }
    }

    #[test]
    fn module_table_resolves_with_index_and_latest_overlap_wins() {
        let mut table = ModuleTable::default();
        let mut writer = writer();
        let first = table
            .intern_module(module(7, 0x1000, 0x3000, "/first", false), &mut writer)
            .unwrap();
        let second = table
            .intern_module(module(7, 0x0800, 0x4000, "/second", false), &mut writer)
            .unwrap();

        let resolved = table.resolve_frame(7, 0x2000, FrameMode::User);

        assert_eq!(first, 0);
        assert_eq!(second, 1);
        assert_eq!(resolved.module_id, Some(second));
    }

    #[test]
    fn module_table_rebuilds_index_after_deactivation() {
        let mut table = ModuleTable::default();
        let mut writer = writer();
        let first = table
            .intern_module(module(7, 0x1000, 0x3000, "/first", false), &mut writer)
            .unwrap();
        let _second = table
            .intern_module(module(7, 0x0800, 0x4000, "/second", false), &mut writer)
            .unwrap();

        table.deactivate_process_modules(7);
        table
            .intern_module(module(7, 0x1000, 0x3000, "/first", false), &mut writer)
            .unwrap();
        let resolved = table.resolve_frame(7, 0x2000, FrameMode::User);

        assert_ne!(resolved.module_id, Some(first));
        assert!(resolved.module_id.is_some());
    }
}

fn read_module_mmap(reader: &mut MmapSpoolCursor) -> io::Result<ModuleRecord> {
    let id = reader.read_varint::<u64>()? as u32;
    let process_id = reader.read_varint::<i64>()? as i32;
    let start = reader.read_varint::<u64>()?;
    let end = reader.read_varint::<u64>()?;
    let file_offset = reader.read_varint::<u64>()?;
    let inode = reader.read_varint::<u64>()?;
    let mut flag = [0_u8; 1];
    reader.read_exact(&mut flag)?;
    let len = reader.read_varint::<u64>()? as usize;
    let range = reader.read_bytes_range(len)?;
    let path = ModulePath::from_mmap(Arc::clone(&reader.mmap), range)?;
    Ok(ModuleRecord {
        id,
        process_id,
        start,
        end,
        file_offset,
        path,
        is_kernel: flag[0] != 0,
        inode,
    })
}

fn read_process_exec(reader: &mut impl Read) -> io::Result<ProcessExecRecord> {
    let timestamp_ns = reader.read_varint::<u64>()?;
    let process_id = reader.read_varint::<i64>()? as i32;
    let mut flag = [0_u8; 1];
    reader.read_exact(&mut flag)?;
    Ok(ProcessExecRecord {
        timestamp_ns,
        process_id,
        is_python_runtime: flag[0] != 0,
    })
}

fn write_compact_frame(writer: &mut impl Write, frame: &FrameRecord) -> io::Result<()> {
    let (tag, address) = match frame.module_id {
        Some(module_id) => (u64::from(module_id) << 1, frame.rel_ip),
        None => (
            1 | (u64::from(frame.mode == FrameMode::Kernel) << 1),
            frame.abs_ip,
        ),
    };
    writer.write_varint(tag)?;
    writer.write_varint(address).map(drop)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn check_id(reader: &mut impl Read, expected: usize, kind: &str) -> io::Result<()> {
    let id = reader.read_varint::<u64>()? as usize;
    if id != expected {
        return Err(invalid_data(format!(
            "{kind} id {id} did not match expected {expected}"
        )));
    }
    Ok(())
}

fn bounded_id(raw: u64, limit: usize, kind: &str) -> io::Result<u32> {
    let id = u32::try_from(raw).map_err(|_| invalid_data(format!("{kind} id too large")))?;
    if (id as usize) >= limit {
        return Err(invalid_data(format!("{kind} references missing id {id}")));
    }
    Ok(id)
}

fn read_id_within(reader: &mut impl Read, limit: usize, kind: &str) -> io::Result<u32> {
    bounded_id(reader.read_varint::<u64>()?, limit, kind)
}

fn read_frame(
    reader: &mut impl Read,
    modules: &[ModuleRecord],
    expected_id: usize,
) -> io::Result<FrameRecord> {
    check_id(reader, expected_id, "frame")?;
    let tag = reader.read_varint::<u64>()?;
    let address = reader.read_varint::<u64>()?;
    if tag & 1 == 0 {
        let module_id =
            u32::try_from(tag >> 1).map_err(|_| invalid_data("frame module id too large"))?;
        let module = modules
            .get(module_id as usize)
            .ok_or_else(|| invalid_data(format!("frame references missing module {module_id}")))?;
        let abs_ip = module
            .start
            .saturating_add(address.saturating_sub(module.file_offset));
        Ok(FrameRecord {
            module_id: Some(module_id),
            rel_ip: address,
            abs_ip,
            mode: frame_mode(module.is_kernel),
        })
    } else {
        Ok(FrameRecord {
            module_id: None,
            rel_ip: address,
            abs_ip: address,
            mode: frame_mode(tag & 2 != 0),
        })
    }
}

fn frame_mode(is_kernel: bool) -> FrameMode {
    if is_kernel {
        FrameMode::Kernel
    } else {
        FrameMode::User
    }
}

fn read_stack_node(
    reader: &mut impl Read,
    stack_nodes: &[StackNodeRecord],
    frame_count: usize,
) -> io::Result<StackNodeRecord> {
    let expected_id = stack_nodes.len();
    check_id(reader, expected_id, "stack")?;
    let raw_prefix = reader.read_varint::<u64>()?;
    let prefix = (raw_prefix != u64::from(NONE_U32))
        .then(|| bounded_id(raw_prefix, expected_id, "stack prefix"))
        .transpose()?;
    let frame_id = read_id_within(reader, frame_count, "stack frame")?;
    let depth = prefix.map_or(1, |id| stack_nodes[id as usize].depth.saturating_add(1));
    Ok(StackNodeRecord {
        prefix,
        frame_id,
        depth,
    })
}

fn read_thread(reader: &mut impl Read, expected_id: usize) -> io::Result<(i32, u64)> {
    check_id(reader, expected_id, "thread")?;
    let process_id = reader.read_varint::<i64>()? as i32;
    let thread_id = reader.read_varint::<u64>()?;
    Ok((process_id, thread_id))
}

fn read_sample(
    reader: &mut impl Read,
    threads: &[(i32, u64)],
    stack_count: usize,
    last_timestamp_ns: &mut u64,
) -> io::Result<OwnedSampleRecord> {
    let delta = reader.read_varint::<i64>()?;
    let timestamp_ns = last_timestamp_ns.saturating_add_signed(delta);
    *last_timestamp_ns = timestamp_ns;
    let thread_ref = reader.read_varint::<u64>()? as usize;
    let (process_id, thread_id) = threads
        .get(thread_ref)
        .copied()
        .ok_or_else(|| invalid_data(format!("sample references missing thread {thread_ref}")))?;
    let stack_id = read_id_within(reader, stack_count, "sample stack")?;
    Ok(OwnedSampleRecord {
        timestamp_ns,
        process_id,
        thread_id,
        stack_id,
    })
}

fn write_bytes(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    writer.write_varint(bytes.len() as u64)?;
    writer.write_all(bytes)
}
