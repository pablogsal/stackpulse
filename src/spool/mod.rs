use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use integer_encoding::{VarInt, VarIntReader, VarIntWriter};
use memmap2::Mmap;
use rustc_hash::FxHashMap;

mod model;
mod modules;
pub use model::{
    FrameMode, FrameRecord, ModulePath, ModuleRecord, OwnedSampleRecord, ProcessExecRecord,
};
pub(crate) use modules::ModuleTable;
pub(crate) use modules::ModuleUpdate;

const MAGIC_V1: &[u8; 8] = b"SPULSE1\0";
const MAGIC_V2: &[u8; 8] = b"SPULSE2\0";
pub(crate) const CURRENT_MAGIC: &[u8; 8] = b"SPULSE3\0";
const REC_MODULE: u8 = 1;
const REC_FRAME: u8 = 2;
const REC_STACK: u8 = 3;
const REC_THREAD: u8 = 4;
const REC_SAMPLE: u8 = 5;
const REC_PROCESS_EXEC: u8 = 6;
const REC_MODULE_DEACTIVATE: u8 = 7;
const REC_MODULE_DEACTIVATE_ONE: u8 = 8;
const TRUNCATED_STACK_MARKER_TAG: u64 = 5;
const NONE_U32: u32 = u32::MAX;

#[derive(Clone, Copy, Debug)]
struct StackNodeRecord {
    prefix: Option<u32>,
    frame_id: u32,
    depth: usize,
}

pub struct PerfSpoolWriter<W: Write> {
    writer: W,
    last_timestamp_ns: u64,
    // Frames pinned to a module id resolve through that id on the read side
    // regardless of surrounding module records, so they are interned once for
    // the whole recording. Unpinned frames are resolved against the module
    // set visible at their position in the file, so their cache must be
    // dropped whenever that set changes (write_module / deactivation).
    pinned_frame_cache: FxHashMap<FrameRecord, u32>,
    unpinned_frame_cache: FxHashMap<FrameRecord, u32>,
    next_frame_id: u32,
    stack_cache: FxHashMap<(u32, u32), u32>,
    thread_cache: FxHashMap<(i32, u64), u32>,
}

impl PerfSpoolWriter<BufWriter<File>> {
    pub fn create<P: AsRef<Path>>(
        path: P,
        start_timestamp_us: u64,
        sample_interval_us: u64,
    ) -> io::Result<Self> {
        Self::from_writer(
            BufWriter::new(File::create(path)?),
            start_timestamp_us,
            sample_interval_us,
        )
    }
}

impl<W: Write> PerfSpoolWriter<W> {
    pub(crate) fn from_writer(
        writer: W,
        start_timestamp_us: u64,
        sample_interval_us: u64,
    ) -> io::Result<Self> {
        let mut writer = Self {
            writer,
            pinned_frame_cache: FxHashMap::default(),
            unpinned_frame_cache: FxHashMap::default(),
            next_frame_id: 0,
            stack_cache: FxHashMap::default(),
            thread_cache: FxHashMap::default(),
            last_timestamp_ns: 0,
        };
        writer.writer.write_all(CURRENT_MAGIC)?;
        writer.writer.write_varint(start_timestamp_us)?;
        writer.writer.write_varint(sample_interval_us)?;
        Ok(writer)
    }

    #[cfg(any(test, feature = "bench-support"))]
    pub(crate) fn into_inner(self) -> W {
        self.writer
    }

    pub fn write_module(&mut self, module: &ModuleRecord) -> io::Result<()> {
        self.writer.write_all(&[REC_MODULE])?;
        self.writer.write_varint(module.id as u64)?;
        self.writer.write_varint(module.process_id as i64)?;
        self.writer.write_varint(module.start)?;
        self.writer.write_varint(module.end)?;
        self.writer.write_varint(module.file_offset)?;
        self.writer.write_varint(module.inode)?;
        self.writer.write_varint(u64::from(module.device_major))?;
        self.writer.write_varint(u64::from(module.device_minor))?;
        self.writer.write_varint(module.inode_generation)?;
        self.writer.write_all(&[u8::from(module.is_kernel)])?;
        write_bytes(&mut self.writer, module.path.as_bytes())?;
        self.unpinned_frame_cache.clear();
        Ok(())
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
        let mut frames = frames.into_iter().peekable();
        if frames.peek().is_none() {
            return Ok(None);
        }
        let delta = checked_sample_timestamp_delta(self.last_timestamp_ns, timestamp_ns)?;
        let Some(stack_id) = self.intern_stack(frames)? else {
            return Ok(None);
        };
        let thread_id = self.intern_thread(process_id, thread_id)?;

        self.writer.write_all(&[REC_SAMPLE])?;
        self.writer.write_varint(delta)?;
        self.writer.write_varint(u64::from(thread_id))?;
        self.writer.write_varint(u64::from(stack_id))?;
        // Advance the delta baseline only after the record is written; a failed
        // write would otherwise skew every later sample's timestamp.
        self.last_timestamp_ns = timestamp_ns;
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

    pub(crate) fn write_module_deactivation(&mut self, process_id: i32) -> io::Result<()> {
        self.writer.write_all(&[REC_MODULE_DEACTIVATE])?;
        self.writer.write_varint(i64::from(process_id))?;
        self.unpinned_frame_cache.clear();
        Ok(())
    }

    pub(crate) fn write_module_deactivation_one(&mut self, module_id: u32) -> io::Result<()> {
        self.writer.write_all(&[REC_MODULE_DEACTIVATE_ONE])?;
        self.writer.write_varint(u64::from(module_id))?;
        self.unpinned_frame_cache.clear();
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    fn intern_thread(&mut self, process_id: i32, thread_id: u64) -> io::Result<u32> {
        let key = (process_id, thread_id);
        if let Some(&id) = self.thread_cache.get(&key) {
            return Ok(id);
        }
        let id = next_spool_id(self.thread_cache.len(), "thread")?;
        self.writer.write_all(&[REC_THREAD])?;
        self.writer.write_varint(u64::from(id))?;
        self.writer.write_varint(i64::from(process_id))?;
        self.writer.write_varint(thread_id)?;
        self.thread_cache.insert(key, id);
        Ok(id)
    }

    fn intern_frame(&mut self, frame: &FrameRecord) -> io::Result<u32> {
        let Self {
            writer,
            pinned_frame_cache,
            unpinned_frame_cache,
            next_frame_id,
            ..
        } = self;
        // Truncated-stack markers resolve context-free on the read side, so
        // they are as durable as module-pinned frames.
        let cache = if frame.module_id.is_some() || frame.is_truncated_stack_marker() {
            pinned_frame_cache
        } else {
            unpinned_frame_cache
        };
        if let Some(&id) = cache.get(frame) {
            return Ok(id);
        }
        let id = *next_frame_id;
        if id == NONE_U32 {
            return Err(invalid_input("frame id space exhausted"));
        }
        writer.write_all(&[REC_FRAME])?;
        writer.write_varint(u64::from(id))?;
        write_compact_frame(writer, frame)?;
        cache.insert(*frame, id);
        *next_frame_id = next_frame_id
            .checked_add(1)
            .ok_or_else(|| invalid_input("frame id space exhausted"))?;
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
            let stack_id = next_spool_id(self.stack_cache.len(), "stack")?;
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
    sample_interval_us: u64,
    modules: Vec<ModuleRecord>,
    frames: Vec<FrameRecord>,
    frame_contexts: SpoolFrameModuleContexts,
    stack_nodes: Vec<StackNodeRecord>,
    samples: Vec<OwnedSampleRecord>,
    process_execs: Vec<ProcessExecRecord>,
    truncated_tail: bool,
}

/// Recorded module context for a raw frame.
#[derive(Clone, Copy, Debug)]
pub struct FrameModuleRef<'a> {
    /// Recorded module that contains the frame.
    pub module: &'a ModuleRecord,
    /// Address relative to the module's file-offset coordinate space.
    pub rel_ip: u64,
}

impl<'a> FrameModuleRef<'a> {
    #[must_use]
    pub(crate) fn into_owned(self) -> (ModuleRecord, u64) {
        (self.module.clone(), self.rel_ip)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrameLookupContext {
    frame_index: usize,
    module_limit: usize,
}

#[derive(Clone, Default)]
pub(crate) struct SpoolFrameModuleContexts {
    frame_module_limits: Arc<Vec<usize>>,
    module_deactivated_at: Arc<Vec<Option<usize>>>,
}

impl SpoolFrameModuleContexts {
    fn new(frame_module_limits: Vec<usize>, module_deactivated_at: Vec<Option<usize>>) -> Self {
        Self {
            frame_module_limits: Arc::new(frame_module_limits),
            module_deactivated_at: Arc::new(module_deactivated_at),
        }
    }

    pub(crate) fn for_frame_id(&self, frame_id: u32) -> Option<FrameLookupContext> {
        let frame_index = frame_id as usize;
        self.frame_module_limits
            .get(frame_index)
            .copied()
            .map(|module_limit| FrameLookupContext {
                frame_index,
                module_limit,
            })
    }

    fn module_active(&self, module_index: usize, context: FrameLookupContext) -> bool {
        module_index < context.module_limit
            && self
                .module_deactivated_at
                .get(module_index)
                .copied()
                .flatten()
                .is_none_or(|deactivated_at| context.frame_index < deactivated_at)
    }
}

/// Raw frame plus its recorded module context, when Stackpulse had one.
#[derive(Clone, Copy, Debug)]
pub struct FrameContext<'a> {
    /// Raw frame from the interned stack.
    pub frame: &'a FrameRecord,
    /// Recorded module context for `frame`.
    pub module: Option<FrameModuleRef<'a>>,
}

/// Borrowed raw frames with recorded module context for one interned stack.
pub struct StackFrameContexts<'a> {
    reader: &'a PerfSpoolReader,
    process_id: i32,
    frames: StackFrameRefs<'a>,
}

/// Borrowed sample and its no-copy raw stack iterator.
pub struct SampleStack<'a> {
    /// Sample metadata.
    pub sample: &'a OwnedSampleRecord,
    /// Borrowed raw frames for `sample.stack_id`.
    pub frames: StackFrameRefs<'a>,
}

/// No-copy iterator over all samples and their raw stacks.
pub struct SampleStacks<'a> {
    reader: &'a PerfSpoolReader,
    samples: std::slice::Iter<'a, OwnedSampleRecord>,
}

/// Borrowed raw frames for one interned stack.
pub struct StackFrameRefs<'a> {
    frames: &'a [FrameRecord],
    stack_nodes: &'a [StackNodeRecord],
    current: Option<u32>,
    remaining: usize,
}

pub(crate) struct StackFrameRef<'a> {
    pub(crate) id: u32,
    pub(crate) frame: &'a FrameRecord,
}

impl<'a> StackFrameRefs<'a> {
    pub(crate) fn next_with_id(&mut self) -> Option<StackFrameRef<'a>> {
        let id = self.current?;
        let node = self.stack_nodes.get(id as usize)?;
        self.current = node.prefix;
        self.remaining = self.remaining.saturating_sub(1);
        self.frames
            .get(node.frame_id as usize)
            .map(|frame| StackFrameRef {
                id: node.frame_id,
                frame,
            })
    }
}

impl<'a> Iterator for StackFrameRefs<'a> {
    type Item = &'a FrameRecord;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_with_id().map(|frame_ref| frame_ref.frame)
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

impl<'a> Iterator for StackFrameContexts<'a> {
    type Item = FrameContext<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let frame_ref = self.frames.next_with_id()?;
        Some(
            self.reader
                .frame_context(self.process_id, frame_ref.id, frame_ref.frame),
        )
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.frames.size_hint()
    }
}

impl ExactSizeIterator for StackFrameContexts<'_> {
    fn len(&self) -> usize {
        self.frames.len()
    }
}

impl<'a> Iterator for SampleStacks<'a> {
    type Item = SampleStack<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let sample = self.samples.next()?;
        let frames = self
            .reader
            .stack_frame_refs(sample.stack_id)
            .expect("sample stack ids are validated when opening the spool");
        Some(SampleStack { sample, frames })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.samples.size_hint()
    }
}

impl ExactSizeIterator for SampleStacks<'_> {
    fn len(&self) -> usize {
        self.samples.len()
    }
}

impl PerfSpoolReader {
    /// Open and read a profile file.
    ///
    /// The reader borrows path strings from a memory map of the file. The file
    /// must not be truncated or mutated while the reader is alive.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let mmap = Arc::new(unsafe { Mmap::map(&file)? });
        let mut reader = MmapSpoolCursor::new(Arc::clone(&mmap));
        let spool_version = reader.check_magic()?;
        let start_timestamp_us = reader.read_varint::<u64>()?;
        let sample_interval_us = reader.read_varint::<u64>()?;
        let (
            mut modules,
            mut module_deactivated_at,
            mut frames,
            mut frame_module_limits,
            mut stack_nodes,
            mut threads,
            mut samples,
            mut process_execs,
        ) = (
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut last_timestamp_ns = 0_u64;
        let mut truncated_tail = false;
        while let Some(tag) = reader.read_tag()? {
            // Each record's reads run before any push, so a record truncated by
            // a crash mid-write leaves the accumulated state untouched. Stop at
            // such a tail and keep the prefix (records only reference earlier
            // ones); still surface real corruption (bad tag, invalid data).
            let parsed = (|| -> io::Result<()> {
                match tag {
                    REC_MODULE => {
                        modules.push(read_module_mmap(&mut reader, modules.len(), spool_version)?);
                        module_deactivated_at.push(None);
                    }
                    REC_FRAME => {
                        let module_limit = modules.len();
                        frames.push(read_frame(&mut reader, &modules, frames.len())?);
                        frame_module_limits.push(module_limit);
                    }
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
                    REC_MODULE_DEACTIVATE => {
                        let process_id = read_process_id(&mut reader)?;
                        let deactivated_at = frames.len();
                        for (module, deactivated) in modules.iter().zip(&mut module_deactivated_at)
                        {
                            if module.process_id == process_id && !module.is_kernel {
                                deactivated.get_or_insert(deactivated_at);
                            }
                        }
                    }
                    REC_MODULE_DEACTIVATE_ONE => {
                        if spool_version < 2 {
                            return Err(invalid_data(
                                "targeted module deactivation requires spool version 2",
                            ));
                        }
                        let module_id =
                            read_index_within(&mut reader, modules.len(), "module deactivation")?;
                        module_deactivated_at[module_id].get_or_insert(frames.len());
                    }
                    other => return Err(invalid_data(format!("unknown spool record tag {other}"))),
                }
                Ok(())
            })();
            if let Err(err) = parsed {
                // A record cut off by a crash leaves the cursor at EOF (see
                // MmapSpoolCursor). UnexpectedEof with bytes still left is
                // corruption, not a truncated tail.
                if err.kind() == io::ErrorKind::UnexpectedEof && reader.at_eof() {
                    truncated_tail = true;
                    tracing::warn!(
                        "spool tail truncated mid-record; keeping {} samples",
                        samples.len()
                    );
                    break;
                }
                return Err(err);
            }
        }
        let frame_contexts =
            SpoolFrameModuleContexts::new(frame_module_limits, module_deactivated_at);
        Ok(Self {
            start_timestamp_us,
            sample_interval_us,
            modules,
            frames,
            frame_contexts,
            stack_nodes,
            samples,
            process_execs,
            truncated_tail,
        })
    }

    /// Return the profile timeline anchor in microseconds.
    pub fn start_timestamp_us(&self) -> u64 {
        self.start_timestamp_us
    }

    /// Return the optional sample interval metadata in microseconds.
    pub fn sample_interval_us(&self) -> u64 {
        self.sample_interval_us
    }

    /// Return code areas recorded in the profile.
    pub fn modules(&self) -> &[ModuleRecord] {
        &self.modules
    }

    /// Return all interned raw frame records.
    pub fn frames(&self) -> &[FrameRecord] {
        &self.frames
    }

    /// Return samples recorded in the profile.
    pub fn samples(&self) -> &[OwnedSampleRecord] {
        &self.samples
    }

    /// Return process execution markers recorded in the profile.
    pub fn process_execs(&self) -> &[ProcessExecRecord] {
        &self.process_execs
    }

    /// Whether the file ended mid-record (e.g. the recorder crashed while
    /// writing) and the reader recovered by keeping only the intact prefix.
    pub fn recovered_from_truncated_tail(&self) -> bool {
        self.truncated_tail
    }

    /// Return absolute kernel instruction pointers present in interned frame records.
    pub fn kernel_frame_addresses(&self) -> impl Iterator<Item = u64> + '_ {
        self.frames
            .iter()
            .filter_map(|frame| (frame.mode == FrameMode::Kernel).then_some(frame.abs_ip))
    }

    pub(crate) fn module_for_frame(
        &self,
        process_id: i32,
        frame_id: u32,
        frame: &FrameRecord,
    ) -> Option<FrameModuleRef<'_>> {
        let context = self.frame_contexts.for_frame_id(frame_id)?;
        module_for_frame_with_context(
            &self.modules,
            &self.frame_contexts,
            context,
            process_id,
            frame,
        )
    }

    fn frame_context<'a>(
        &'a self,
        process_id: i32,
        frame_id: u32,
        frame: &'a FrameRecord,
    ) -> FrameContext<'a> {
        FrameContext {
            frame,
            module: self.module_for_frame(process_id, frame_id, frame),
        }
    }

    pub(crate) fn frame_module_contexts(&self) -> SpoolFrameModuleContexts {
        self.frame_contexts.clone()
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

    /// Borrow raw frame contexts for `stack_id` without copying them.
    pub fn stack_frame_contexts(
        &self,
        process_id: i32,
        stack_id: u32,
    ) -> io::Result<StackFrameContexts<'_>> {
        Ok(StackFrameContexts {
            reader: self,
            process_id,
            frames: self.stack_frame_refs(stack_id)?,
        })
    }

    /// Iterate over all samples with borrowed raw frames.
    pub fn sample_stacks(&self) -> SampleStacks<'_> {
        SampleStacks {
            reader: self,
            samples: self.samples.iter(),
        }
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

trait SpoolRead {
    fn read_exact_spool(&mut self, buf: &mut [u8]) -> io::Result<()>;
    fn read_varint<VI: VarInt>(&mut self) -> io::Result<VI>;
}

impl MmapSpoolCursor {
    fn new(mmap: Arc<Mmap>) -> Self {
        Self { mmap, position: 0 }
    }

    fn check_magic(&mut self) -> io::Result<u8> {
        let mut magic = [0_u8; 8];
        self.read_exact_spool(&mut magic)?;
        match &magic {
            magic if magic == MAGIC_V1 => Ok(1),
            magic if magic == MAGIC_V2 => Ok(2),
            magic if magic == CURRENT_MAGIC => Ok(3),
            _ => Err(invalid_data("invalid stackpulse spool magic")),
        }
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
            // Consume the partial tail so `at_eof` holds: every read that
            // fails because the record extends past the end of the file must
            // leave the cursor at EOF, distinguishing crash truncation from
            // mid-file corruption in the recovery loop.
            self.position = self.mmap.len();
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated spool byte range",
            ));
        }
        self.position = end;
        Ok(start..end)
    }

    fn at_eof(&self) -> bool {
        self.position == self.mmap.len()
    }

    fn read_varint<VI: VarInt>(&mut self) -> io::Result<VI> {
        let bytes = &self.mmap[self.position..];
        match VI::decode_var(bytes) {
            Some((value, len)) => {
                self.position += len;
                Ok(value)
            }
            None => {
                if bytes.len() >= 10 {
                    return Err(invalid_data("invalid spool varint"));
                }
                self.position = self.mmap.len();
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated spool varint",
                ))
            }
        }
    }
}

impl SpoolRead for MmapSpoolCursor {
    fn read_exact_spool(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let range = self.read_bytes_range(buf.len())?;
        buf.copy_from_slice(&self.mmap[range]);
        Ok(())
    }

    fn read_varint<VI: VarInt>(&mut self) -> io::Result<VI> {
        MmapSpoolCursor::read_varint(self)
    }
}

impl SpoolRead for &[u8] {
    fn read_exact_spool(&mut self, buf: &mut [u8]) -> io::Result<()> {
        Read::read_exact(self, buf)
    }

    fn read_varint<VI: VarInt>(&mut self) -> io::Result<VI> {
        VarIntReader::read_varint(self)
    }
}

fn read_module_mmap(
    reader: &mut MmapSpoolCursor,
    expected_id: usize,
    spool_version: u8,
) -> io::Result<ModuleRecord> {
    check_id(reader, expected_id, "module")?;
    let id = u32::try_from(expected_id).map_err(|_| invalid_data("module id too large"))?;
    let process_id = read_process_id(reader)?;
    let start = reader.read_varint::<u64>()?;
    let end = reader.read_varint::<u64>()?;
    let file_offset = reader.read_varint::<u64>()?;
    let inode = reader.read_varint::<u64>()?;
    let (device_major, device_minor, inode_generation) = if spool_version >= 3 {
        (
            u32::try_from(reader.read_varint::<u64>()?)
                .map_err(|_| invalid_data("module device major too large"))?,
            u32::try_from(reader.read_varint::<u64>()?)
                .map_err(|_| invalid_data("module device minor too large"))?,
            reader.read_varint::<u64>()?,
        )
    } else {
        (0, 0, 0)
    };
    let mut flag = [0_u8; 1];
    reader.read_exact_spool(&mut flag)?;
    let len = usize::try_from(reader.read_varint::<u64>()?)
        .map_err(|_| invalid_data("module path length too large"))?;
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
        device_major,
        device_minor,
        inode_generation,
    })
}

fn read_process_exec(reader: &mut impl SpoolRead) -> io::Result<ProcessExecRecord> {
    let timestamp_ns = reader.read_varint::<u64>()?;
    let process_id = read_process_id(reader)?;
    let mut flag = [0_u8; 1];
    reader.read_exact_spool(&mut flag)?;
    Ok(ProcessExecRecord {
        timestamp_ns,
        process_id,
        is_python_runtime: flag[0] != 0,
    })
}

fn write_compact_frame(writer: &mut impl Write, frame: &FrameRecord) -> io::Result<()> {
    if frame.mode == FrameMode::TruncatedStackMarker {
        if *frame != FrameRecord::truncated_stack_marker() {
            return Err(invalid_input("invalid truncated stack marker frame"));
        }
        writer.write_varint(TRUNCATED_STACK_MARKER_TAG)?;
        return writer.write_varint(0).map(drop);
    }

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

pub(crate) fn module_for_frame_unbounded<'a>(
    modules: &'a [ModuleRecord],
    process_id: i32,
    frame: &FrameRecord,
) -> Option<FrameModuleRef<'a>> {
    if frame.mode == FrameMode::TruncatedStackMarker {
        return None;
    }
    if let Some(module_id) = frame.module_id {
        return Some(FrameModuleRef {
            module: modules.get(module_id as usize)?,
            rel_ip: frame.rel_ip,
        });
    }
    let module = modules
        .iter()
        .rev()
        .find(|module| module_owns_frame(module, process_id, frame))?;
    Some(frame_module_ref(module, frame))
}

pub(crate) fn module_for_frame_with_context<'a>(
    modules: &'a [ModuleRecord],
    contexts: &SpoolFrameModuleContexts,
    context: FrameLookupContext,
    process_id: i32,
    frame: &FrameRecord,
) -> Option<FrameModuleRef<'a>> {
    if frame.mode == FrameMode::TruncatedStackMarker || frame.module_id.is_some() {
        return module_for_frame_unbounded(modules, process_id, frame);
    }
    let module_limit = context.module_limit.min(modules.len());
    let module = modules
        .get(..module_limit)?
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, module)| {
            if !contexts.module_active(index, context) {
                return None;
            }
            module_owns_frame(module, process_id, frame).then_some(module)
        })?;
    Some(frame_module_ref(module, frame))
}

fn module_owns_frame(module: &ModuleRecord, process_id: i32, frame: &FrameRecord) -> bool {
    let owned_by = match frame.mode {
        FrameMode::Kernel => module.is_kernel,
        FrameMode::User => !module.is_kernel && module.process_id == process_id,
        FrameMode::TruncatedStackMarker => false,
    };
    owned_by && module.start <= frame.abs_ip && frame.abs_ip < module.end
}

fn frame_module_ref<'a>(module: &'a ModuleRecord, frame: &FrameRecord) -> FrameModuleRef<'a> {
    FrameModuleRef {
        module,
        rel_ip: frame
            .abs_ip
            .saturating_sub(module.start)
            .saturating_add(module.file_offset),
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn next_spool_id(len: usize, kind: &str) -> io::Result<u32> {
    let id = u32::try_from(len).map_err(|_| invalid_input(format!("{kind} id space exhausted")))?;
    if id == NONE_U32 {
        return Err(invalid_input(format!("{kind} id space exhausted")));
    }
    Ok(id)
}

fn check_id(reader: &mut impl SpoolRead, expected: usize, kind: &str) -> io::Result<()> {
    let id = usize::try_from(reader.read_varint::<u64>()?)
        .map_err(|_| invalid_data(format!("{kind} id too large")))?;
    if id != expected {
        return Err(invalid_data(format!(
            "{kind} id {id} did not match expected {expected}"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct BoundedId {
    id: u32,
    index: usize,
}

fn bounded_id(raw: u64, limit: usize, kind: &str) -> io::Result<u32> {
    bounded_id_index(raw, limit, kind).map(|bounded| bounded.id)
}

fn bounded_id_index(raw: u64, limit: usize, kind: &str) -> io::Result<BoundedId> {
    let id = u32::try_from(raw).map_err(|_| invalid_data(format!("{kind} id too large")))?;
    let index = id_index(id, kind)?;
    check_bounded_index(index, limit, id, kind)?;
    Ok(BoundedId { id, index })
}

fn id_index(id: u32, kind: &str) -> io::Result<usize> {
    usize::try_from(id).map_err(|_| invalid_data(format!("{kind} id too large")))
}

fn bounded_index(raw: u64, limit: usize, kind: &str) -> io::Result<usize> {
    let index = usize::try_from(raw).map_err(|_| invalid_data(format!("{kind} id too large")))?;
    check_bounded_index(index, limit, index, kind)?;
    Ok(index)
}

fn check_bounded_index(
    index: usize,
    limit: usize,
    display_id: impl std::fmt::Display,
    kind: &str,
) -> io::Result<()> {
    if index >= limit {
        return Err(invalid_data(format!(
            "{kind} references missing id {display_id}"
        )));
    }
    Ok(())
}

fn read_id_within(reader: &mut impl SpoolRead, limit: usize, kind: &str) -> io::Result<u32> {
    bounded_id(reader.read_varint::<u64>()?, limit, kind)
}

fn read_index_within(reader: &mut impl SpoolRead, limit: usize, kind: &str) -> io::Result<usize> {
    bounded_index(reader.read_varint::<u64>()?, limit, kind)
}

fn read_frame(
    reader: &mut impl SpoolRead,
    modules: &[ModuleRecord],
    expected_id: usize,
) -> io::Result<FrameRecord> {
    check_id(reader, expected_id, "frame")?;
    let tag = reader.read_varint::<u64>()?;
    let encoded_ip = reader.read_varint::<u64>()?;
    if tag == TRUNCATED_STACK_MARKER_TAG {
        if encoded_ip != 0 {
            return Err(invalid_data("truncated stack marker has nonzero payload"));
        }
        return Ok(FrameRecord::truncated_stack_marker());
    }
    if tag & 1 == 0 {
        let module_ref = bounded_id_index(tag >> 1, modules.len(), "frame module")?;
        let module = &modules[module_ref.index];
        let offset = encoded_ip.checked_sub(module.file_offset).ok_or_else(|| {
            invalid_data(format!(
                "frame address precedes module {} file offset",
                module_ref.id
            ))
        })?;
        let span = module.end.checked_sub(module.start).ok_or_else(|| {
            invalid_data(format!(
                "module {} end precedes module start",
                module_ref.id
            ))
        })?;
        if offset >= span {
            return Err(invalid_data(format!(
                "frame address outside referenced module {}",
                module_ref.id
            )));
        }
        let abs_ip = module.start + offset;
        Ok(FrameRecord {
            module_id: Some(module_ref.id),
            rel_ip: encoded_ip,
            abs_ip,
            mode: frame_mode(module.is_kernel),
        })
    } else {
        Ok(FrameRecord {
            module_id: None,
            rel_ip: encoded_ip,
            abs_ip: encoded_ip,
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
    reader: &mut impl SpoolRead,
    stack_nodes: &[StackNodeRecord],
    frame_count: usize,
) -> io::Result<StackNodeRecord> {
    let expected_id = stack_nodes.len();
    check_id(reader, expected_id, "stack")?;
    let raw_prefix = reader.read_varint::<u64>()?;
    let prefix = (raw_prefix != u64::from(NONE_U32))
        .then(|| bounded_id_index(raw_prefix, expected_id, "stack prefix"))
        .transpose()?;
    let frame_id = read_id_within(reader, frame_count, "stack frame")?;
    let depth = prefix.map_or(1, |prefix| {
        stack_nodes[prefix.index].depth.saturating_add(1)
    });
    Ok(StackNodeRecord {
        prefix: prefix.map(|prefix| prefix.id),
        frame_id,
        depth,
    })
}

fn read_thread(reader: &mut impl SpoolRead, expected_id: usize) -> io::Result<(i32, u64)> {
    check_id(reader, expected_id, "thread")?;
    let process_id = read_process_id(reader)?;
    let thread_id = reader.read_varint::<u64>()?;
    Ok((process_id, thread_id))
}

fn read_process_id(reader: &mut impl SpoolRead) -> io::Result<i32> {
    let process_id = reader.read_varint::<i64>()?;
    i32::try_from(process_id)
        .map_err(|_| invalid_data(format!("process id {process_id} out of range")))
}

fn checked_sample_timestamp_delta(last_timestamp_ns: u64, timestamp_ns: u64) -> io::Result<i64> {
    let delta = i128::from(timestamp_ns) - i128::from(last_timestamp_ns);
    i64::try_from(delta)
        .map_err(|_| invalid_input(format!("sample timestamp delta {delta} out of range")))
}

fn read_sample(
    reader: &mut impl SpoolRead,
    threads: &[(i32, u64)],
    stack_count: usize,
    last_timestamp_ns: &mut u64,
) -> io::Result<OwnedSampleRecord> {
    let delta = reader.read_varint::<i64>()?;
    let timestamp_ns = last_timestamp_ns
        .checked_add_signed(delta)
        .ok_or_else(|| invalid_data(format!("sample timestamp delta {delta} out of range")))?;
    *last_timestamp_ns = timestamp_ns;
    let thread_ref = read_index_within(reader, threads.len(), "sample thread")?;
    let (process_id, thread_id) = threads[thread_ref];
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

#[cfg(test)]
mod tests {
    use super::*;

    fn writer() -> PerfSpoolWriter<Vec<u8>> {
        PerfSpoolWriter {
            writer: Vec::new(),
            last_timestamp_ns: 0,
            pinned_frame_cache: FxHashMap::default(),
            unpinned_frame_cache: FxHashMap::default(),
            next_frame_id: 0,
            stack_cache: FxHashMap::default(),
            thread_cache: FxHashMap::default(),
        }
    }

    fn frame(abs_ip: u64) -> FrameRecord {
        FrameRecord {
            module_id: None,
            rel_ip: abs_ip,
            abs_ip,
            mode: FrameMode::User,
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
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.into(),
            is_kernel,
        }
    }

    fn temp_spool_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("stackpulse-{name}-{}.spool", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn reader_recovers_records_before_a_crash_truncated_tail() {
        let path = temp_spool_path("truncated-tail");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        writer
            .write_sample_frames(1_000, 7, 11, [frame(0x1000)])
            .unwrap();
        writer
            .write_sample_frames(2_000, 7, 11, [frame(0x2000)])
            .unwrap();
        writer.flush().unwrap();
        let len = std::fs::metadata(&path).unwrap().len();
        drop(writer);

        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len - 1)
            .unwrap();

        let reader = PerfSpoolReader::open(&path).expect("truncated spool still opens");
        let _ = std::fs::remove_file(&path);
        assert!(!reader.samples().is_empty());
        assert!(reader.recovered_from_truncated_tail());
    }

    #[test]
    fn reader_recovers_when_a_length_prefixed_range_is_cut_short() {
        let path = temp_spool_path("truncated-path-bytes");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        writer
            .write_sample_frames(1_000, 7, 11, [frame(0x1000)])
            .unwrap();
        writer.flush().unwrap();
        let boundary = std::fs::metadata(&path).unwrap().len();
        writer
            .write_module(&module(7, 0x1000, 0x2000, "/some/long/module/path", false))
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        // Cut the file in the middle of the module path string, inside the
        // length-prefixed byte range.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(boundary + 8)
            .unwrap();

        let reader = PerfSpoolReader::open(&path).expect("truncated spool still opens");
        let _ = std::fs::remove_file(&path);

        assert_eq!(reader.samples().len(), 1);
        assert!(reader.modules().is_empty());
        assert!(reader.recovered_from_truncated_tail());
    }

    #[test]
    fn reader_rejects_overflowing_varint_corruption_mid_file() {
        let path = temp_spool_path("overflow-varint");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        writer
            .write_sample_frames(1_000, 7, 11, [frame(0x1000)])
            .unwrap();
        writer.flush().unwrap();
        let boundary = std::fs::metadata(&path).unwrap().len() as usize;
        writer
            .write_sample_frames(2_000, 7, 11, [frame(0x2000)])
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let mut bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() >= boundary + 11, "second record too short");
        bytes[boundary + 1..boundary + 11]
            .copy_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02]);
        std::fs::write(&path, &bytes).unwrap();

        let err = match PerfSpoolReader::open(&path) {
            Ok(_) => panic!("corruption must not open"),
            Err(err) => err,
        };
        let _ = std::fs::remove_file(&path);
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn truncated_stack_marker_round_trips_through_spool() {
        let path = temp_spool_path("truncated-marker");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        let marker = FrameRecord::truncated_stack_marker();
        let stack_id = writer
            .write_sample_frames(1_000, 7, 11, [frame(0x1000), marker])
            .unwrap()
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);

        let mut frames = Vec::new();
        reader.stack_frames(stack_id, &mut frames).unwrap();

        assert_eq!(frames, vec![frame(0x1000), marker]);
        assert!(frames[1].is_truncated_stack_marker());
    }

    #[test]
    fn truncated_stack_marker_only_stack_round_trips_through_spool() {
        let path = temp_spool_path("truncated-marker-only");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        let marker = FrameRecord::truncated_stack_marker();
        let stack_id = writer
            .write_sample_frames(1_000, 7, 11, [marker])
            .unwrap()
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);

        let mut frames = Vec::new();
        reader.stack_frames(stack_id, &mut frames).unwrap();

        assert_eq!(frames, vec![marker]);
    }

    #[test]
    fn writer_treats_truncated_stack_marker_as_stack_identity() {
        let mut writer = writer();
        let frame = frame(0x1000);
        let marker = FrameRecord::truncated_stack_marker();

        let plain = writer
            .write_sample_frames(0, 7, 11, [frame])
            .unwrap()
            .unwrap();
        let marked = writer
            .write_sample_frames(1, 7, 11, [frame, marker])
            .unwrap()
            .unwrap();
        let plain_again = writer
            .write_sample_frames(2, 7, 11, [frame])
            .unwrap()
            .unwrap();

        assert_ne!(plain, marked);
        assert_eq!(plain, plain_again);
    }

    #[test]
    fn module_for_frame_ignores_truncated_stack_marker() {
        let modules = [module(7, 0, 1, "/module", false)];

        assert!(
            module_for_frame_unbounded(&modules, 7, &FrameRecord::truncated_stack_marker())
                .is_none()
        );
    }

    #[test]
    fn pinned_frame_resolution_ignores_record_context() {
        let modules = [module(7, 0x1000, 0x2000, "/module", false)];
        let frame = FrameRecord {
            module_id: Some(0),
            rel_ip: 0x123,
            abs_ip: 0x1123,
            mode: FrameMode::User,
        };
        let context = FrameLookupContext {
            frame_index: 0,
            module_limit: 0,
        };

        let resolved = module_for_frame_with_context(
            &modules,
            &SpoolFrameModuleContexts::default(),
            context,
            7,
            &frame,
        )
        .unwrap();

        assert_eq!(resolved.module.id, 0);
        assert_eq!(resolved.rel_ip, 0x123);
    }

    #[test]
    fn reader_rejects_truncated_stack_marker_with_payload() {
        let mut bytes = Vec::new();
        bytes.write_varint(0_u64).unwrap();
        bytes.write_varint(TRUNCATED_STACK_MARKER_TAG).unwrap();
        bytes.write_varint(1_u64).unwrap();

        assert_invalid_data_contains(
            read_frame(&mut bytes.as_slice(), &[], 0),
            "truncated stack marker has nonzero payload",
            "reader accepted a malformed truncated stack marker",
        );
    }

    #[test]
    fn reader_exposes_no_copy_stacks_and_module_contexts() {
        let path = temp_spool_path("raw-api");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        writer
            .write_module(&ModuleRecord {
                id: 0,
                process_id: 7,
                start: 0x1000,
                end: 0x2000,
                file_offset: 0x100,
                inode: 1,
                device_major: 0,
                device_minor: 0,
                inode_generation: 0,
                path: "/first".into(),
                is_kernel: false,
            })
            .unwrap();
        writer
            .write_module(&ModuleRecord {
                id: 1,
                process_id: 7,
                start: 0x3000,
                end: 0x4000,
                file_offset: 0x200,
                inode: 2,
                device_major: 0,
                device_minor: 0,
                inode_generation: 0,
                path: "/second".into(),
                is_kernel: false,
            })
            .unwrap();
        writer
            .write_module(&ModuleRecord {
                id: 2,
                process_id: -1,
                start: 0xffff_ffff_8100_0000,
                end: 0xffff_ffff_8101_0000,
                file_offset: 0,
                inode: 0,
                device_major: 0,
                device_minor: 0,
                inode_generation: 0,
                path: "[kernel]".into(),
                is_kernel: true,
            })
            .unwrap();
        let stack_id = writer
            .write_sample_frames(
                1_000,
                7,
                11,
                [
                    FrameRecord {
                        module_id: Some(0),
                        rel_ip: 0x110,
                        abs_ip: 0x1010,
                        mode: FrameMode::User,
                    },
                    FrameRecord {
                        module_id: None,
                        rel_ip: 0x3010,
                        abs_ip: 0x3010,
                        mode: FrameMode::User,
                    },
                    FrameRecord {
                        module_id: None,
                        rel_ip: 0xffff_ffff_8100_0010,
                        abs_ip: 0xffff_ffff_8100_0010,
                        mode: FrameMode::Kernel,
                    },
                ],
            )
            .unwrap()
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(reader.start_timestamp_us(), 123);
        assert_eq!(reader.sample_interval_us(), 10);
        assert_eq!(reader.frames().len(), 3);
        assert_eq!(reader.sample_stacks().len(), 1);

        let sample_stack = reader.sample_stacks().next().unwrap();
        assert_eq!(sample_stack.sample.stack_id, stack_id);
        assert_eq!(sample_stack.frames.len(), 3);

        let contexts: Vec<_> = reader
            .stack_frame_contexts(7, stack_id)
            .unwrap()
            .map(|context| {
                (
                    context.frame.abs_ip,
                    context.module.map(|module| {
                        (
                            module.module.id,
                            module.module.path.as_str().to_owned(),
                            module.rel_ip,
                        )
                    }),
                )
            })
            .collect();
        assert_eq!(
            contexts,
            vec![
                (0x1010, Some((0, "/first".to_owned(), 0x110))),
                (0x3010, Some((1, "/second".to_owned(), 0x210))),
                (
                    0xffff_ffff_8100_0010,
                    Some((2, "[kernel]".to_owned(), 0x10))
                ),
            ]
        );
    }

    #[test]
    fn reader_does_not_resolve_moduleless_frames_to_future_modules() {
        let path = temp_spool_path("future-module");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        let stack_id = writer
            .write_sample_frames(1_000, 7, 11, [frame(0x1500)])
            .unwrap()
            .unwrap();
        writer
            .write_module(&ModuleRecord {
                id: 0,
                process_id: 7,
                start: 0x1000,
                end: 0x2000,
                file_offset: 0,
                inode: 1,
                device_major: 0,
                device_minor: 0,
                inode_generation: 0,
                path: "/future".into(),
                is_kernel: false,
            })
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let mut frames = reader.stack_frame_refs(stack_id).unwrap();
        let frame_ref = frames.next_with_id().unwrap();

        assert_eq!(frame_ref.frame.module_id, None);
        assert!(reader
            .module_for_frame(7, frame_ref.id, frame_ref.frame)
            .is_none());
        assert!(reader
            .stack_frame_contexts(7, stack_id)
            .unwrap()
            .next()
            .unwrap()
            .module
            .is_none());
    }

    #[test]
    fn reader_does_not_resolve_moduleless_frames_to_deactivated_modules() {
        let path = temp_spool_path("deactivated-module");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        let mut table = ModuleTable::default();
        table
            .intern_module(module(7, 0x1000, 0x2000, "/old", false), &mut writer)
            .unwrap();
        table.deactivate_process_modules(7, &mut writer).unwrap();
        let stack_id = writer
            .write_sample_frames(1_000, 7, 11, [frame(0x1500)])
            .unwrap()
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let mut frames = reader.stack_frame_refs(stack_id).unwrap();
        let frame_ref = frames.next_with_id().unwrap();

        assert!(reader
            .module_for_frame(7, frame_ref.id, frame_ref.frame)
            .is_none());
        assert!(reader
            .stack_frame_contexts(7, stack_id)
            .unwrap()
            .next()
            .unwrap()
            .module
            .is_none());
    }

    #[test]
    fn reader_resolves_moduleless_frames_before_later_deactivation() {
        let path = temp_spool_path("pre-deactivation-module");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        writer
            .write_module(&module(7, 0x1000, 0x2000, "/old", false))
            .unwrap();
        let stack_id = writer
            .write_sample_frames(1_000, 7, 11, [frame(0x1500)])
            .unwrap()
            .unwrap();
        writer.write_module_deactivation(7).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let context = reader
            .stack_frame_contexts(7, stack_id)
            .unwrap()
            .next()
            .unwrap();

        assert_eq!(
            context.module.map(|module| module.module.path.as_str()),
            Some("/old")
        );
    }

    #[test]
    fn writer_reinterns_moduleless_frames_when_module_context_changes() {
        let path = temp_spool_path("module-context-epoch");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        let first_stack = writer
            .write_sample_frames(1_000, 7, 11, [frame(0x1500)])
            .unwrap()
            .unwrap();
        writer
            .write_module(&module(7, 0x1000, 0x2000, "/new", false))
            .unwrap();
        let second_stack = writer
            .write_sample_frames(2_000, 7, 11, [frame(0x1500)])
            .unwrap()
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let first = reader
            .stack_frame_contexts(7, first_stack)
            .unwrap()
            .next()
            .unwrap();
        let second = reader
            .stack_frame_contexts(7, second_stack)
            .unwrap()
            .next()
            .unwrap();

        assert!(first.module.is_none());
        assert_eq!(
            second.module.map(|module| module.module.path.as_str()),
            Some("/new")
        );
    }

    #[test]
    fn writer_does_not_reintern_pinned_frames_when_module_context_changes() {
        let path = temp_spool_path("pinned-frame-stability");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        writer
            .write_module(&module(7, 0x1000, 0x2000, "/pinned", false))
            .unwrap();
        let pinned = FrameRecord {
            module_id: Some(0),
            rel_ip: 0x10,
            abs_ip: 0x1010,
            mode: FrameMode::User,
        };
        let first_stack = writer
            .write_sample_frames(1_000, 7, 11, [pinned])
            .unwrap()
            .unwrap();
        let mut unrelated = module(9, 0x9000, 0xa000, "/unrelated", false);
        unrelated.id = 1;
        writer.write_module(&unrelated).unwrap();
        let second_stack = writer
            .write_sample_frames(2_000, 7, 11, [pinned])
            .unwrap()
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(first_stack, second_stack);
        assert_eq!(reader.frames(), &[pinned]);
    }

    #[test]
    fn module_table_dedupes_active_modules_and_reinterns_after_deactivation() {
        let mut table = ModuleTable::default();
        let mut spool = writer();

        let first = table
            .intern_module(module(7, 0x1000, 0x2000, "/m", false), &mut spool)
            .unwrap();
        let duplicate = table
            .intern_module(module(7, 0x1000, 0x2000, "/m", false), &mut spool)
            .unwrap();
        assert_eq!(first, duplicate);

        let kernel = table
            .intern_module(module(7, 0x8000, 0x9000, "[kernel]", true), &mut spool)
            .unwrap();
        table.deactivate_process_modules(7, &mut spool).unwrap();

        let reinterned = table
            .intern_module(module(7, 0x1000, 0x2000, "/m", false), &mut spool)
            .unwrap();
        assert_ne!(first, reinterned);

        let kernel_again = table
            .intern_module(module(7, 0x8000, 0x9000, "[kernel]", true), &mut spool)
            .unwrap();
        assert_eq!(kernel, kernel_again);
    }

    #[test]
    fn reader_rejects_non_sequential_module_ids() {
        let path = temp_spool_path("bad-module-id");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        writer
            .write_module(&ModuleRecord {
                id: 7,
                process_id: 7,
                start: 0x1000,
                end: 0x2000,
                file_offset: 0,
                inode: 1,
                device_major: 0,
                device_minor: 0,
                inode_generation: 0,
                path: "/bad".into(),
                is_kernel: false,
            })
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let result = PerfSpoolReader::open(&path);
        let _ = std::fs::remove_file(path);
        assert_invalid_data_contains(
            result,
            "module id 7 did not match expected 0",
            "reader accepted a non-sequential module id",
        );
    }

    fn module_frame_reader_result(rel_ip: u64) -> io::Result<FrameRecord> {
        let mut bytes = Vec::new();
        bytes.write_varint(0_u64).unwrap();
        bytes.write_varint(0_u64).unwrap();
        bytes.write_varint(rel_ip).unwrap();
        read_frame(
            &mut bytes.as_slice(),
            &[ModuleRecord {
                id: 0,
                process_id: 7,
                start: 0x1000,
                end: 0x2000,
                file_offset: 0x100,
                inode: 1,
                device_major: 0,
                device_minor: 0,
                inode_generation: 0,
                path: "/module".into(),
                is_kernel: false,
            }],
            0,
        )
    }

    fn out_of_range_process_id() -> i64 {
        i64::from(i32::MAX) + 1
    }

    fn assert_error_contains<T>(
        result: io::Result<T>,
        kind: io::ErrorKind,
        expected: &str,
        message: &str,
    ) {
        let err = match result {
            Ok(_) => panic!("{message}"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), kind, "{message}: {err}");
        assert!(
            err.to_string().contains(expected),
            "unexpected error: {err}"
        );
    }

    fn assert_invalid_data_contains<T>(result: io::Result<T>, expected: &str, message: &str) {
        assert_error_contains(result, io::ErrorKind::InvalidData, expected, message);
    }

    fn assert_invalid_input_contains<T>(result: io::Result<T>, expected: &str, message: &str) {
        assert_error_contains(result, io::ErrorKind::InvalidInput, expected, message);
    }

    fn read_sample_with_delta(
        last_timestamp_ns: &mut u64,
        delta: i64,
    ) -> io::Result<OwnedSampleRecord> {
        let mut bytes = Vec::new();
        bytes.write_varint(delta).unwrap();
        bytes.write_varint(0_u64).unwrap();
        bytes.write_varint(0_u64).unwrap();
        read_sample(&mut bytes.as_slice(), &[(7, 11)], 1, last_timestamp_ns)
    }

    #[test]
    fn reader_rejects_sample_timestamp_underflow() {
        let mut last_timestamp_ns = 0;
        assert_invalid_data_contains(
            read_sample_with_delta(&mut last_timestamp_ns, -1),
            "sample timestamp delta -1 out of range",
            "reader accepted a sample timestamp underflow",
        );
    }

    #[test]
    fn reader_rejects_sample_timestamp_overflow() {
        let mut last_timestamp_ns = u64::MAX;
        assert_invalid_data_contains(
            read_sample_with_delta(&mut last_timestamp_ns, 1),
            "sample timestamp delta 1 out of range",
            "reader accepted a sample timestamp overflow",
        );
    }

    #[test]
    fn writer_rejects_positive_sample_timestamp_delta_out_of_range() {
        let mut writer = writer();
        assert_invalid_input_contains(
            writer.write_sample_frames(i64::MAX as u64 + 1, 7, 11, [frame(1)]),
            "sample timestamp delta 9223372036854775808 out of range",
            "writer accepted a positive sample timestamp delta outside i64",
        );
    }

    #[test]
    fn writer_rejects_negative_sample_timestamp_delta_out_of_range() {
        let mut writer = writer();
        writer.last_timestamp_ns = u64::MAX;

        assert_invalid_input_contains(
            writer.write_sample_frames(0, 7, 11, [frame(2)]),
            "sample timestamp delta -18446744073709551615 out of range",
            "writer accepted a negative sample timestamp delta outside i64",
        );
    }

    #[test]
    fn reader_rejects_out_of_range_module_process_id() {
        let path = temp_spool_path("bad-module-process-id");
        let mut bytes = Vec::new();
        bytes.write_varint(0_u64).unwrap();
        bytes.write_varint(out_of_range_process_id()).unwrap();
        bytes.write_varint(0x1000_u64).unwrap();
        bytes.write_varint(0x2000_u64).unwrap();
        bytes.write_varint(0_u64).unwrap();
        bytes.write_varint(0_u64).unwrap();
        bytes.write_all(&[0]).unwrap();
        bytes.write_varint(4_u64).unwrap();
        bytes.write_all(b"/bad").unwrap();
        std::fs::write(&path, bytes).unwrap();

        let file = File::open(&path).unwrap();
        let mmap = Arc::new(unsafe { Mmap::map(&file).unwrap() });
        let mut reader = MmapSpoolCursor::new(mmap);

        assert_invalid_data_contains(
            read_module_mmap(&mut reader, 0, 3),
            "process id",
            "reader accepted an out-of-range module process id",
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reader_rejects_out_of_range_process_exec_process_id() {
        let mut bytes = Vec::new();
        bytes.write_varint(1_u64).unwrap();
        bytes.write_varint(out_of_range_process_id()).unwrap();
        bytes.write_all(&[1]).unwrap();

        assert_invalid_data_contains(
            read_process_exec(&mut bytes.as_slice()),
            "process id",
            "reader accepted an out-of-range process-exec process id",
        );
    }

    #[test]
    fn reader_rejects_out_of_range_thread_process_id() {
        let mut bytes = Vec::new();
        bytes.write_varint(0_u64).unwrap();
        bytes.write_varint(out_of_range_process_id()).unwrap();
        bytes.write_varint(99_u64).unwrap();

        assert_invalid_data_contains(
            read_thread(&mut bytes.as_slice(), 0),
            "process id",
            "reader accepted an out-of-range thread process id",
        );
    }

    #[test]
    fn reader_rejects_module_frame_before_file_offset() {
        assert_invalid_data_contains(
            module_frame_reader_result(0x80),
            "frame address precedes module 0 file offset",
            "reader accepted a module frame before its file offset",
        );
    }

    #[test]
    fn reader_rejects_module_frame_outside_module_span() {
        assert_invalid_data_contains(
            module_frame_reader_result(0x1100),
            "frame address outside referenced module 0",
            "reader accepted a module frame outside its module span",
        );
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
    fn module_table_keeps_same_path_mappings_with_different_inodes_distinct() {
        let mut table = ModuleTable::default();
        let mut writer = writer();
        let mut first = module(7, 0x1000, 0x2000, "/same", false);
        first.inode = 1;
        let mut second = first.clone();
        second.inode = 2;

        let first_id = table.intern_module(first, &mut writer).unwrap();
        let second_id = table.intern_module(second, &mut writer).unwrap();

        assert_ne!(first_id, second_id);
        assert_eq!(
            table.resolve_frame(7, 0x1008, FrameMode::User).module_id,
            Some(second_id)
        );
    }

    #[test]
    fn module_updates_return_canonical_assigned_records() {
        let mut table = ModuleTable::default();
        let mut writer = writer();
        let first = table
            .apply_module(module(7, 0x1000, 0x2000, "/first", false), &mut writer)
            .unwrap();
        let second_module = module(7, 0x3000, 0x4000, "/second", false);
        let second = table
            .apply_module(second_module.clone(), &mut writer)
            .unwrap();
        let duplicate = table.apply_module(second_module, &mut writer).unwrap();

        assert_eq!(first.active[0].module.id, 0);
        assert_eq!(second.active[0].module.id, 1);
        assert_eq!(duplicate.active[0].module.id, 1);
        assert!(!duplicate.mapping_changed);
    }

    #[test]
    fn module_identity_includes_device_and_inode_generation() {
        let mut table = ModuleTable::default();
        let mut writer = writer();
        let mut first = module(7, 0x1000, 0x2000, "/same", false);
        first.inode = 9;
        first.device_major = 8;
        first.device_minor = 1;
        first.inode_generation = 4;
        let mut second = first.clone();
        second.device_minor = 2;
        second.inode_generation = 5;

        let first = table.apply_module(first, &mut writer).unwrap();
        let second = table.apply_module(second, &mut writer).unwrap();

        assert_eq!(first.active[0].module.id, 0);
        assert_eq!(second.retired[0].id, 0);
        assert_eq!(second.active[0].module.id, 1);
        assert_eq!(second.active[0].module.device_minor, 2);
        assert_eq!(second.active[0].module.inode_generation, 5);
    }

    #[test]
    fn unknown_snapshot_generation_preserves_canonical_identity() {
        let mut table = ModuleTable::default();
        let mut writer = writer();
        let mut mmap2 = module(7, 0x1000, 0x2000, "/same", false);
        mmap2.inode = 9;
        mmap2.device_major = 8;
        mmap2.device_minor = 1;
        mmap2.inode_generation = 4;
        let mut snapshot = mmap2.clone();
        snapshot.inode_generation = 0;

        let first = table.apply_module(mmap2, &mut writer).unwrap();
        let snapshot = table.apply_module(snapshot, &mut writer).unwrap();

        assert_eq!(snapshot.active[0].module.id, first.active[0].module.id);
        assert_eq!(snapshot.active[0].module.inode_generation, 4);
        assert!(!snapshot.mapping_changed);
        assert!(snapshot.retired.is_empty());
    }

    #[test]
    fn process_module_snapshot_matching_is_one_to_one() {
        let mut table = ModuleTable::default();
        let mut writer = writer();
        let mut first = module(7, 0x1000, 0x2000, "/first", false);
        first.inode_generation = 4;
        let second = module(7, 0x3000, 0x4000, "/second", false);
        table.apply_module(first.clone(), &mut writer).unwrap();
        table.apply_module(second.clone(), &mut writer).unwrap();

        first.inode_generation = 0;
        let snapshot = vec![first.clone(), second];
        assert!(table.process_modules_match(7, &snapshot));

        assert!(!table.process_modules_match(7, std::slice::from_ref(&first)));
        assert!(!table.process_modules_match(7, &[first.clone(), first.clone()]));

        let mut changed = snapshot;
        changed[0].end += 1;
        assert!(!table.process_modules_match(7, &changed));
    }

    #[test]
    fn spool_v3_round_trips_full_module_identity() {
        let path = temp_spool_path("module-identity-v3");
        let mut writer = PerfSpoolWriter::create(&path, 0, 0).unwrap();
        let mut module = module(7, 0x1000, 0x2000, "/module", false);
        module.id = 0;
        module.inode = 99;
        module.device_major = 8;
        module.device_minor = 2;
        module.inode_generation = 17;
        writer.write_module(&module).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(reader.modules()[0].device_major, 8);
        assert_eq!(reader.modules()[0].device_minor, 2);
        assert_eq!(reader.modules()[0].inode_generation, 17);
    }

    #[test]
    fn spool_v2_defaults_extended_module_identity() {
        let path = temp_spool_path("module-identity-v2");
        let mut bytes = MAGIC_V2.to_vec();
        bytes.write_varint(0_u64).unwrap();
        bytes.write_varint(0_u64).unwrap();
        bytes.push(REC_MODULE);
        bytes.write_varint(0_u64).unwrap();
        bytes.write_varint(7_i64).unwrap();
        bytes.write_varint(0x1000_u64).unwrap();
        bytes.write_varint(0x2000_u64).unwrap();
        bytes.write_varint(0_u64).unwrap();
        bytes.write_varint(99_u64).unwrap();
        bytes.push(0);
        write_bytes(&mut bytes, b"/module").unwrap();
        std::fs::write(&path, bytes).unwrap();

        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(reader.modules()[0].inode, 99);
        assert_eq!(reader.modules()[0].device_major, 0);
        assert_eq!(reader.modules()[0].device_minor, 0);
        assert_eq!(reader.modules()[0].inode_generation, 0);
    }

    #[test]
    fn module_table_records_exact_address_mapping_generations() {
        let mut table = ModuleTable::default();
        let mut writer = writer();

        let alpha1 = table
            .intern_module(module(7, 0x1000, 0x2000, "/alpha.so", false), &mut writer)
            .unwrap();
        let beta = table
            .intern_module(module(7, 0x1000, 0x2000, "/beta.so", false), &mut writer)
            .unwrap();
        let alpha2 = table
            .intern_module(module(7, 0x1000, 0x2000, "/alpha.so", false), &mut writer)
            .unwrap();

        assert_ne!(alpha1, alpha2);
        assert_ne!(beta, alpha2);
        assert_eq!(
            table.resolve_frame(7, 0x1100, FrameMode::User).module_id,
            Some(alpha2)
        );
    }

    #[test]
    fn targeted_module_deactivation_round_trips_generation_contexts() {
        let path = temp_spool_path("targeted-module-generations");
        let mut spool = PerfSpoolWriter::create(&path, 0, 0).unwrap();
        let mut table = ModuleTable::default();
        let raw = frame(0x1100);

        table
            .intern_module(module(7, 0x1000, 0x2000, "/alpha.so", false), &mut spool)
            .unwrap();
        spool.write_sample_frames(1, 7, 7, [raw]).unwrap();
        table
            .intern_module(module(7, 0x1000, 0x2000, "/beta.so", false), &mut spool)
            .unwrap();
        spool.write_sample_frames(2, 7, 7, [raw]).unwrap();
        table
            .intern_module(module(7, 0x1000, 0x2000, "/alpha.so", false), &mut spool)
            .unwrap();
        spool.write_sample_frames(3, 7, 7, [raw]).unwrap();
        spool.flush().unwrap();
        drop(spool);

        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let paths: Vec<_> = reader
            .samples()
            .iter()
            .map(|sample| {
                reader
                    .stack_frame_contexts(sample.process_id, sample.stack_id)
                    .unwrap()
                    .next()
                    .unwrap()
                    .module
                    .unwrap()
                    .module
                    .path
                    .to_string()
            })
            .collect();
        assert_eq!(paths, ["/alpha.so", "/beta.so", "/alpha.so"]);
    }

    #[test]
    fn module_table_preserves_partial_overlap_fragments_and_offsets() {
        let mut table = ModuleTable::default();
        let mut writer = writer();
        let mut old = module(7, 0x1000, 0x5000, "/old.so", false);
        old.file_offset = 0x8000;
        table.intern_module(old, &mut writer).unwrap();
        let replacement = table
            .intern_module(module(7, 0x2000, 0x3000, "/new.so", false), &mut writer)
            .unwrap();

        let left = table.resolve_frame(7, 0x1800, FrameMode::User);
        let middle = table.resolve_frame(7, 0x2800, FrameMode::User);
        let right = table.resolve_frame(7, 0x3800, FrameMode::User);
        assert_ne!(left.module_id, Some(replacement));
        assert_eq!(middle.module_id, Some(replacement));
        assert_ne!(right.module_id, Some(replacement));
        assert_eq!(left.rel_ip, 0x8800);
        assert_eq!(right.rel_ip, 0xa800);
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

        table.deactivate_process_modules(7, &mut writer).unwrap();
        table
            .intern_module(module(7, 0x1000, 0x3000, "/first", false), &mut writer)
            .unwrap();
        let resolved = table.resolve_frame(7, 0x2000, FrameMode::User);

        assert_ne!(resolved.module_id, Some(first));
        assert!(resolved.module_id.is_some());
    }

    #[test]
    fn module_table_respects_frame_mode_when_resolving_modules() {
        let mut table = ModuleTable::default();
        let mut writer = writer();
        table
            .intern_module(module(7, 0x1000, 0x2000, "/user", false), &mut writer)
            .unwrap();
        table
            .intern_module(module(-1, 0x3000, 0x4000, "[kernel]", true), &mut writer)
            .unwrap();

        let kernel_frame_in_user_module = table.resolve_frame(7, 0x1008, FrameMode::Kernel);
        let user_frame_in_kernel_module = table.resolve_frame(7, 0x3008, FrameMode::User);

        assert_eq!(kernel_frame_in_user_module.module_id, None);
        assert_eq!(kernel_frame_in_user_module.rel_ip, 0x1008);
        assert_eq!(user_frame_in_kernel_module.module_id, None);
        assert_eq!(user_frame_in_kernel_module.rel_ip, 0x3008);
    }
}
