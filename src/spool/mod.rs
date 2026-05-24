use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;

use integer_encoding::{VarIntReader, VarIntWriter};
use rustc_hash::FxHashMap;

const MAGIC: &[u8; 8] = b"CHPERF2\0";
const REC_MODULE: u8 = 1;
const REC_FRAME: u8 = 2;
const REC_STACK: u8 = 3;
const REC_THREAD: u8 = 4;
const REC_SAMPLE: u8 = 5;
const REC_PROCESS_EXEC: u8 = 6;
const NONE_U32: u32 = u32::MAX;

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
    pub path: String,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
}

pub struct PerfSpoolWriter<W: Write> {
    writer: W,
    last_timestamp_ns: u64,
    frame_cache: FxHashMap<FrameRecord, u32>,
    stack_cache: FxHashMap<(u32, u32), u32>,
    thread_cache: FxHashMap<(i32, u64), u32>,
    last_stack_frames: Vec<FrameRecord>,
    last_stack_id: Option<u32>,
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
            last_stack_frames: Vec::new(),
            last_stack_id: None,
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
        let thread_id = self.intern_thread(sample.process_id, sample.thread_id)?;
        let stack_id = self.intern_stack_cached(sample.frames)?;
        let delta = sample.timestamp_ns as i64 - self.last_timestamp_ns as i64;
        self.last_timestamp_ns = sample.timestamp_ns;

        self.writer.write_all(&[REC_SAMPLE])?;
        self.writer.write_varint(delta)?;
        self.writer.write_varint(u64::from(thread_id))?;
        self.writer.write_varint(u64::from(stack_id)).map(drop)
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

    fn intern_stack_cached(&mut self, frames: &[FrameRecord]) -> io::Result<u32> {
        if let Some(stack_id) = self.last_stack_id {
            if self.last_stack_frames.as_slice() == frames {
                return Ok(stack_id);
            }
        }

        let stack_id = self.intern_stack(frames)?;
        self.last_stack_frames.clear();
        self.last_stack_frames.extend_from_slice(frames);
        self.last_stack_id = Some(stack_id);
        Ok(stack_id)
    }

    fn intern_frame(&mut self, frame: &FrameRecord) -> io::Result<u32> {
        if let Some(&id) = self.frame_cache.get(frame) {
            return Ok(id);
        }
        let id = self.frame_cache.len() as u32;
        self.writer.write_all(&[REC_FRAME])?;
        self.writer.write_varint(u64::from(id))?;
        write_compact_frame(&mut self.writer, frame)?;
        self.frame_cache.insert(frame.clone(), id);
        Ok(id)
    }

    fn intern_stack(&mut self, frames: &[FrameRecord]) -> io::Result<u32> {
        let mut prefix = NONE_U32;
        for frame in frames.iter().rev() {
            let frame_id = self.intern_frame(frame)?;
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
        Ok(prefix)
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

impl PerfSpoolReader {
    /// Open and read a profile file.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut reader = BufReader::new(File::open(path)?);
        let mut magic = [0_u8; 8];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(invalid_data("invalid stackpulse spool magic"));
        }
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
        let mut tag = [0_u8; 1];
        loop {
            match reader.read_exact(&mut tag) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(err),
            }
            match tag[0] {
                REC_MODULE => modules.push(read_module(&mut reader)?),
                REC_FRAME => frames.push(read_frame(&mut reader, &modules, frames.len())?),
                REC_STACK => stack_nodes.push(read_stack_node(
                    &mut reader,
                    stack_nodes.len(),
                    frames.len(),
                )?),
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

    /// Expand `stack_id` into raw frames.
    ///
    /// `out` is cleared before the frames are written.
    pub fn stack_frames(&self, stack_id: u32, out: &mut Vec<FrameRecord>) -> io::Result<()> {
        out.clear();
        let mut current = Some(stack_id);
        while let Some(id) = current {
            let node = self.stack_nodes.get(id as usize).ok_or_else(|| {
                invalid_data(format!("sample references missing stack node {id}"))
            })?;
            let frame = self.frames.get(node.frame_id as usize).ok_or_else(|| {
                invalid_data(format!(
                    "stack node references missing frame {}",
                    node.frame_id
                ))
            })?;
            out.push(frame.clone());
            current = node.prefix;
        }
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

#[derive(Default)]
pub struct ModuleTable {
    modules: Vec<ModuleRecord>,
    active: Vec<bool>,
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
        Ok(id)
    }

    pub fn deactivate_process_modules(&mut self, process_id: i32) {
        for (module, active) in self.modules.iter().zip(self.active.iter_mut()) {
            if module.process_id == process_id && !module.is_kernel {
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

    pub fn resolve_frame(&self, process_id: i32, abs_ip: u64, mode: FrameMode) -> FrameRecord {
        let module = self
            .modules
            .iter()
            .zip(&self.active)
            .rev()
            .find(|(m, &active)| {
                active
                    && (m.process_id == process_id || m.is_kernel)
                    && m.start <= abs_ip
                    && abs_ip < m.end
            })
            .map(|(m, _)| m);
        let (module_id, rel_ip) = match module {
            Some(m) => (Some(m.id), abs_ip.saturating_sub(m.start) + m.file_offset),
            None => (None, abs_ip),
        };
        FrameRecord {
            module_id,
            rel_ip,
            abs_ip,
            mode,
        }
    }
}

fn read_module(reader: &mut impl Read) -> io::Result<ModuleRecord> {
    let id = reader.read_varint::<u64>()? as u32;
    let process_id = reader.read_varint::<i64>()? as i32;
    let start = reader.read_varint::<u64>()?;
    let end = reader.read_varint::<u64>()?;
    let file_offset = reader.read_varint::<u64>()?;
    let inode = reader.read_varint::<u64>()?;
    let mut flag = [0_u8; 1];
    reader.read_exact(&mut flag)?;
    let path = String::from_utf8(read_bytes(reader)?)
        .map_err(|e| invalid_data(e.utf8_error().to_string()))?;
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
    expected_id: usize,
    frame_count: usize,
) -> io::Result<StackNodeRecord> {
    check_id(reader, expected_id, "stack")?;
    let raw_prefix = reader.read_varint::<u64>()?;
    let prefix = (raw_prefix != u64::from(NONE_U32))
        .then(|| bounded_id(raw_prefix, expected_id, "stack prefix"))
        .transpose()?;
    let frame_id = read_id_within(reader, frame_count, "stack frame")?;
    Ok(StackNodeRecord { prefix, frame_id })
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

fn read_bytes(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let len = reader.read_varint::<u64>()? as usize;
    let mut bytes = vec![0_u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
