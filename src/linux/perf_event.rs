use std::cmp::max;
use std::fmt;
use std::io;
use std::mem::{align_of, size_of};
use std::os::fd::{AsRawFd, RawFd};
use std::slice;

use perf_event_open::config::{
    CallChain, Clock, Cpu, Inherit, OnExecve, Opts, Proc, RecordIdFormat, RegsMask, SampleOn, Size,
    UseBuildId,
};
use perf_event_open::count::Counter;
use perf_event_open::event::hw::Hardware;
use perf_event_open::event::sw::Software;
use perf_event_open::event::Event as PerfOpenEvent;
use perf_event_open::sample::rb::CowChunk;
use perf_event_open::sample::record::{Priv, Record, RecordId, UnsafeParser};
use perf_event_open::sample::Sampler;
use perf_event_open_sys::bindings as sys;

/// Hard kernel cap on the user-stack snapshot size, in bytes, that
/// `perf_event_open` will copy per sample. Acts as a ceiling for
/// `PerfRecorderOptions::stack_size`; anything larger is rejected.
pub const MAX_SAMPLE_USER_STACK: u32 = 65_528;
/// Size of the perf metadata page that precedes the ring buffer in the mmap.
const META_PAGE: u32 = 4096;

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Error returned when the requested sample rate exceeds the kernel's
/// `perf_event_max_sample_rate`.
///
/// Wraps the rate the caller asked for and the cap currently in effect, so
/// they can adjust the recorder's `frequency` option and retry, or read the
/// cap up front via [`crate::max_sample_rate`].
#[derive(Debug)]
pub struct PerfFrequencyLimit {
    /// Frequency the caller asked for, in Hz.
    pub requested_frequency: u64,
    /// Current `/proc/sys/kernel/perf_event_max_sample_rate` cap.
    pub max_frequency: u64,
}

impl fmt::Display for PerfFrequencyLimit {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            fmt,
            "frequency {} exceeds /proc/sys/kernel/perf_event_max_sample_rate {}",
            self.requested_frequency, self.max_frequency
        )
    }
}

impl std::error::Error for PerfFrequencyLimit {}

#[derive(Copy, Clone, PartialEq, Debug, Default)]
pub enum EventSource {
    HwCpuCycles,
    #[default]
    SwCpuClock,
}

/// `include_kernel = false` is the safe default; everything else zero-defaults.
#[derive(Clone, Debug, Default)]
pub struct PerfOptions {
    pub pid: u32,
    /// `None` => any cpu.
    pub cpu: Option<u32>,
    pub frequency: u64,
    pub stack_size: u32,
    pub reg_mask: u64,
    pub event_source: EventSource,
    pub inherit: TaskInheritance,
    pub enable_on_exec: bool,
    pub include_kernel: bool,
    pub sample_callchain: bool,
    pub exclude_user_callchain: bool,
    pub exclude_kernel_callchain: bool,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum TaskInheritance {
    #[default]
    None,
    Threads,
    Children,
}

impl TaskInheritance {
    #[inline]
    #[must_use]
    pub(crate) fn is_enabled(self) -> bool {
        self != Self::None
    }
}

impl PerfOptions {
    pub fn open(mut self) -> io::Result<Perf> {
        match self.open_once() {
            Ok(perf) => Ok(perf),
            Err(err)
                if self.inherit == TaskInheritance::Threads && is_inherit_thread_error(&err) =>
            {
                self.inherit = TaskInheritance::None;
                self.open_once()
            }
            Err(err) => Err(err),
        }
    }

    fn open_once(&self) -> io::Result<Perf> {
        if let Some(max_rate) = crate::max_sample_rate().filter(|&r| self.frequency > r) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                PerfFrequencyLimit {
                    requested_frequency: self.frequency,
                    max_frequency: max_rate,
                },
            ));
        }
        if self.stack_size > MAX_SAMPLE_USER_STACK {
            return Err(invalid_input(format!(
                "sample_user_stack can be at most {MAX_SAMPLE_USER_STACK} bytes"
            )));
        }
        // See `perf_mmap` in the Linux kernel.
        if self.cpu.is_none() && self.inherit.is_enabled() {
            return Err(invalid_input("inherit and any-cpu are mutually exclusive"));
        }

        let opts = self.perf_open_opts();
        let counter = self.open_counter(&opts)?;
        let sampler = counter.sampler(ring_buffer_page_exp(self.stack_size)?)?;
        let fd = counter.file().as_raw_fd();

        let perf = Perf {
            counter,
            sampler,
            fd,
            inherit: self.inherit,
        };
        Ok(perf)
    }

    fn open_counter(&self, opts: &Opts) -> io::Result<Counter> {
        match self.event_source {
            EventSource::HwCpuCycles => {
                open_counter_for_event(Hardware::CpuCycle, self.pid, self.cpu, opts)
            }
            EventSource::SwCpuClock => {
                open_counter_for_event(Software::CpuClock, self.pid, self.cpu, opts)
            }
        }
    }

    fn perf_open_opts(&self) -> Opts {
        let mut opts = Opts {
            exclude: perf_event_open::config::Priv {
                kernel: !self.include_kernel,
                ..Default::default()
            },
            inherit: match self.inherit {
                TaskInheritance::None => None,
                TaskInheritance::Threads => Some(Inherit::NewThread),
                TaskInheritance::Children => Some(Inherit::NewChild),
            },
            on_execve: self.enable_on_exec.then_some(OnExecve::Enable),
            enable: false,
            sample_on: SampleOn::Freq(self.frequency),
            record_id_format: RecordIdFormat {
                task: true,
                time: true,
                ..RecordIdFormat::default()
            },
            record_id_all: true,
            timer: Some(Clock::Monotonic),
            ..Opts::default()
        };
        opts.sample_format.code_addr = true;
        if self.sample_callchain {
            opts.sample_format.call_chain = Some(CallChain {
                exclude_user: self.exclude_user_callchain,
                exclude_kernel: self.exclude_kernel_callchain,
                defer_user: false,
                max_stack_frames: 0,
            });
        }
        if self.reg_mask != 0 {
            opts.sample_format.user_regs = Some(RegsMask(self.reg_mask));
        }
        if self.stack_size != 0 {
            opts.sample_format.user_stack = Some(Size(self.stack_size));
        }
        opts.extra_record.mmap.code = true;
        opts.extra_record.mmap.data = true;
        opts.extra_record.mmap.ext = Some(UseBuildId(false));
        opts.extra_record.comm = true;
        opts.extra_record.task = true;
        opts
    }
}

fn open_counter_for_event<E>(
    event: E,
    pid: u32,
    cpu: Option<u32>,
    opts: &Opts,
) -> io::Result<Counter>
where
    E: TryInto<PerfOpenEvent, Error = io::Error>,
{
    match cpu {
        Some(cpu) => Counter::new(event, (Proc(pid), Cpu(cpu)), opts),
        None => Counter::new(event, (Proc(pid), Cpu::ALL), opts),
    }
}

fn is_inherit_thread_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::InvalidInput
        || err.kind() == io::ErrorKind::Unsupported
        || matches!(
            err.raw_os_error(),
            Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
        )
}

fn ring_buffer_page_exp(stack_size: u32) -> io::Result<u8> {
    const STACK_COUNT_PER_BUFFER: u32 = 32;
    let required_space = max(stack_size, META_PAGE) * STACK_COUNT_PER_BUFFER;
    let Some(n) = (1..26).find(|n| (1_u32 << n) * META_PAGE >= required_space) else {
        return Err(invalid_input(format!(
            "stack_size {stack_size} too large for the ring buffer"
        )));
    };
    Ok(max(1 << n, 16_u32).trailing_zeros() as u8)
}

pub struct Perf {
    counter: Counter,
    sampler: Sampler,
    fd: RawFd,
    inherit: TaskInheritance,
}

impl Perf {
    pub fn enable(&self) -> io::Result<()> {
        self.counter.enable()
    }

    pub fn disable(&self) -> io::Result<()> {
        self.counter.disable()
    }

    #[inline]
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    #[inline]
    pub fn inherit(&self) -> TaskInheritance {
        self.inherit
    }

    /// Record parser for this counter's ring buffer. Every counter opened
    /// from the same [`PerfOptions`] template shares an identical parser
    /// configuration.
    pub fn parser(&self) -> &UnsafeParser {
        self.sampler.parser()
    }

    pub fn consume_owned_events(&self, cb: &mut impl FnMut(OwnedEventRecord)) {
        let mut iter = self.sampler.iter().into_cow();
        while iter
            .next(|chunk, parser| cb(OwnedEventRecord::new(chunk, parser.as_unsafe())))
            .is_some()
        {}
    }
}

#[doc(hidden)]
pub struct EventRef<'a> {
    privilege: Priv,
    record: EventRecord<'a>,
    timestamp: Option<u64>,
}

#[doc(hidden)]
pub enum EventRecord<'a> {
    Sample(SampleRecordRef<'a>),
    Owned(Record),
}

#[doc(hidden)]
pub enum OwnedEventRecord {
    // Samples keep the raw bytes and are re-read zero-copy at dispatch,
    // using the group-wide parser passed to `dispatch`.
    Sample {
        record: AlignedPerfRecord,
        time: Option<u64>,
    },
    // Everything else is parsed exactly once, at construction.
    Parsed {
        privilege: Priv,
        record: Record,
        time: Option<u64>,
    },
}

impl OwnedEventRecord {
    fn new(chunk: CowChunk<'_>, parser: &UnsafeParser) -> Self {
        Self::from_chunk_bytes(chunk.as_bytes(), parser)
    }

    #[doc(hidden)]
    pub fn from_chunk_bytes(bytes: &[u8], parser: &UnsafeParser) -> Self {
        // Borrowed chunks are u64-aligned in the common case; only records
        // that wrapped the ring-buffer edge arrive unaligned and must be
        // copied before the parser (which requires 8-byte alignment) can
        // read them. Samples always take the aligned copy, since they keep
        // the raw bytes for re-reading at dispatch.
        if is_u64_aligned(bytes) {
            match parse_sample_record(bytes, parser).map(|(_, sample)| sample.time) {
                Some(time) => Self::Sample {
                    record: AlignedPerfRecord::from_bytes(bytes),
                    time,
                },
                None => Self::parse_in_place(bytes, parser),
            }
        } else {
            let record = AlignedPerfRecord::from_bytes(bytes);
            match parse_sample_record(record.as_bytes(), parser).map(|(_, sample)| sample.time) {
                Some(time) => Self::Sample { record, time },
                None => Self::parse_in_place(record.as_bytes(), parser),
            }
        }
    }

    /// Parse a non-sample record directly from u64-aligned bytes.
    fn parse_in_place(bytes: &[u8], parser: &UnsafeParser) -> Self {
        debug_assert!(is_u64_aligned(bytes));
        let (privilege, record, _) = unsafe { parser.parse(bytes) };
        Self::Parsed {
            privilege,
            time: record_timestamp(&record),
            record,
        }
    }

    pub fn timestamp(&self) -> Option<u64> {
        match self {
            Self::Sample { time, .. } | Self::Parsed { time, .. } => *time,
        }
    }

    pub fn dispatch(self, parser: &UnsafeParser, cb: &mut impl FnMut(EventRef<'_>)) {
        match self {
            Self::Sample { record, .. } => {
                dispatch_event_bytes(record.as_bytes(), parser, cb);
            }
            Self::Parsed {
                privilege,
                record,
                time,
            } => cb(EventRef {
                privilege,
                timestamp: time,
                record: EventRecord::Owned(record),
            }),
        }
    }
}

#[derive(Clone, Copy)]
pub struct SampleRecordRef<'a> {
    pub task: Option<TaskRef>,
    pub time: Option<u64>,
    pub code_addr: Option<(u64, bool)>,
    pub user_regs: Option<&'a [u64]>,
    pub user_stack: Option<&'a [u8]>,
    pub call_chain: Option<CallChainRef<'a>>,
}

#[derive(Clone, Copy)]
pub struct TaskRef {
    pub pid: u32,
    pub tid: u32,
}

#[derive(Clone, Copy)]
pub struct CallChainRef<'a> {
    addresses: &'a [u64],
}

impl<'a> CallChainRef<'a> {
    pub fn iter(&self) -> CallChainIter<'a> {
        CallChainIter {
            addresses: self.addresses,
            cursor: 0,
        }
    }
}

pub struct CallChainIter<'a> {
    addresses: &'a [u64],
    cursor: usize,
}

pub enum CallChainEntry<'a> {
    User(&'a [u64]),
    Kernel(&'a [u64]),
    Hv(&'a [u64]),
    Guest(&'a [u64]),
    GuestUser(&'a [u64]),
    GuestKernel(&'a [u64]),
    Unknown(&'a [u64]),
}

impl<'a> Iterator for CallChainIter<'a> {
    type Item = CallChainEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let marker = *self.addresses.get(self.cursor)?;
        self.cursor += 1;
        let start = self.cursor;
        while self
            .addresses
            .get(self.cursor)
            .is_some_and(|&address| !is_callchain_marker(address))
        {
            self.cursor += 1;
        }
        let addresses = &self.addresses[start..self.cursor];
        Some(match marker {
            sys::PERF_CONTEXT_USER => CallChainEntry::User(addresses),
            sys::PERF_CONTEXT_KERNEL => CallChainEntry::Kernel(addresses),
            sys::PERF_CONTEXT_HV => CallChainEntry::Hv(addresses),
            sys::PERF_CONTEXT_GUEST => CallChainEntry::Guest(addresses),
            sys::PERF_CONTEXT_GUEST_USER => CallChainEntry::GuestUser(addresses),
            sys::PERF_CONTEXT_GUEST_KERNEL => CallChainEntry::GuestKernel(addresses),
            _ => CallChainEntry::Unknown(addresses),
        })
    }
}

impl fmt::Debug for EventRef<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("EventRef")
            .field("privilege", &self.privilege)
            .field("timestamp", &self.timestamp)
            .finish_non_exhaustive()
    }
}

impl<'a> EventRef<'a> {
    fn new(privilege: Priv, record: Record) -> Self {
        let timestamp = record_timestamp(&record);
        Self {
            privilege,
            record: EventRecord::Owned(record),
            timestamp,
        }
    }

    pub fn timestamp(&self) -> Option<u64> {
        self.timestamp
    }

    pub fn into_parts(self) -> (Priv, EventRecord<'a>) {
        (self.privilege, self.record)
    }
}

fn record_id_time(record_id: &Option<RecordId>) -> Option<u64> {
    record_id.as_ref()?.time
}

fn record_timestamp(record: &Record) -> Option<u64> {
    match record {
        Record::Sample(sample) => sample.record_id.time,
        Record::Mmap(mmap) => record_id_time(&mmap.record_id),
        Record::Read(read) => record_id_time(&read.record_id),
        Record::Cgroup(cgroup) => record_id_time(&cgroup.record_id),
        Record::Ksymbol(ksymbol) => record_id_time(&ksymbol.record_id),
        Record::TextPoke(text_poke) => record_id_time(&text_poke.record_id),
        Record::BpfEvent(bpf_event) => record_id_time(&bpf_event.record_id),
        Record::CtxSwitch(ctx_switch) => record_id_time(&ctx_switch.record_id),
        Record::Namespaces(namespaces) => record_id_time(&namespaces.record_id),
        Record::ItraceStart(itrace_start) => record_id_time(&itrace_start.record_id),
        Record::CallChainDeferred(call_chain) => record_id_time(&call_chain.record_id),
        Record::Aux(aux) => record_id_time(&aux.record_id),
        Record::AuxOutputHwId(aux) => record_id_time(&aux.record_id),
        Record::Comm(comm) => record_id_time(&comm.record_id),
        Record::Exit(exit) => record_id_time(&exit.record_id).or(Some(exit.time)),
        Record::Fork(fork) => record_id_time(&fork.record_id).or(Some(fork.time)),
        Record::Throttle(throttle) => record_id_time(&throttle.record_id).or(Some(throttle.time)),
        Record::Unthrottle(unthrottle) => {
            record_id_time(&unthrottle.record_id).or(Some(unthrottle.time))
        }
        Record::LostRecords(lost) => record_id_time(&lost.record_id),
        Record::LostSamples(lost) => record_id_time(&lost.record_id),
        Record::Unknown(_) => None,
    }
}

fn dispatch_event_bytes(bytes: &[u8], parser: &UnsafeParser, cb: &mut impl FnMut(EventRef<'_>)) {
    if let Some((privilege, sample)) = parse_sample_record(bytes, parser) {
        cb(EventRef {
            privilege,
            timestamp: sample.time,
            record: EventRecord::Sample(sample),
        });
        return;
    }

    let (privilege, record, _) = unsafe { parser.parse(bytes) };
    cb(EventRef::new(privilege, record));
}

fn parse_sample_record<'a>(
    bytes: &'a [u8],
    parser: &perf_event_open::sample::record::UnsafeParser,
) -> Option<(Priv, SampleRecordRef<'a>)> {
    if !is_u64_aligned(bytes) {
        return None;
    }
    let mut cursor = ByteCursor::new(bytes);
    let misc = read_sample_header(&mut cursor)?;
    let sample_type = parser.sample_type;
    let mut sample = SampleRecordRef {
        task: None,
        time: None,
        code_addr: None,
        user_regs: None,
        user_stack: None,
        call_chain: None,
    };

    parse_common_sample_fields(sample_type, misc, &mut cursor, &mut sample)?;
    skip_sample_fields(sample_type, &mut cursor)?;
    parse_stack_sample_fields(sample_type, parser, &mut cursor, &mut sample)?;

    Some((priv_from_misc(misc), sample))
}

fn read_sample_header(cursor: &mut ByteCursor<'_>) -> Option<u16> {
    let record_type = cursor.read_u32()?;
    let misc = cursor.read_u16()?;
    let _size = cursor.read_u16()?;
    (record_type == sys::PERF_RECORD_SAMPLE).then_some(misc)
}

fn parse_common_sample_fields<'a>(
    sample_type: u64,
    misc: u16,
    cursor: &mut ByteCursor<'a>,
    sample: &mut SampleRecordRef<'a>,
) -> Option<()> {
    if has_sample(sample_type, sys::PERF_SAMPLE_IP) {
        sample.code_addr = Some((
            cursor.read_u64()?,
            u32::from(misc) & sys::PERF_RECORD_MISC_EXACT_IP != 0,
        ));
    }
    if has_sample(sample_type, sys::PERF_SAMPLE_TID) {
        sample.task = Some(TaskRef {
            pid: cursor.read_u32()?,
            tid: cursor.read_u32()?,
        });
    }
    if has_sample(sample_type, sys::PERF_SAMPLE_TIME) {
        sample.time = Some(cursor.read_u64()?);
    }
    Some(())
}

fn skip_sample_fields(sample_type: u64, cursor: &mut ByteCursor<'_>) -> Option<()> {
    if has_sample(sample_type, sys::PERF_SAMPLE_ADDR) {
        cursor.skip(size_of::<u64>())?;
    }
    if has_sample(sample_type, sys::PERF_SAMPLE_ID) {
        cursor.skip(size_of::<u64>())?;
    }
    if has_sample(sample_type, sys::PERF_SAMPLE_STREAM_ID) {
        cursor.skip(size_of::<u64>())?;
    }
    if has_sample(sample_type, sys::PERF_SAMPLE_CPU) {
        cursor.skip(size_of::<u32>() * 2)?;
    }
    if has_sample(sample_type, sys::PERF_SAMPLE_PERIOD) {
        cursor.skip(size_of::<u64>())?;
    }
    if has_sample(sample_type, sys::PERF_SAMPLE_READ) {
        return None;
    }
    Some(())
}

fn parse_stack_sample_fields<'a>(
    sample_type: u64,
    parser: &perf_event_open::sample::record::UnsafeParser,
    cursor: &mut ByteCursor<'a>,
    sample: &mut SampleRecordRef<'a>,
) -> Option<()> {
    if has_sample(sample_type, sys::PERF_SAMPLE_CALLCHAIN) {
        let len = usize::try_from(cursor.read_u64()?).ok()?;
        sample.call_chain = Some(CallChainRef {
            addresses: cursor.read_u64_slice(len)?,
        });
    }
    if has_sample(sample_type, sys::PERF_SAMPLE_RAW) {
        let len = cursor.read_u32()? as usize;
        cursor.skip(len)?;
        cursor.align_to_u64()?;
    }
    if has_sample(sample_type, sys::PERF_SAMPLE_BRANCH_STACK) {
        return None;
    }
    parse_user_regs_sample(sample_type, parser, cursor, sample)?;
    parse_user_stack_sample(sample_type, cursor, sample)
}

fn parse_user_regs_sample<'a>(
    sample_type: u64,
    parser: &perf_event_open::sample::record::UnsafeParser,
    cursor: &mut ByteCursor<'a>,
    sample: &mut SampleRecordRef<'a>,
) -> Option<()> {
    if has_sample(sample_type, sys::PERF_SAMPLE_REGS_USER) {
        let abi = cursor.read_u64()? as u32;
        if abi != sys::PERF_SAMPLE_REGS_ABI_NONE {
            let abi = match abi {
                sys::PERF_SAMPLE_REGS_ABI_32 | sys::PERF_SAMPLE_REGS_ABI_64 => abi,
                _ => return None,
            };
            let regs = cursor.read_u64_slice(parser.user_regs)?;
            debug_assert!(
                abi == sys::PERF_SAMPLE_REGS_ABI_32 || abi == sys::PERF_SAMPLE_REGS_ABI_64
            );
            sample.user_regs = Some(regs);
        }
    }
    Some(())
}

fn parse_user_stack_sample<'a>(
    sample_type: u64,
    cursor: &mut ByteCursor<'a>,
    sample: &mut SampleRecordRef<'a>,
) -> Option<()> {
    if has_sample(sample_type, sys::PERF_SAMPLE_STACK_USER) {
        let len = usize::try_from(cursor.read_u64()?).ok()?;
        let bytes = cursor.read_bytes(len)?;
        let dyn_len = if len == 0 {
            0
        } else {
            usize::try_from(cursor.read_u64()?).ok()?
        };
        if dyn_len > len {
            return None;
        }
        sample.user_stack = Some(&bytes[..dyn_len]);
    }
    Some(())
}

fn has_sample(sample_type: u64, flag: sys::perf_event_sample_format) -> bool {
    sample_type & u64::from(flag) != 0
}

fn priv_from_misc(misc: u16) -> Priv {
    match u32::from(misc) & sys::PERF_RECORD_MISC_CPUMODE_MASK {
        sys::PERF_RECORD_MISC_USER => Priv::User,
        sys::PERF_RECORD_MISC_KERNEL => Priv::Kernel,
        sys::PERF_RECORD_MISC_HYPERVISOR => Priv::Hv,
        sys::PERF_RECORD_MISC_GUEST_USER => Priv::GuestUser,
        sys::PERF_RECORD_MISC_GUEST_KERNEL => Priv::GuestKernel,
        _ => Priv::Unknown,
    }
}

fn is_u64_aligned(bytes: &[u8]) -> bool {
    (bytes.as_ptr() as usize).is_multiple_of(align_of::<u64>())
}

fn is_callchain_marker(address: u64) -> bool {
    address.wrapping_add(4095) < 4095
}

pub(crate) struct BenchSampleBatch {
    parser: perf_event_open::sample::record::UnsafeParser,
    records: Vec<AlignedPerfRecord>,
    event_bytes: usize,
    frames_per_sample: usize,
}

pub(crate) struct BenchSampleBatchSpec {
    pub samples: usize,
    pub user_frames: usize,
    pub kernel_frames: usize,
    pub user_regs: usize,
    pub user_stack_bytes: usize,
    pub process_id: u32,
    pub thread_count: u32,
    pub user_base: u64,
    pub kernel_base: u64,
}

impl BenchSampleBatch {
    pub(crate) fn new(spec: BenchSampleBatchSpec) -> Self {
        let sample_type = u64::from(sys::PERF_SAMPLE_IP)
            | u64::from(sys::PERF_SAMPLE_TID)
            | u64::from(sys::PERF_SAMPLE_TIME)
            | u64::from(sys::PERF_SAMPLE_CALLCHAIN)
            | u64::from(sys::PERF_SAMPLE_REGS_USER)
            | u64::from(sys::PERF_SAMPLE_STACK_USER);
        let parser = perf_event_open::sample::record::UnsafeParser {
            sample_id_all: false,
            sample_type,
            read_format: 0,
            user_regs: spec.user_regs,
            intr_regs: 0,
            branch_sample_type: 0,
        };

        let mut records = Vec::with_capacity(spec.samples);
        let mut event_bytes = 0;
        for sample_idx in 0..spec.samples {
            let record = build_bench_sample_record(&spec, sample_idx);
            event_bytes += record.len();
            records.push(record);
        }

        Self {
            parser,
            records,
            event_bytes,
            frames_per_sample: spec.user_frames + spec.kernel_frames,
        }
    }

    pub(crate) fn records(&self) -> &[AlignedPerfRecord] {
        &self.records
    }

    pub(crate) fn event_bytes(&self) -> usize {
        self.event_bytes
    }

    pub(crate) fn sample_count(&self) -> usize {
        self.records.len()
    }

    pub(crate) fn frame_count(&self) -> usize {
        self.records.len() * self.frames_per_sample
    }

    pub(crate) fn parse<'a>(
        &self,
        record: &'a AlignedPerfRecord,
    ) -> Option<(Priv, SampleRecordRef<'a>)> {
        parse_sample_record(record.as_bytes(), &self.parser)
    }
}

pub(crate) fn bench_parse_sample_records(batch: &BenchSampleBatch, rounds: u64) -> usize {
    let mut checksum = 0usize;
    for _ in 0..rounds {
        for record in batch.records() {
            let (privilege, sample) = batch.parse(record).expect("parse synthetic perf sample");
            checksum = checksum.wrapping_add(privilege_score(privilege));
            if let Some(task) = sample.task {
                checksum = checksum
                    .wrapping_add(task.pid as usize)
                    .wrapping_add(task.tid as usize);
            }
            if let Some((ip, exact)) = sample.code_addr {
                checksum = checksum.wrapping_add(ip as usize ^ usize::from(exact));
            }
            if let Some(time) = sample.time {
                checksum = checksum.wrapping_add(time as usize);
            }
            if let Some(regs) = sample.user_regs {
                for reg in regs {
                    checksum = checksum.rotate_left(5) ^ *reg as usize;
                }
            }
            if let Some(stack) = sample.user_stack {
                checksum = checksum
                    .wrapping_add(stack.len())
                    .wrapping_add(stack.first().copied().unwrap_or_default() as usize)
                    .wrapping_add(stack.last().copied().unwrap_or_default() as usize);
            }
            if let Some(call_chain) = sample.call_chain {
                for entry in call_chain.iter() {
                    let (tag, addresses) = match entry {
                        CallChainEntry::User(addresses) => (1usize, addresses),
                        CallChainEntry::Kernel(addresses) => (2usize, addresses),
                        CallChainEntry::Hv(addresses) => (3usize, addresses),
                        CallChainEntry::Guest(addresses) => (4usize, addresses),
                        CallChainEntry::GuestUser(addresses) => (5usize, addresses),
                        CallChainEntry::GuestKernel(addresses) => (6usize, addresses),
                        CallChainEntry::Unknown(addresses) => (7usize, addresses),
                    };
                    checksum = checksum.wrapping_add(tag).wrapping_add(addresses.len());
                    for address in addresses {
                        checksum = checksum.rotate_left(7) ^ *address as usize;
                    }
                }
            }
        }
    }
    checksum
}

#[doc(hidden)]
pub struct AlignedPerfRecord {
    words: Vec<u64>,
    len: usize,
}

impl AlignedPerfRecord {
    #[doc(hidden)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut words = vec![0_u64; bytes.len().div_ceil(size_of::<u64>())];
        // The parser intentionally consumes u64-aligned perf record bytes.
        let aligned_bytes =
            unsafe { slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), words.len() * 8) };
        aligned_bytes[..bytes.len()].copy_from_slice(bytes);
        Self {
            words,
            len: bytes.len(),
        }
    }

    #[doc(hidden)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.len) }
    }

    fn len(&self) -> usize {
        self.len
    }
}

fn build_bench_sample_record(spec: &BenchSampleBatchSpec, sample_idx: usize) -> AlignedPerfRecord {
    let mut bytes = Vec::with_capacity(
        64 + (spec.user_frames + spec.kernel_frames) * size_of::<u64>()
            + spec.user_regs * size_of::<u64>()
            + spec.user_stack_bytes,
    );
    push_u32(&mut bytes, sys::PERF_RECORD_SAMPLE);
    push_u16(
        &mut bytes,
        (sys::PERF_RECORD_MISC_USER | sys::PERF_RECORD_MISC_EXACT_IP) as u16,
    );
    push_u16(&mut bytes, 0);

    let sample_variant = sample_idx as u64;
    let user_ip = spec.user_base + (sample_variant % 512) * 0x40 + 0x11;
    push_u64(&mut bytes, user_ip);
    push_u32(&mut bytes, spec.process_id);
    push_u32(
        &mut bytes,
        spec.process_id + (sample_idx as u32 % spec.thread_count.max(1)),
    );
    push_u64(&mut bytes, 1_700_000_000_000_000 + sample_variant * 1_000);

    push_u64(
        &mut bytes,
        (2 + spec.kernel_frames + spec.user_frames) as u64,
    );
    push_u64(&mut bytes, sys::PERF_CONTEXT_KERNEL);
    for frame_idx in 0..spec.kernel_frames {
        push_u64(
            &mut bytes,
            spec.kernel_base + ((sample_variant + frame_idx as u64 * 13) % 4096) * 0x20,
        );
    }
    push_u64(&mut bytes, sys::PERF_CONTEXT_USER);
    for frame_idx in 0..spec.user_frames {
        push_u64(
            &mut bytes,
            spec.user_base + ((sample_variant + frame_idx as u64 * 17) % 4096) * 0x20,
        );
    }

    push_u64(&mut bytes, u64::from(sys::PERF_SAMPLE_REGS_ABI_64));
    for reg_idx in 0..spec.user_regs {
        push_u64(
            &mut bytes,
            spec.user_base + 0x8000 + sample_variant * 8 + reg_idx as u64 * 0x10,
        );
    }

    push_u64(&mut bytes, spec.user_stack_bytes as u64);
    let stack_start = bytes.len();
    bytes.resize(stack_start + spec.user_stack_bytes, 0);
    for (offset, byte) in bytes[stack_start..].iter_mut().enumerate() {
        *byte = sample_idx.wrapping_add(offset) as u8;
    }
    push_u64(&mut bytes, spec.user_stack_bytes as u64);

    let padded_len = bytes.len().next_multiple_of(size_of::<u64>());
    bytes.resize(padded_len, 0);
    let size = u16::try_from(bytes.len()).expect("synthetic perf sample fits in u16");
    bytes[6..8].copy_from_slice(&size.to_ne_bytes());
    AlignedPerfRecord::from_bytes(&bytes)
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_ne_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_ne_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_ne_bytes());
}

fn privilege_score(privilege: Priv) -> usize {
    match privilege {
        Priv::User => 1,
        Priv::Kernel => 2,
        Priv::Hv => 3,
        Priv::GuestUser => 4,
        Priv::GuestKernel => 5,
        Priv::Unknown => 6,
    }
}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u16(&mut self) -> Option<u16> {
        self.read_array().map(u16::from_ne_bytes)
    }

    fn read_u32(&mut self) -> Option<u32> {
        self.read_array().map(u32::from_ne_bytes)
    }

    fn read_u64(&mut self) -> Option<u64> {
        self.read_array().map(u64::from_ne_bytes)
    }

    fn read_u64_slice(&mut self, len: usize) -> Option<&'a [u64]> {
        let byte_len = len.checked_mul(size_of::<u64>())?;
        let bytes = self.read_bytes(byte_len)?;
        if !is_u64_aligned(bytes) {
            return None;
        }
        Some(unsafe { slice::from_raw_parts(bytes.as_ptr().cast::<u64>(), len) })
    }

    fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(len)?;
        let bytes = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(bytes)
    }

    fn skip(&mut self, len: usize) -> Option<()> {
        self.read_bytes(len).map(drop)
    }

    fn align_to_u64(&mut self) -> Option<()> {
        let aligned = self.offset.checked_add(align_of::<u64>() - 1)? & !(align_of::<u64>() - 1);
        if aligned > self.bytes.len() {
            return None;
        }
        self.offset = aligned;
        Some(())
    }

    fn read_array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.read_bytes(N)?.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stack_sample_spec(user_stack_bytes: usize) -> BenchSampleBatchSpec {
        BenchSampleBatchSpec {
            samples: 1,
            user_frames: 1,
            kernel_frames: 1,
            user_regs: 3,
            user_stack_bytes,
            process_id: 1234,
            thread_count: 1,
            user_base: 0x1000,
            kernel_base: 0xffff_0000,
        }
    }

    fn stack_sample_parser(user_regs: usize) -> UnsafeParser {
        UnsafeParser {
            sample_id_all: false,
            sample_type: u64::from(sys::PERF_SAMPLE_IP)
                | u64::from(sys::PERF_SAMPLE_TID)
                | u64::from(sys::PERF_SAMPLE_TIME)
                | u64::from(sys::PERF_SAMPLE_CALLCHAIN)
                | u64::from(sys::PERF_SAMPLE_REGS_USER)
                | u64::from(sys::PERF_SAMPLE_STACK_USER),
            read_format: 0,
            user_regs,
            intr_regs: 0,
            branch_sample_type: 0,
        }
    }

    fn set_dynamic_stack_size(record: &mut AlignedPerfRecord, dyn_len: u64) {
        let len = record.len();
        let bytes = unsafe {
            slice::from_raw_parts_mut(
                record.words.as_mut_ptr().cast::<u8>(),
                record.words.len() * size_of::<u64>(),
            )
        };
        bytes[len - size_of::<u64>()..len].copy_from_slice(&dyn_len.to_ne_bytes());
    }

    #[test]
    fn ring_buffer_exp_keeps_space_for_queued_stack_samples() {
        assert_eq!(ring_buffer_page_exp(0).expect("page exp"), 5);
    }

    #[test]
    fn sample_parser_clips_user_stack_to_dynamic_size() {
        let spec = stack_sample_spec(64);
        let parser = stack_sample_parser(spec.user_regs);
        let mut record = build_bench_sample_record(&spec, 0);
        set_dynamic_stack_size(&mut record, 8);

        let (_, sample) =
            parse_sample_record(record.as_bytes(), &parser).expect("sample should parse");
        let stack = sample.user_stack.expect("user stack");

        assert_eq!(stack.len(), 8);
        assert_eq!(stack[0], 0);
        assert_eq!(stack[7], 7);
    }

    #[test]
    fn sample_parser_exposes_empty_stack_when_dynamic_size_is_zero() {
        let spec = stack_sample_spec(64);
        let parser = stack_sample_parser(spec.user_regs);
        let mut record = build_bench_sample_record(&spec, 0);
        set_dynamic_stack_size(&mut record, 0);

        let (_, sample) =
            parse_sample_record(record.as_bytes(), &parser).expect("sample should parse");
        let stack = sample.user_stack.expect("user stack");

        assert!(stack.is_empty());
    }

    #[test]
    fn sample_parser_extracts_timestamp_from_custom_sample_path() {
        let spec = stack_sample_spec(32);
        let parser = stack_sample_parser(spec.user_regs);
        let record = build_bench_sample_record(&spec, 7);

        let (_, sample) =
            parse_sample_record(record.as_bytes(), &parser).expect("sample should parse");
        assert_eq!(sample.time, Some(1_700_000_000_000_000 + 7_000));
    }

    #[test]
    fn sample_parser_rejects_invalid_dynamic_stack_size() {
        let spec = stack_sample_spec(16);
        let parser = stack_sample_parser(spec.user_regs);
        let mut record = build_bench_sample_record(&spec, 0);
        set_dynamic_stack_size(&mut record, 17);

        assert!(parse_sample_record(record.as_bytes(), &parser).is_none());
    }

    /// Copy `bytes` to an address that is deliberately not u64-aligned, to
    /// force `from_chunk_bytes` down the aligned-copy path.
    fn with_unaligned_copy<R>(bytes: &[u8], f: impl FnOnce(&[u8]) -> R) -> R {
        let mut storage = vec![0_u64; bytes.len() / size_of::<u64>() + 1];
        let raw = unsafe {
            slice::from_raw_parts_mut(
                storage.as_mut_ptr().cast::<u8>(),
                storage.len() * size_of::<u64>(),
            )
        };
        raw[1..1 + bytes.len()].copy_from_slice(bytes);
        let unaligned = &raw[1..1 + bytes.len()];
        assert!(!is_u64_aligned(unaligned));
        f(unaligned)
    }

    #[test]
    fn from_chunk_bytes_is_alignment_invariant() {
        const PID: u32 = 4_242;
        const TID: u32 = 4_251;
        const TIME: u64 = 1_700_000_000_777_000;

        let parser = UnsafeParser {
            sample_id_all: true,
            sample_type: u64::from(sys::PERF_SAMPLE_TID) | u64::from(sys::PERF_SAMPLE_TIME),
            read_format: 0,
            user_regs: 0,
            intr_regs: 0,
            branch_sample_type: 0,
        };

        // Minimal FORK record: header, task payload, and the sample_id
        // trailer (tid, then time) implied by `sample_id_all`.
        let mut bytes = Vec::new();
        push_u32(&mut bytes, sys::PERF_RECORD_FORK);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0); // size, patched below
        push_u32(&mut bytes, PID); // pid
        push_u32(&mut bytes, PID); // ppid
        push_u32(&mut bytes, TID); // tid
        push_u32(&mut bytes, TID); // ptid
        push_u64(&mut bytes, TIME);
        push_u32(&mut bytes, PID);
        push_u32(&mut bytes, TID);
        push_u64(&mut bytes, TIME);
        let size = u16::try_from(bytes.len()).expect("record fits in u16");
        bytes[6..8].copy_from_slice(&size.to_ne_bytes());

        let aligned = AlignedPerfRecord::from_bytes(&bytes);
        assert!(is_u64_aligned(aligned.as_bytes()));
        let in_place = OwnedEventRecord::from_chunk_bytes(aligned.as_bytes(), &parser);
        let copied = with_unaligned_copy(&bytes, |bytes| {
            OwnedEventRecord::from_chunk_bytes(bytes, &parser)
        });

        for record in [in_place, copied] {
            match &record {
                OwnedEventRecord::Parsed {
                    record: Record::Fork(fork),
                    time,
                    ..
                } => {
                    assert_eq!(*time, Some(TIME));
                    assert_eq!((fork.task.pid, fork.task.tid), (PID, TID));
                }
                _ => panic!("fork record should be parsed once, at construction"),
            }
            assert_eq!(record.timestamp(), Some(TIME));

            let mut dispatched = Vec::new();
            record.dispatch(&parser, &mut |event| dispatched.push(event.timestamp()));
            assert_eq!(dispatched, [Some(TIME)]);
        }

        // Samples classify as `Sample` on both paths and carry the same
        // timestamp through dispatch.
        let spec = stack_sample_spec(32);
        let sample_parser = stack_sample_parser(spec.user_regs);
        let sample = build_bench_sample_record(&spec, 7);
        let expected_time = Some(1_700_000_000_000_000 + 7_000);

        let in_place = OwnedEventRecord::from_chunk_bytes(sample.as_bytes(), &sample_parser);
        let copied = with_unaligned_copy(sample.as_bytes(), |bytes| {
            OwnedEventRecord::from_chunk_bytes(bytes, &sample_parser)
        });
        for record in [in_place, copied] {
            assert!(matches!(record, OwnedEventRecord::Sample { .. }));
            assert_eq!(record.timestamp(), expected_time);

            let mut seen = None;
            record.dispatch(&sample_parser, &mut |event| {
                let time = event.timestamp();
                let (_, event_record) = event.into_parts();
                assert!(matches!(event_record, EventRecord::Sample(_)));
                seen = Some(time);
            });
            assert_eq!(seen, Some(expected_time));
        }
    }
}
