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
use perf_event_open::sample::iter::CowIter;
use perf_event_open::sample::rb::CowChunk;
use perf_event_open::sample::record::{Parser, Priv, Record, RecordId, UnsafeParser};
use perf_event_open::sample::Sampler;
use perf_event_open_sys::bindings as sys;

/// Hard kernel cap on the user-stack snapshot size, in bytes, that
/// `perf_event_open` will copy per sample. Acts as a ceiling for
/// `PerfRecorderOptions::stack_size`; anything larger is rejected.
pub const MAX_SAMPLE_USER_STACK: u32 = 65_528;

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
    pub cpu: u32,
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
        self.align_stack_size()?;
        let (counter, inherit, include_kernel) = self.open_counter()?;

        Ok(Perf::new(
            counter,
            self.pid,
            self.cpu,
            inherit,
            include_kernel,
        ))
    }

    pub fn open_ring(mut self) -> io::Result<OutputRing> {
        self.align_stack_size()?;
        let (counter, inherit, include_kernel) = self.open_counter()?;
        let sampler = counter.sampler(ring_buffer_page_exp(self.stack_size)?)?;
        Ok(OutputRing {
            perf: Perf::new(counter, self.pid, self.cpu, inherit, include_kernel),
            sampler,
        })
    }

    fn align_stack_size(&mut self) -> io::Result<()> {
        const ALIGNMENT: u32 = size_of::<u64>() as u32;
        if self.stack_size > MAX_SAMPLE_USER_STACK {
            return Err(invalid_input(format!(
                "sample_user_stack can be at most {MAX_SAMPLE_USER_STACK} bytes"
            )));
        }
        self.stack_size = self
            .stack_size
            .checked_add(ALIGNMENT - 1)
            .map(|size| size & !(ALIGNMENT - 1))
            .ok_or_else(|| invalid_input("sample_user_stack size overflow"))?;
        Ok(())
    }

    fn open_counter(&self) -> io::Result<(Counter, TaskInheritance, bool)> {
        self.validate()?;
        let opts = self.perf_open_opts();
        match self.open_counter_once(&opts) {
            Ok((counter, include_kernel)) => Ok((counter, self.inherit, include_kernel)),
            Err(err)
                if self.inherit == TaskInheritance::Threads && is_inherit_thread_error(&err) =>
            {
                let mut no_inherit_opts = opts.clone();
                no_inherit_opts.inherit = None;
                self.open_counter_once(&no_inherit_opts)
                    .map(|(counter, include_kernel)| {
                        (counter, TaskInheritance::None, include_kernel)
                    })
            }
            Err(err) => Err(err),
        }
    }

    fn validate(&self) -> io::Result<()> {
        if let Some(max_rate) = crate::max_sample_rate().filter(|&r| self.frequency > r) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                PerfFrequencyLimit {
                    requested_frequency: self.frequency,
                    max_frequency: max_rate,
                },
            ));
        }
        ring_buffer_page_exp(self.stack_size).map(drop)
    }

    fn open_counter_once(&self, opts: &Opts) -> io::Result<(Counter, bool)> {
        with_guest_exclusion_fallback(opts, |opts| {
            with_kernel_exclusion_fallback(
                self.include_kernel,
                || self.open_event_counter(opts),
                || {
                    let mut user_opts = opts.clone();
                    user_opts.exclude.kernel = true;
                    self.open_event_counter(&user_opts)
                },
            )
        })
    }

    fn open_event_counter(&self, opts: &Opts) -> io::Result<Counter> {
        match self.event_source {
            EventSource::HwCpuCycles => with_software_event_fallback(
                || open_counter_for_event(Hardware::CpuCycle, self.pid, self.cpu, opts),
                || open_counter_for_event(Software::CpuClock, self.pid, self.cpu, opts),
            ),
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
        opts.extra_record.mmap.ext = Some(UseBuildId(false));
        opts.extra_record.comm = true;
        opts.extra_record.task = true;
        opts.stat_format.lost_records = true;
        opts
    }
}

pub struct OutputRing {
    perf: Perf,
    sampler: Sampler,
}

impl OutputRing {
    pub fn enable(&self) -> io::Result<()> {
        self.perf.enable()
    }

    pub fn disable(&self) -> io::Result<()> {
        self.perf.disable()
    }

    #[inline]
    pub fn fd(&self) -> RawFd {
        self.perf.fd()
    }

    #[inline]
    pub fn cpu(&self) -> u32 {
        self.perf.cpu
    }

    #[inline]
    pub fn inherit(&self) -> TaskInheritance {
        self.perf.inherit()
    }

    #[inline]
    pub fn includes_kernel(&self) -> bool {
        self.perf.includes_kernel()
    }

    pub fn event_drain(&self) -> EventDrain<'_> {
        EventDrain {
            iter: self.sampler.iter().into_cow(),
        }
    }

    pub fn lost_records(&self) -> io::Result<u64> {
        self.perf.lost_records()
    }
}

fn sample_type_bits(
    include_callchain: bool,
    include_user_regs: bool,
    include_user_stack: bool,
) -> u64 {
    let mut sample_type = u64::from(sys::PERF_SAMPLE_IP)
        | u64::from(sys::PERF_SAMPLE_TID)
        | u64::from(sys::PERF_SAMPLE_TIME);
    if include_callchain {
        sample_type |= u64::from(sys::PERF_SAMPLE_CALLCHAIN);
    }
    if include_user_regs {
        sample_type |= u64::from(sys::PERF_SAMPLE_REGS_USER);
    }
    if include_user_stack {
        sample_type |= u64::from(sys::PERF_SAMPLE_STACK_USER);
    }
    sample_type
}

fn open_counter_for_event<E>(event: E, pid: u32, cpu: u32, opts: &Opts) -> io::Result<Counter>
where
    E: Clone + TryInto<PerfOpenEvent, Error = io::Error>,
{
    let open = || Counter::new(event.clone(), (Proc(pid), Cpu(cpu)), opts);
    match open() {
        Err(err) if err.raw_os_error() == Some(libc::EMFILE) && raise_nofile_soft_limit() => open(),
        result => result,
    }
}

fn raise_nofile_soft_limit() -> bool {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } < 0
        || limit.rlim_cur >= limit.rlim_max
    {
        return false;
    }
    limit.rlim_cur = limit.rlim_max;
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) == 0 }
}

fn is_inherit_thread_error(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
    )
}

fn with_software_event_fallback<T>(
    hardware: impl FnOnce() -> io::Result<T>,
    software: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    match hardware() {
        Err(err)
            if matches!(
                err.raw_os_error(),
                Some(libc::ENOENT | libc::ENODEV | libc::ENXIO)
            ) =>
        {
            software()
        }
        result => result,
    }
}

fn with_kernel_exclusion_fallback<T>(
    include_kernel: bool,
    preferred: impl FnOnce() -> io::Result<T>,
    user_only: impl FnOnce() -> io::Result<T>,
) -> io::Result<(T, bool)> {
    match preferred() {
        Err(err)
            if include_kernel && matches!(err.raw_os_error(), Some(libc::EACCES | libc::EPERM)) =>
        {
            user_only().map(|value| (value, false))
        }
        result => result.map(|value| (value, include_kernel)),
    }
}

fn with_guest_exclusion_fallback<T>(
    opts: &Opts,
    mut open: impl FnMut(&Opts) -> io::Result<T>,
) -> io::Result<T> {
    match open(opts) {
        Err(err) if !opts.exclude.guest && err.raw_os_error() == Some(libc::EOPNOTSUPP) => {
            let mut host_only = opts.clone();
            host_only.exclude.guest = true;
            open(&host_only)
        }
        result => result,
    }
}

fn ring_buffer_page_exp(stack_size: u32) -> io::Result<u8> {
    ring_buffer_page_exp_for_page_size(stack_size, crate::elf::system_page_size())
}

fn ring_buffer_page_exp_for_page_size(stack_size: u32, page_size: u64) -> io::Result<u8> {
    const STACK_COUNT_PER_BUFFER: u32 = 32;
    if page_size == 0 {
        return Err(invalid_input("system page size cannot be zero"));
    }
    let required_space = u64::from(stack_size)
        .max(page_size)
        .checked_mul(u64::from(STACK_COUNT_PER_BUFFER))
        .ok_or_else(|| invalid_input("perf ring buffer size overflow"))?;
    let pages = required_space
        .div_ceil(page_size)
        .checked_next_power_of_two()
        .ok_or_else(|| invalid_input("perf ring buffer size overflow"))?;
    let page_exp = pages.trailing_zeros();
    if page_exp >= 26 {
        return Err(invalid_input(format!(
            "stack_size {stack_size} too large for the ring buffer"
        )));
    }
    Ok(page_exp as u8)
}

pub struct Perf {
    counter: Counter,
    target: u32,
    cpu: u32,
    inherit: TaskInheritance,
    include_kernel: bool,
}

impl Perf {
    fn new(
        counter: Counter,
        target: u32,
        cpu: u32,
        inherit: TaskInheritance,
        include_kernel: bool,
    ) -> Self {
        Self {
            counter,
            target,
            cpu,
            inherit,
            include_kernel,
        }
    }

    pub fn enable(&self) -> io::Result<()> {
        self.counter.enable()
    }

    pub fn disable(&self) -> io::Result<()> {
        self.counter.disable()
    }

    #[inline]
    pub fn fd(&self) -> RawFd {
        self.counter.file().as_raw_fd()
    }

    #[inline]
    pub fn target(&self) -> u32 {
        self.target
    }

    #[inline]
    pub fn inherit(&self) -> TaskInheritance {
        self.inherit
    }

    #[inline]
    pub fn includes_kernel(&self) -> bool {
        self.include_kernel
    }

    pub fn set_output(&self, output: &OutputRing) -> io::Result<()> {
        if self.cpu != output.cpu() {
            return Err(invalid_input("incompatible perf output ring"));
        }
        let result = unsafe { perf_event_open_sys::ioctls::SET_OUTPUT(self.fd(), output.fd()) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn lost_records(&self) -> io::Result<u64> {
        self.counter.stat()?.lost_records.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "perf counter omitted PERF_FORMAT_LOST",
            )
        })
    }
}

pub struct EventDrain<'a> {
    iter: CowIter<'a>,
}

impl EventDrain<'_> {
    pub fn next_event<R>(&mut self, cb: &mut impl FnMut(EventRef<'_>) -> R) -> Option<R> {
        self.iter
            .next(|record, parser| OwnedEventRecord::new(record, parser).with_event_ref(cb))
    }
}

pub struct EventRef<'a> {
    privilege: Priv,
    record: EventRecord<'a>,
    timestamp: Option<u64>,
}

pub enum EventRecord<'a> {
    Sample(SampleRecordRef<'a>),
    Owned(Record),
}

enum OwnedEventRecord<'a> {
    Sample {
        record: CowChunk<'a>,
        parser: UnsafeParser,
    },
    Parsed {
        privilege: Priv,
        record: Record,
        time: Option<u64>,
    },
}

impl<'a> OwnedEventRecord<'a> {
    fn new(record: CowChunk<'a>, parser: &Parser) -> Self {
        let bytes = record.as_bytes();
        if PerfRecordHeader::from_bytes(bytes)
            .is_some_and(|header| header.is_sample() && header.matches_len(bytes))
            && is_u64_aligned(bytes)
        {
            return Self::Sample {
                record,
                parser: parser.as_unsafe().clone(),
            };
        }

        let (privilege, parsed_record) = if is_u64_aligned(bytes) {
            parser.parse(record)
        } else {
            let parsed = parse_event_record_bytes(bytes, parser.as_unsafe())
                .expect("aligned perf record bytes should parse");
            drop(record);
            parsed
        };
        Self::Parsed {
            privilege,
            time: record_timestamp(&parsed_record),
            record: parsed_record,
        }
    }

    pub fn with_event_ref<R>(self, cb: &mut impl FnMut(EventRef<'_>) -> R) -> R {
        match self {
            Self::Sample { record, parser } => {
                let result = dispatch_event_bytes(record.as_bytes(), &parser, cb);
                drop(record);
                result
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

    pub fn raw_address_count(&self) -> usize {
        self.addresses.len()
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

#[derive(Clone, Copy)]
struct PerfRecordHeader {
    record_type: u32,
    misc: u16,
    size: usize,
}

impl PerfRecordHeader {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        ByteCursor::new(bytes).read_record_header()
    }

    fn is_sample(self) -> bool {
        self.record_type == sys::PERF_RECORD_SAMPLE
    }

    fn matches_len(self, bytes: &[u8]) -> bool {
        self.size == bytes.len()
    }
}

fn dispatch_event_bytes<R>(
    bytes: &[u8],
    parser: &UnsafeParser,
    cb: &mut impl FnMut(EventRef<'_>) -> R,
) -> R {
    if let Some((privilege, sample)) = parse_sample_record(bytes, parser) {
        return cb(EventRef {
            privilege,
            timestamp: sample.time,
            record: EventRecord::Sample(sample),
        });
    }

    let (privilege, record) =
        parse_aligned_event_record(bytes, parser).expect("perf record bytes should parse");
    cb(EventRef::new(privilege, record))
}

fn parse_aligned_event_record(bytes: &[u8], parser: &UnsafeParser) -> Option<(Priv, Record)> {
    if !is_u64_aligned(bytes) || !PerfRecordHeader::from_bytes(bytes)?.matches_len(bytes) {
        return None;
    }
    let (privilege, record, _) = unsafe { parser.parse(bytes) };
    Some((privilege, record))
}

fn parse_event_record_bytes(bytes: &[u8], parser: &UnsafeParser) -> Option<(Priv, Record)> {
    if is_u64_aligned(bytes) {
        return parse_aligned_event_record(bytes, parser);
    }
    let aligned = AlignedPerfRecord::from_unaligned_bytes(bytes);
    parse_aligned_event_record(aligned.as_bytes(), parser)
}

fn parse_sample_record<'a>(
    bytes: &'a [u8],
    parser: &perf_event_open::sample::record::UnsafeParser,
) -> Option<(Priv, SampleRecordRef<'a>)> {
    if !is_u64_aligned(bytes) {
        return None;
    }
    let mut cursor = ByteCursor::new(bytes);
    let header = read_sample_header(&mut cursor)?;
    let misc = header.misc;
    let sample_type = parser.sample_type;
    if !sample_type_supported(sample_type) {
        return None;
    }
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
    if !cursor.is_finished() {
        return None;
    }

    Some((priv_from_misc(misc), sample))
}

fn read_sample_header(cursor: &mut ByteCursor<'_>) -> Option<PerfRecordHeader> {
    let header = cursor.read_record_header()?;
    (header.is_sample() && header.matches_len(cursor.bytes)).then_some(header)
}

fn sample_type_supported(sample_type: u64) -> bool {
    const SUPPORTED_SAMPLE_TYPE: u64 = sys::PERF_SAMPLE_IP as u64
        | sys::PERF_SAMPLE_TID as u64
        | sys::PERF_SAMPLE_TIME as u64
        | sys::PERF_SAMPLE_ADDR as u64
        | sys::PERF_SAMPLE_ID as u64
        | sys::PERF_SAMPLE_STREAM_ID as u64
        | sys::PERF_SAMPLE_CPU as u64
        | sys::PERF_SAMPLE_PERIOD as u64
        | sys::PERF_SAMPLE_CALLCHAIN as u64
        | sys::PERF_SAMPLE_RAW as u64
        | sys::PERF_SAMPLE_REGS_USER as u64
        | sys::PERF_SAMPLE_STACK_USER as u64;

    sample_type & !SUPPORTED_SAMPLE_TYPE == 0
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
            // Framehop's native unwinder and our stack reader use the host's
            // 64-bit register/word ABI. Keep parsing ABI_32 records so the
            // cursor remains valid, but do not feed them into a 64-bit unwind.
            if abi == sys::PERF_SAMPLE_REGS_ABI_64 {
                sample.user_regs = Some(regs);
            }
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
        let parser = perf_event_open::sample::record::UnsafeParser {
            sample_id_all: false,
            sample_type: sample_type_bits(true, true, true),
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

    pub(crate) fn dispatch_event<R>(
        &self,
        record: &AlignedPerfRecord,
        cb: &mut impl FnMut(EventRef<'_>) -> R,
    ) -> R {
        dispatch_event_bytes(record.as_bytes(), &self.parser, cb)
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

enum AlignedPerfRecordStorage {
    Bytes(Vec<u8>),
    Words(Vec<u64>),
}

pub(crate) struct AlignedPerfRecord {
    storage: AlignedPerfRecordStorage,
    len: usize,
}

impl AlignedPerfRecord {
    fn from_vec(bytes: Vec<u8>) -> Self {
        if is_u64_aligned(&bytes) {
            return Self {
                len: bytes.len(),
                storage: AlignedPerfRecordStorage::Bytes(bytes),
            };
        }
        Self::from_unaligned_bytes(&bytes)
    }

    fn from_unaligned_bytes(bytes: &[u8]) -> Self {
        let mut words = vec![0_u64; bytes.len().div_ceil(size_of::<u64>())];
        let aligned_bytes =
            unsafe { slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), words.len() * 8) };
        aligned_bytes[..bytes.len()].copy_from_slice(bytes);
        Self {
            len: bytes.len(),
            storage: AlignedPerfRecordStorage::Words(words),
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        match &self.storage {
            AlignedPerfRecordStorage::Bytes(bytes) => bytes,
            AlignedPerfRecordStorage::Words(words) => unsafe {
                slice::from_raw_parts(words.as_ptr().cast::<u8>(), self.len)
            },
        }
    }

    #[cfg(test)]
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        match &mut self.storage {
            AlignedPerfRecordStorage::Bytes(bytes) => bytes,
            AlignedPerfRecordStorage::Words(words) => unsafe {
                slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), words.len() * 8)
            },
        }
    }

    fn len(&self) -> usize {
        self.len
    }
}

fn build_bench_sample_record(spec: &BenchSampleBatchSpec, sample_idx: usize) -> AlignedPerfRecord {
    build_bench_sample_record_with_abi(spec, sample_idx, sys::PERF_SAMPLE_REGS_ABI_64)
}

fn build_bench_sample_record_with_abi(
    spec: &BenchSampleBatchSpec,
    sample_idx: usize,
    user_regs_abi: u32,
) -> AlignedPerfRecord {
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

    push_u64(&mut bytes, u64::from(user_regs_abi));
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
    AlignedPerfRecord::from_vec(bytes)
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

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
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

    fn read_record_header(&mut self) -> Option<PerfRecordHeader> {
        Some(PerfRecordHeader {
            record_type: self.read_u32()?,
            misc: self.read_u16()?,
            size: usize::from(self.read_u16()?),
        })
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
            sample_type: sample_type_bits(true, true, true),
            read_format: 0,
            user_regs,
            intr_regs: 0,
            branch_sample_type: 0,
        }
    }

    fn set_dynamic_stack_size(record: &mut AlignedPerfRecord, dyn_len: u64) {
        let len = record.len();
        let bytes = record.as_mut_bytes();
        bytes[len - size_of::<u64>()..len].copy_from_slice(&dyn_len.to_ne_bytes());
    }

    #[test]
    fn ring_buffer_exp_keeps_space_for_queued_stack_samples() {
        assert_eq!(ring_buffer_page_exp(0).expect("page exp"), 5);
    }

    #[test]
    fn ring_buffer_exp_uses_the_runtime_page_size() {
        assert_eq!(
            ring_buffer_page_exp_for_page_size(MAX_SAMPLE_USER_STACK, 4_096).expect("4K page exp"),
            9
        );
        assert_eq!(
            ring_buffer_page_exp_for_page_size(MAX_SAMPLE_USER_STACK, 16_384)
                .expect("16K page exp"),
            7
        );
        assert_eq!(
            ring_buffer_page_exp_for_page_size(MAX_SAMPLE_USER_STACK, 65_536)
                .expect("64K page exp"),
            5
        );
        assert!(ring_buffer_page_exp_for_page_size(0, 0).is_err());
        assert!(ring_buffer_page_exp_for_page_size(0, u64::MAX).is_err());
    }

    #[test]
    fn software_fallback_is_limited_to_unavailable_hardware_events() {
        for errno in [libc::ENOENT, libc::ENODEV, libc::ENXIO] {
            let value = with_software_event_fallback(
                || Err(io::Error::from_raw_os_error(errno)),
                || Ok(42),
            )
            .expect("fallback to software event");
            assert_eq!(value, 42);
        }

        let err = with_software_event_fallback::<()>(
            || Err(io::Error::from_raw_os_error(libc::EPERM)),
            || panic!("permission errors must not trigger fallback"),
        )
        .expect_err("preserve hardware error");
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn software_fallback_preserves_the_software_errno() {
        let err = with_software_event_fallback::<()>(
            || Err(io::Error::from_raw_os_error(libc::ENODEV)),
            || Err(io::Error::from_raw_os_error(libc::EMFILE)),
        )
        .expect_err("return software event error");

        assert_eq!(err.raw_os_error(), Some(libc::EMFILE));
    }

    #[test]
    fn kernel_exclusion_fallback_is_limited_to_permission_errors() {
        for errno in [libc::EACCES, libc::EPERM] {
            let (value, kernel_enabled) = with_kernel_exclusion_fallback(
                true,
                || Err(io::Error::from_raw_os_error(errno)),
                || Ok(42),
            )
            .expect("retry without kernel samples");
            assert_eq!(value, 42);
            assert!(!kernel_enabled);
        }

        let err = with_kernel_exclusion_fallback::<()>(
            true,
            || Err(io::Error::from_raw_os_error(libc::EMFILE)),
            || panic!("resource errors must not trigger fallback"),
        )
        .expect_err("preserve preferred event error");
        assert_eq!(err.raw_os_error(), Some(libc::EMFILE));
    }

    #[test]
    fn guest_exclusion_fallback_retries_only_unsupported_guest_events() {
        let opts = Opts::default();
        let mut seen = Vec::new();
        let value = with_guest_exclusion_fallback(&opts, |opts| {
            seen.push(opts.exclude.guest);
            if opts.exclude.guest {
                Ok(42)
            } else {
                Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            }
        })
        .expect("retry with guest events excluded");

        assert_eq!(value, 42);
        assert_eq!(seen, [false, true]);

        for errno in [libc::EINVAL, libc::EPERM] {
            let mut calls = 0;
            let err = with_guest_exclusion_fallback::<()>(&opts, |_| {
                calls += 1;
                Err(io::Error::from_raw_os_error(errno))
            })
            .expect_err("preserve unrelated open error");
            assert_eq!(err.raw_os_error(), Some(errno));
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn guest_exclusion_fallback_is_bounded_and_preserves_retry_error() {
        let mut opts = Opts::default();
        opts.exclude.guest = true;
        let mut calls = 0;
        let err = with_guest_exclusion_fallback::<()>(&opts, |_| {
            calls += 1;
            Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
        })
        .expect_err("do not retry an already host-only event");
        assert_eq!(err.raw_os_error(), Some(libc::EOPNOTSUPP));
        assert_eq!(calls, 1);

        opts.exclude.guest = false;
        calls = 0;
        let err = with_guest_exclusion_fallback::<()>(&opts, |opts| {
            calls += 1;
            Err(io::Error::from_raw_os_error(if opts.exclude.guest {
                libc::EMFILE
            } else {
                libc::EOPNOTSUPP
            }))
        })
        .expect_err("preserve retry error");
        assert_eq!(err.raw_os_error(), Some(libc::EMFILE));
        assert_eq!(calls, 2);
    }

    #[test]
    fn perf_options_request_executable_mmaps_and_lost_counters() {
        let opts = PerfOptions::default().perf_open_opts();
        assert!(opts.extra_record.mmap.code);
        assert!(!opts.extra_record.mmap.data);
        assert!(opts.stat_format.lost_records);
    }

    #[test]
    fn perf_options_align_user_stack_to_u64() {
        let mut options = PerfOptions {
            stack_size: 12_345,
            ..PerfOptions::default()
        };

        options.align_stack_size().expect("align stack size");

        assert_eq!(options.stack_size, 12_352);
        assert_eq!(
            options.perf_open_opts().sample_format.user_stack,
            Some(Size(12_352))
        );
    }

    #[test]
    fn perf_options_align_and_validate_stack_size_boundaries() {
        for (requested, expected) in [
            (0, 0),
            (MAX_SAMPLE_USER_STACK - 1, MAX_SAMPLE_USER_STACK),
            (MAX_SAMPLE_USER_STACK, MAX_SAMPLE_USER_STACK),
        ] {
            let mut options = PerfOptions {
                stack_size: requested,
                ..PerfOptions::default()
            };
            options.align_stack_size().expect("align valid stack size");
            assert_eq!(options.stack_size, expected);
        }

        for requested in [MAX_SAMPLE_USER_STACK + 1, u32::MAX] {
            let mut options = PerfOptions {
                stack_size: requested,
                ..PerfOptions::default()
            };
            let err = options
                .align_stack_size()
                .expect_err("reject oversized stack");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(
                err.to_string(),
                format!("sample_user_stack can be at most {MAX_SAMPLE_USER_STACK} bytes")
            );
        }
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
    fn sample_parser_does_not_expose_32_bit_regs_to_native_unwinder() {
        let spec = stack_sample_spec(32);
        let parser = stack_sample_parser(spec.user_regs);
        let record = build_bench_sample_record_with_abi(&spec, 0, sys::PERF_SAMPLE_REGS_ABI_32);

        let (_, sample) =
            parse_sample_record(record.as_bytes(), &parser).expect("sample should parse");
        assert_eq!(sample.user_regs, None);
        assert_eq!(sample.user_stack.map(<[u8]>::len), Some(32));
    }

    #[test]
    fn bench_batch_dispatches_sample_event() {
        let spec = stack_sample_spec(16);
        let batch = BenchSampleBatch::new(spec);

        let mut timestamp = None;
        let mut task = None;
        batch.dispatch_event(&batch.records()[0], &mut |event| {
            timestamp = event.timestamp();
            let (privilege, record) = event.into_parts();
            let EventRecord::Sample(sample) = record else {
                panic!("expected sample record");
            };
            assert!(matches!(privilege, Priv::User));
            task = sample.task;
        });

        assert_eq!(timestamp, Some(1_700_000_000_000_000));
        let task = task.expect("sample task");
        assert_eq!(task.pid, 1234);
        assert_eq!(task.tid, 1234);
    }

    #[test]
    fn event_parser_handles_unaligned_sample_bytes() {
        let spec = stack_sample_spec(8);
        let parser = stack_sample_parser(spec.user_regs);
        let record = build_bench_sample_record(&spec, 0);
        let mut unaligned = Vec::with_capacity(record.len() + 1);
        unaligned.push(0);
        unaligned.extend_from_slice(record.as_bytes());
        let bytes = &unaligned[1..];

        assert!(!is_u64_aligned(bytes));
        let (privilege, record) =
            parse_event_record_bytes(bytes, &parser).expect("unaligned sample should parse");
        let Record::Sample(sample) = record else {
            panic!("expected parsed sample record");
        };
        assert_eq!(privilege, Priv::User);
        assert_eq!(
            sample.record_id.task.map(|task| task.pid),
            Some(spec.process_id)
        );
        assert_eq!(
            sample.user_stack.as_deref(),
            Some(&[0, 1, 2, 3, 4, 5, 6, 7][..])
        );
    }

    #[test]
    fn sample_parser_rejects_invalid_dynamic_stack_size() {
        let spec = stack_sample_spec(16);
        let parser = stack_sample_parser(spec.user_regs);
        let mut record = build_bench_sample_record(&spec, 0);
        set_dynamic_stack_size(&mut record, 17);

        assert!(parse_sample_record(record.as_bytes(), &parser).is_none());
    }
}
