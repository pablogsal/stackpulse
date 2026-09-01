use std::fmt;
use std::io;
use std::mem::{size_of, size_of_val};
use std::ops::Range;
use std::os::fd::{AsRawFd, RawFd};
use std::slice;
use std::sync::Arc;

use perf_event_open::config::{
    CallChain, Clock, Cpu, Inherit, OnExecve, Opts, Proc, RecordIdFormat, RegsMask, SampleOn, Size,
    UseBuildId, WakeUpOn,
};
use perf_event_open::count::Counter;
use perf_event_open::event::hw::Hardware;
use perf_event_open::event::sw::Software;
use perf_event_open::event::Event as PerfOpenEvent;
use perf_event_open::sample::record::{Priv, Record, RecordId, UnsafeParser};
use perf_event_open_sys::bindings as sys;

use super::aligned_bytes::{is_u64_aligned, AlignedBytes};
use super::ring_buffer::{RingBuffer, RingRecord};
#[cfg(test)]
use super::DEFAULT_RING_BUFFER_STACKS;
use super::{invalid_data, normalized_ring_stacks};

/// Maximum accepted `sample_stack_user` request, in bytes. The kernel may
/// return fewer bytes so the complete perf record still fits its size field.
/// Acts as a ceiling for `RecorderOptions::stack_size`; larger values are
/// rejected.
pub const MAX_SAMPLE_USER_STACK: u32 = 65_528;

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Error returned when the requested sample rate exceeds the kernel's
/// `perf_event_max_sample_rate`.
///
/// Wraps the rate the caller asked for and the cap currently in effect, so
/// they can adjust the recorder's `frequency` option and retry, or read the
/// cap up front via [`crate::record::max_sample_rate`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, thiserror::Error)]
#[error(
    "frequency {requested_frequency} exceeds /proc/sys/kernel/perf_event_max_sample_rate {max_frequency}"
)]
pub struct PerfFrequencyLimit {
    /// Frequency the caller asked for, in Hz.
    pub requested_frequency: u64,
    /// Current `/proc/sys/kernel/perf_event_max_sample_rate` cap.
    pub max_frequency: u64,
}

#[derive(Copy, Clone, PartialEq, Debug, Default)]
pub(super) enum EventSource {
    HwCpuCycles,
    #[default]
    SwCpuClock,
}

/// `include_kernel = false` is the safe default; everything else zero-defaults.
#[derive(Clone, Debug)]
pub(super) struct PerfOptions {
    pub pid: u32,
    pub cpu: u32,
    pub frequency: u64,
    pub stack_size: u32,
    pub ring_stacks: u32,
    pub maximum_ring_bytes: u64,
    pub reg_mask: u64,
    pub event_source: EventSource,
    pub inherit: TaskInheritance,
    pub enable_on_exec: bool,
    pub include_kernel: bool,
    pub sample_callchain: bool,
    pub exclude_user_callchain: bool,
    pub exclude_kernel_callchain: bool,
}

impl Default for PerfOptions {
    fn default() -> Self {
        Self {
            pid: 0,
            cpu: 0,
            frequency: 0,
            stack_size: 0,
            ring_stacks: 0,
            maximum_ring_bytes: MAX_RING_BUFFER_BYTES,
            reg_mask: 0,
            event_source: EventSource::default(),
            inherit: TaskInheritance::default(),
            enable_on_exec: false,
            include_kernel: false,
            sample_callchain: false,
            exclude_user_callchain: false,
            exclude_kernel_callchain: false,
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(super) enum TaskInheritance {
    #[default]
    None,
    Threads,
    Children,
}

impl TaskInheritance {
    #[inline]
    #[must_use]
    pub(super) fn is_enabled(self) -> bool {
        self != Self::None
    }
}

struct OpenedCounter {
    counter: Counter,
    inherit: TaskInheritance,
    include_kernel: bool,
}

struct PerfRecordLayout {
    callchain: bool,
    user_regs_mask: u64,
    user_stack_size: u32,
}

impl PerfRecordLayout {
    fn apply(self, opts: &mut Opts, exclude_user_callchain: bool, exclude_kernel_callchain: bool) {
        opts.sample_format.code_addr = true;
        if self.callchain {
            opts.sample_format.call_chain = Some(CallChain {
                exclude_user: exclude_user_callchain,
                exclude_kernel: exclude_kernel_callchain,
                defer_user: false,
                // Zero lets the kernel honor its current perf_event_max_stack
                // setting instead of rejecting hosts configured below ours.
                max_stack_frames: 0,
            });
        }
        if self.user_regs_mask != 0 {
            opts.sample_format.user_regs = Some(RegsMask(self.user_regs_mask));
        }
        if self.user_stack_size != 0 {
            opts.sample_format.user_stack = Some(Size(self.user_stack_size));
        }
        opts.stat_format.lost_records = true;
    }

    fn parser(self) -> UnsafeParser {
        UnsafeParser {
            sample_id_all: true,
            sample_type: sample_type_bits(
                self.callchain,
                self.user_regs_mask != 0,
                self.user_stack_size != 0,
            ),
            read_format: u64::from(sys::PERF_FORMAT_LOST),
            user_regs: self.user_regs_mask.count_ones() as usize,
            intr_regs: 0,
            branch_sample_type: 0,
        }
    }
}

#[derive(Debug)]
struct RingPlan {
    requested_exp: u8,
    fallback_exp: u8,
}

impl PerfOptions {
    fn record_layout(&self) -> PerfRecordLayout {
        PerfRecordLayout {
            callchain: self.sample_callchain,
            user_regs_mask: self.reg_mask,
            user_stack_size: self.stack_size,
        }
    }

    pub(super) fn open(mut self) -> io::Result<Perf> {
        self.align_stack_size()?;
        let OpenedCounter {
            counter,
            inherit,
            include_kernel,
        } = self.open_counter()?;

        Ok(Perf::new(
            counter,
            self.pid,
            self.cpu,
            inherit,
            include_kernel,
        ))
    }

    pub(super) fn open_ring(mut self) -> io::Result<OutputRing> {
        self.align_stack_size()?;
        let plan = self.ring_plan()?;
        let parser = Arc::new(self.record_parser());
        self.validate()?;
        let (opened, ring) = open_ring_with_fallback(
            plan.requested_exp,
            plan.fallback_exp,
            |page_exp| self.open_counter_with_page_exp(page_exp),
            |opened, page_exp| RingBuffer::new(opened.counter.file(), page_exp),
        )?;
        let OpenedCounter {
            counter,
            inherit,
            include_kernel,
        } = opened;
        Ok(OutputRing {
            perf: Perf::new(counter, self.pid, self.cpu, inherit, include_kernel),
            ring,
            parser,
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

    fn open_counter(&self) -> io::Result<OpenedCounter> {
        self.validate()?;
        let plan = self.ring_plan()?;
        self.open_counter_with_page_exp(plan.requested_exp)
    }

    fn open_counter_with_page_exp(&self, page_exp: u8) -> io::Result<OpenedCounter> {
        let opts = self.perf_open_opts(ring_wakeup_bytes(page_exp)?);
        match self.open_counter_once(&opts) {
            Ok((counter, include_kernel)) => Ok(OpenedCounter {
                counter,
                inherit: self.inherit,
                include_kernel,
            }),
            Err(err)
                if self.inherit == TaskInheritance::Threads && is_inherit_thread_error(&err) =>
            {
                let mut no_inherit_opts = opts.clone();
                no_inherit_opts.inherit = None;
                self.open_counter_once(&no_inherit_opts)
                    .map(|(counter, include_kernel)| OpenedCounter {
                        counter,
                        inherit: TaskInheritance::None,
                        include_kernel,
                    })
            }
            Err(err) => Err(err),
        }
    }

    fn validate(&self) -> io::Result<()> {
        if let Some(max_rate) = crate::record::max_sample_rate().filter(|&r| self.frequency > r) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                PerfFrequencyLimit {
                    requested_frequency: self.frequency,
                    max_frequency: max_rate,
                },
            ));
        }
        Ok(())
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

    fn ring_plan(&self) -> io::Result<RingPlan> {
        let requested_exp = ring_buffer_page_exp(self.stack_size, self.ring_stacks)?;
        let budget_exp = ring_buffer_budget_page_exp(self.maximum_ring_bytes)?;
        let minimum_exp = ring_buffer_page_exp(self.stack_size, 1)?;
        if budget_exp < minimum_exp {
            return Err(invalid_input(
                "aggregate perf ring budget cannot fit one complete sample per CPU",
            ));
        }
        let requested_exp = requested_exp.min(budget_exp);
        Ok(RingPlan {
            requested_exp,
            fallback_exp: minimum_exp,
        })
    }

    fn perf_open_opts(&self, wakeup_bytes: u32) -> Opts {
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
        opts.wake_up.on = WakeUpOn::Bytes(wakeup_bytes);
        self.record_layout().apply(
            &mut opts,
            self.exclude_user_callchain,
            self.exclude_kernel_callchain,
        );
        opts.extra_record.mmap.code = true;
        opts.extra_record.mmap.ext = Some(UseBuildId(false));
        opts.extra_record.comm = true;
        opts.extra_record.task = true;
        opts
    }

    fn record_parser(&self) -> UnsafeParser {
        self.record_layout().parser()
    }
}

pub(super) struct OutputRing {
    perf: Perf,
    ring: RingBuffer,
    parser: Arc<UnsafeParser>,
}

impl OutputRing {
    pub(super) fn enable(&self) -> io::Result<()> {
        self.perf.enable()
    }

    pub(super) fn disable(&self) -> io::Result<()> {
        self.perf.disable()
    }

    #[inline]
    pub(super) fn fd(&self) -> RawFd {
        self.perf.fd()
    }

    #[inline]
    pub(super) fn cpu(&self) -> u32 {
        self.perf.cpu
    }

    pub(super) fn capacity_bytes(&self) -> u64 {
        self.ring.capacity_bytes() as u64
    }

    #[inline]
    pub(super) fn inherit(&self) -> TaskInheritance {
        self.perf.inherit()
    }

    #[inline]
    pub(super) fn includes_kernel(&self) -> bool {
        self.perf.includes_kernel()
    }

    pub(super) fn event_drain(&mut self) -> EventDrain<'_> {
        let end = self.ring.snapshot_head();
        EventDrain {
            ring: &mut self.ring,
            parser: &self.parser,
            end,
        }
    }

    pub(super) fn lost_records(&self) -> io::Result<u64> {
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
    // SAFETY: limit points to initialized writable storage for one rlimit value.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } < 0
        || limit.rlim_cur >= limit.rlim_max
    {
        return false;
    }
    limit.rlim_cur = limit.rlim_max;
    // SAFETY: limit points to an initialized rlimit obtained from getrlimit.
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

const RING_WAKEUP_FRACTION: u64 = 8;
const MAX_RING_BUFFER_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PERF_RECORD_BYTES: u64 = u16::MAX as u64;

fn ring_buffer_page_exp(stack_size: u32, ring_stacks: u32) -> io::Result<u8> {
    ring_buffer_page_exp_for_page_size(stack_size, ring_stacks, crate::elf::system_page_size())
}

fn ring_buffer_page_exp_for_page_size(
    stack_size: u32,
    ring_stacks: u32,
    page_size: u64,
) -> io::Result<u8> {
    if page_size == 0 {
        return Err(invalid_input("system page size cannot be zero"));
    }
    // Size each requested slot from the configured stack snapshot while
    // keeping enough total capacity for any perf_event_header::size value.
    let required_space = u64::from(stack_size)
        .max(page_size)
        .checked_mul(u64::from(normalized_ring_stacks(ring_stacks)))
        .ok_or_else(|| invalid_input("perf ring buffer size overflow"))?
        .max(MAX_PERF_RECORD_BYTES);
    let pages = required_space
        .div_ceil(page_size)
        .checked_next_power_of_two()
        .ok_or_else(|| invalid_input("perf ring buffer size overflow"))?;
    let ring_bytes = page_size
        .checked_mul(pages)
        .ok_or_else(|| invalid_input("perf ring buffer size overflow"))?;
    if ring_bytes > MAX_RING_BUFFER_BYTES {
        return Err(invalid_input(format!(
            "requested perf ring buffer exceeds {MAX_RING_BUFFER_BYTES} bytes per CPU"
        )));
    }
    Ok(pages.trailing_zeros() as u8)
}

fn ring_wakeup_bytes(page_exp: u8) -> io::Result<u32> {
    let capacity = crate::elf::system_page_size()
        .checked_shl(u32::from(page_exp))
        .ok_or_else(|| invalid_input("perf ring buffer size overflow"))?;
    u32::try_from((capacity / RING_WAKEUP_FRACTION).max(1))
        .map_err(|_| invalid_input("perf ring wakeup watermark exceeds u32"))
}

fn ring_buffer_budget_page_exp(maximum_bytes: u64) -> io::Result<u8> {
    let page_size = crate::elf::system_page_size();
    let pages = maximum_bytes / page_size;
    if pages == 0 {
        return Err(invalid_input(
            "perf ring buffer budget is smaller than one page",
        ));
    }
    Ok((u64::BITS - 1 - pages.leading_zeros()) as u8)
}

fn open_ring_with_fallback<C, R>(
    requested_exp: u8,
    fallback_exp: u8,
    mut open_counter: impl FnMut(u8) -> io::Result<C>,
    mut open_ring: impl FnMut(&C, u8) -> io::Result<R>,
) -> io::Result<(C, R)> {
    let mut page_exp = requested_exp;
    loop {
        let counter = open_counter(page_exp)?;
        match open_ring(&counter, page_exp) {
            Err(error)
                if page_exp > fallback_exp
                    && matches!(error.raw_os_error(), Some(libc::EPERM | libc::ENOMEM)) =>
            {
                page_exp -= 1;
            }
            Ok(ring) => return Ok((counter, ring)),
            Err(error) => return Err(error),
        }
    }
}

pub(super) struct Perf {
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

    pub(super) fn enable(&self) -> io::Result<()> {
        self.counter.enable()
    }

    pub(super) fn disable(&self) -> io::Result<()> {
        self.counter.disable()
    }

    #[inline]
    pub(super) fn fd(&self) -> RawFd {
        self.counter.file().as_raw_fd()
    }

    #[inline]
    pub(super) fn target(&self) -> u32 {
        self.target
    }

    #[inline]
    pub(super) fn inherit(&self) -> TaskInheritance {
        self.inherit
    }

    #[inline]
    pub(super) fn includes_kernel(&self) -> bool {
        self.include_kernel
    }

    pub(super) fn set_output(&self, output: &OutputRing) -> io::Result<()> {
        if self.cpu != output.cpu() {
            return Err(invalid_input("incompatible perf output ring"));
        }
        // SAFETY: both descriptors are live perf events opened with compatible attributes.
        let result = unsafe { perf_event_open_sys::ioctls::SET_OUTPUT(self.fd(), output.fd()) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn lost_records(&self) -> io::Result<u64> {
        self.counter.stat()?.lost_records.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "perf counter omitted PERF_FORMAT_LOST",
            )
        })
    }
}

pub(super) struct EventDrain<'a> {
    ring: &'a mut RingBuffer,
    parser: &'a Arc<UnsafeParser>,
    end: u64,
}

impl EventDrain<'_> {
    pub(super) fn next_event<R>(
        &mut self,
        cb: &mut impl FnMut(EventRef) -> R,
    ) -> io::Result<Option<R>> {
        let Some(record) = self.ring.next_record_to(self.end)? else {
            return Ok(None);
        };
        let bytes = record.as_bytes();
        if PerfRecordHeader::from_bytes(bytes)
            .is_some_and(|header| header.is_sample() && header.matches_len(bytes))
            && is_u64_aligned(bytes)
        {
            let (privilege, metadata, layout) = {
                let (privilege, sample) = parse_sample_record(bytes, self.parser)
                    .ok_or_else(|| invalid_data("perf sample payload does not match its format"))?;
                (
                    privilege,
                    SampleMetadata {
                        task: sample.task,
                        time: sample.time,
                        code_addr: sample.code_addr,
                    },
                    SampleRecordLayout::from_sample(bytes, sample).ok_or_else(|| {
                        invalid_data("perf sample slices fall outside their record")
                    })?,
                )
            };
            return Ok(Some(cb(EventRef {
                privilege,
                timestamp: metadata.time,
                record: EventRecord::RingSample {
                    sample: RingSample {
                        storage: RingSampleStorage::Ring(record),
                        layout,
                    },
                    metadata,
                },
            })));
        }

        let (privilege, parsed_record) = parse_event_record_bytes(bytes, self.parser)
            .ok_or_else(|| invalid_data("perf record payload does not match its format"))?;
        drop(record);
        let timestamp = record_timestamp(&parsed_record);
        Ok(Some(cb(EventRef {
            privilege,
            record: EventRecord::Owned(parsed_record),
            timestamp,
        })))
    }
}

pub(super) struct EventRef {
    privilege: Priv,
    record: EventRecord,
    timestamp: Option<u64>,
}

pub(super) enum EventRecord {
    RingSample {
        sample: RingSample,
        metadata: SampleMetadata,
    },
    Owned(Record),
}

pub(super) struct RingSample {
    storage: RingSampleStorage,
    layout: SampleRecordLayout,
}

struct SampleRecordLayout {
    user_regs: Option<Range<usize>>,
    user_stack: Option<Range<usize>>,
    call_chain: Option<Range<usize>>,
}

impl SampleRecordLayout {
    fn from_sample(bytes: &[u8], sample: SampleRecordRef<'_>) -> Option<Self> {
        Some(Self {
            user_regs: match sample.user_regs {
                Some(slice) => Some(slice_byte_range(bytes, slice)?),
                None => None,
            },
            user_stack: match sample.user_stack {
                Some(slice) => Some(slice_byte_range(bytes, slice)?),
                None => None,
            },
            call_chain: match sample.call_chain {
                Some(chain) => Some(slice_byte_range(bytes, chain.addresses)?),
                None => None,
            },
        })
    }

    fn sample<'a>(&self, bytes: &'a [u8]) -> Option<RingSampleRef<'a>> {
        Some(RingSampleRef {
            user_regs: match &self.user_regs {
                Some(range) => Some(u64_slice(bytes.get(range.clone())?)?),
                None => None,
            },
            user_stack: match &self.user_stack {
                Some(range) => Some(bytes.get(range.clone())?),
                None => None,
            },
            call_chain: match &self.call_chain {
                Some(range) => Some(CallChainRef {
                    addresses: u64_slice(bytes.get(range.clone())?)?,
                }),
                None => None,
            },
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct SampleMetadata {
    pub(super) task: Option<TaskRef>,
    pub(super) time: Option<u64>,
    pub(super) code_addr: Option<(u64, bool)>,
}

enum RingSampleStorage {
    Ring(RingRecord),
    Detached(AlignedBytes),
}

impl RingSample {
    fn bytes(&self) -> &[u8] {
        match &self.storage {
            RingSampleStorage::Ring(record) => record.as_bytes(),
            RingSampleStorage::Detached(record) => record.as_bytes(),
        }
    }

    pub(super) fn with_sample<R>(
        &self,
        callback: impl FnOnce(RingSampleRef<'_>) -> R,
    ) -> Option<R> {
        self.layout.sample(self.bytes()).map(callback)
    }

    pub(super) fn detach(&mut self) {
        let RingSampleStorage::Ring(record) = &mut self.storage else {
            return;
        };
        let detached = record.detach_bytes();
        self.storage = RingSampleStorage::Detached(detached);
    }
}

pub(super) struct RingSampleRef<'a> {
    pub(super) user_regs: Option<&'a [u64]>,
    pub(super) user_stack: Option<&'a [u8]>,
    pub(super) call_chain: Option<CallChainRef<'a>>,
}

fn slice_byte_range<T>(bytes: &[u8], slice: &[T]) -> Option<Range<usize>> {
    let start = (slice.as_ptr() as usize).checked_sub(bytes.as_ptr() as usize)?;
    let end = start.checked_add(size_of_val(slice))?;
    bytes.get(start..end)?;
    Some(start..end)
}

fn u64_slice(bytes: &[u8]) -> Option<&[u64]> {
    if !is_u64_aligned(bytes) || !bytes.len().is_multiple_of(size_of::<u64>()) {
        return None;
    }
    // SAFETY: the alignment and exact u64-multiple byte length were checked.
    Some(unsafe {
        slice::from_raw_parts(bytes.as_ptr().cast::<u64>(), bytes.len() / size_of::<u64>())
    })
}

#[derive(Clone, Copy)]
pub(super) struct SampleRecordRef<'a> {
    pub task: Option<TaskRef>,
    pub time: Option<u64>,
    pub code_addr: Option<(u64, bool)>,
    pub user_regs: Option<&'a [u64]>,
    pub user_stack: Option<&'a [u8]>,
    pub call_chain: Option<CallChainRef<'a>>,
}

#[derive(Clone, Copy)]
pub(super) struct TaskRef {
    pub pid: u32,
    pub tid: u32,
}

#[derive(Clone, Copy)]
pub(super) struct CallChainRef<'a> {
    addresses: &'a [u64],
}

impl<'a> CallChainRef<'a> {
    pub(super) fn iter(&self) -> CallChainIter<'a> {
        CallChainIter {
            addresses: self.addresses,
            cursor: 0,
        }
    }

    pub(super) fn raw_address_count(&self) -> usize {
        self.addresses.len()
    }
}

pub(super) struct CallChainIter<'a> {
    addresses: &'a [u64],
    cursor: usize,
}

pub(super) enum CallChainEntry<'a> {
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

impl fmt::Debug for EventRef {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("EventRef")
            .field("privilege", &self.privilege)
            .field("timestamp", &self.timestamp)
            .finish_non_exhaustive()
    }
}

impl EventRef {
    pub(super) fn timestamp(&self) -> Option<u64> {
        self.timestamp
    }

    pub(super) fn into_parts(self) -> (Priv, EventRecord) {
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

fn parse_aligned_event_record(bytes: &[u8], parser: &UnsafeParser) -> Option<(Priv, Record)> {
    if !is_u64_aligned(bytes) || !PerfRecordHeader::from_bytes(bytes)?.matches_len(bytes) {
        return None;
    }
    // SAFETY: the bytes are aligned, contain a complete record, and come from
    // the same perf layout as this parser. Output rings and synthetic fixtures
    // construct their parser and bytes from one `PerfRecordLayout`.
    let (privilege, record, _) = unsafe { parser.parse(bytes) };
    Some((privilege, record))
}

fn parse_event_record_bytes(bytes: &[u8], parser: &UnsafeParser) -> Option<(Priv, Record)> {
    if is_u64_aligned(bytes) {
        return parse_aligned_event_record(bytes, parser);
    }
    let aligned = AlignedBytes::from_unaligned_bytes(bytes);
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
    const REQUIRED_SAMPLE_TYPE: u64 =
        sys::PERF_SAMPLE_IP as u64 | sys::PERF_SAMPLE_TID as u64 | sys::PERF_SAMPLE_TIME as u64;
    const SUPPORTED_SAMPLE_TYPE: u64 = sys::PERF_SAMPLE_IP as u64
        | sys::PERF_SAMPLE_TID as u64
        | sys::PERF_SAMPLE_TIME as u64
        | sys::PERF_SAMPLE_CALLCHAIN as u64
        | sys::PERF_SAMPLE_REGS_USER as u64
        | sys::PERF_SAMPLE_STACK_USER as u64;

    sample_type & REQUIRED_SAMPLE_TYPE == REQUIRED_SAMPLE_TYPE
        && sample_type & !SUPPORTED_SAMPLE_TYPE == 0
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

fn is_callchain_marker(address: u64) -> bool {
    address.wrapping_add(4095) < 4095
}

#[cfg(any(test, feature = "bench-support"))]
pub(super) struct BenchSampleBatch {
    parser: Arc<perf_event_open::sample::record::UnsafeParser>,
    records: Vec<AlignedBytes>,
    event_bytes: usize,
    frames_per_sample: usize,
}

#[cfg(any(test, feature = "bench-support"))]
pub(super) struct BenchSampleBatchSpec {
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

#[cfg(any(test, feature = "bench-support"))]
impl BenchSampleBatch {
    pub(super) fn new(spec: BenchSampleBatchSpec) -> Self {
        let parser = Arc::new(perf_event_open::sample::record::UnsafeParser {
            sample_id_all: false,
            sample_type: sample_type_bits(true, true, true),
            read_format: 0,
            user_regs: spec.user_regs,
            intr_regs: 0,
            branch_sample_type: 0,
        });

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

    pub(super) fn records(&self) -> &[AlignedBytes] {
        &self.records
    }

    pub(super) fn event_bytes(&self) -> usize {
        self.event_bytes
    }

    pub(super) fn sample_count(&self) -> usize {
        self.records.len()
    }

    pub(super) fn frame_count(&self) -> usize {
        self.records.len() * self.frames_per_sample
    }

    pub(super) fn parse<'a>(
        &self,
        record: &'a AlignedBytes,
    ) -> Option<(Priv, SampleRecordRef<'a>)> {
        parse_sample_record(record.as_bytes(), &self.parser)
    }

    pub(super) fn event_drain<'a>(&'a self, ring: &'a mut RingBuffer) -> EventDrain<'a> {
        EventDrain {
            end: ring.snapshot_head(),
            ring,
            parser: &self.parser,
        }
    }
}

#[cfg(any(test, feature = "bench-support"))]
#[expect(
    clippy::expect_used,
    reason = "the benchmark parses records generated by this module"
)]
pub(super) fn bench_parse_sample_records(batch: &BenchSampleBatch, rounds: u64) -> usize {
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

#[cfg(any(test, feature = "bench-support"))]
fn build_bench_sample_record(spec: &BenchSampleBatchSpec, sample_idx: usize) -> AlignedBytes {
    build_bench_sample_record_with_abi(spec, sample_idx, sys::PERF_SAMPLE_REGS_ABI_64)
}

#[cfg(any(test, feature = "bench-support"))]
#[expect(
    clippy::expect_used,
    reason = "the bounded synthetic fixture is constructed to fit the perf u16 record size"
)]
fn build_bench_sample_record_with_abi(
    spec: &BenchSampleBatchSpec,
    sample_idx: usize,
    user_regs_abi: u32,
) -> AlignedBytes {
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

    let context_count = usize::from(spec.kernel_frames != 0) + usize::from(spec.user_frames != 0);
    push_u64(
        &mut bytes,
        (context_count + spec.kernel_frames + spec.user_frames) as u64,
    );
    if spec.kernel_frames != 0 {
        push_u64(&mut bytes, sys::PERF_CONTEXT_KERNEL);
        for frame_idx in 0..spec.kernel_frames {
            push_u64(
                &mut bytes,
                spec.kernel_base + ((sample_variant + frame_idx as u64 * 13) % 4096) * 0x20,
            );
        }
    }
    if spec.user_frames != 0 {
        push_u64(&mut bytes, sys::PERF_CONTEXT_USER);
        for frame_idx in 0..spec.user_frames {
            push_u64(
                &mut bytes,
                spec.user_base + ((sample_variant + frame_idx as u64 * 17) % 4096) * 0x20,
            );
        }
    }

    push_u64(&mut bytes, u64::from(user_regs_abi));
    for reg_idx in 0..spec.user_regs {
        push_u64(
            &mut bytes,
            spec.user_base + 0x8000 + sample_variant * 8 + reg_idx as u64 * 0x10,
        );
    }

    push_u64(&mut bytes, spec.user_stack_bytes as u64);
    if spec.user_stack_bytes != 0 {
        let stack_start = bytes.len();
        bytes.resize(stack_start + spec.user_stack_bytes, 0);
        for (offset, byte) in bytes[stack_start..].iter_mut().enumerate() {
            *byte = sample_idx.wrapping_add(offset) as u8;
        }
        push_u64(&mut bytes, spec.user_stack_bytes as u64);
    }

    let padded_len = bytes.len().next_multiple_of(size_of::<u64>());
    bytes.resize(padded_len, 0);
    let size = u16::try_from(bytes.len()).expect("synthetic perf sample fits in u16");
    bytes[6..8].copy_from_slice(&size.to_ne_bytes());
    AlignedBytes::from_vec(bytes)
}

#[cfg(any(test, feature = "bench-support"))]
fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_ne_bytes());
}

#[cfg(any(test, feature = "bench-support"))]
fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_ne_bytes());
}

#[cfg(any(test, feature = "bench-support"))]
fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_ne_bytes());
}

#[cfg(any(test, feature = "bench-support"))]
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
        // SAFETY: alignment and the exact u64-multiple length were checked above.
        Some(unsafe { slice::from_raw_parts(bytes.as_ptr().cast::<u64>(), len) })
    }

    fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(len)?;
        let bytes = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(bytes)
    }

    fn read_array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.read_bytes(N)?.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::super::SampleCallChain;
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

    fn set_dynamic_stack_size(record: &mut AlignedBytes, dyn_len: u64) {
        let len = record.len();
        let bytes = record.as_mut_bytes();
        bytes[len - size_of::<u64>()..len].copy_from_slice(&dyn_len.to_ne_bytes());
    }

    #[test]
    fn detached_ring_sample_releases_tail_and_remains_parseable() {
        let spec = stack_sample_spec(64);
        let parser = Arc::new(stack_sample_parser(spec.user_regs));
        let bytes = build_bench_sample_record(&spec, 3);
        let mut ring = super::super::ring_buffer::mock_ring(0, bytes.as_bytes());
        let (mut sample, time) = {
            let end = ring.snapshot_head();
            let mut drain = EventDrain {
                ring: &mut ring,
                parser: &parser,
                end,
            };
            drain
                .next_event(&mut |event| match event.record {
                    EventRecord::RingSample { sample, metadata } => (sample, metadata.time),
                    _ => panic!("expected ring-backed sample"),
                })
                .expect("read ring sample")
                .expect("ring sample")
        };

        assert_eq!(super::super::ring_buffer::test_tail(&ring), 0);
        sample.detach();
        assert_eq!(
            super::super::ring_buffer::test_tail(&ring),
            bytes.len() as u64
        );
        let stack_len = sample
            .with_sample(|sample| sample.user_stack.map_or(0, <[u8]>::len))
            .expect("detached sample parses");
        assert_eq!(time, Some(1_700_000_000_000_000 + 3_000));
        assert_eq!(stack_len, 64);
    }

    #[test]
    fn ring_buffer_exp_uses_stack_size_and_record_count() {
        assert_eq!(
            ring_buffer_page_exp_for_page_size(32 * 1024, 32, 4_096).unwrap(),
            8
        );
        assert_eq!(
            ring_buffer_page_exp_for_page_size(32 * 1024, 0, 4_096).unwrap(),
            8
        );
        assert_eq!(
            ring_buffer_page_exp_for_page_size(64 * 1024, 32, 4_096).unwrap(),
            9
        );
        assert_eq!(
            ring_buffer_page_exp_for_page_size(16 * 1024, 8, 4_096).unwrap(),
            5
        );
        assert_eq!(
            ring_buffer_page_exp_for_page_size(48 * 1024, 3, 4_096).unwrap(),
            6
        );
    }

    #[test]
    fn ring_buffer_exp_preserves_record_minimum_and_runtime_page_size() {
        assert_eq!(ring_buffer_page_exp_for_page_size(0, 1, 4_096).unwrap(), 4);
        assert_eq!(ring_buffer_page_exp_for_page_size(0, 1, 16_384).unwrap(), 2);
        assert_eq!(ring_buffer_page_exp_for_page_size(0, 1, 65_536).unwrap(), 0);
        assert!(ring_buffer_page_exp_for_page_size(0, 1, 0).is_err());
        assert_eq!(
            ring_buffer_page_exp_for_page_size(64 * 1024, 256, 4_096).expect("256 stacks"),
            12
        );
        assert_eq!(
            ring_buffer_page_exp_for_page_size(64 * 1024, 4_096, 4_096).expect("256 MiB ring"),
            16
        );
        assert!(ring_buffer_page_exp_for_page_size(64 * 1024, 4_097, 4_096).is_err());
        assert!(ring_buffer_page_exp_for_page_size(0, 1, u64::MAX).is_err());
    }

    #[test]
    fn aggregate_ring_budget_rounds_down_to_complete_pages() {
        let page_size = crate::elf::system_page_size();

        assert_eq!(ring_buffer_budget_page_exp(page_size * 3).unwrap(), 1);
        assert_eq!(ring_buffer_budget_page_exp(page_size * 8).unwrap(), 3);
        assert!(ring_buffer_budget_page_exp(page_size - 1).is_err());
    }

    #[test]
    fn ring_plan_clamps_watermark_to_the_smallest_effective_capacity() {
        let page_size = crate::elf::system_page_size();
        let minimum_exp = ring_buffer_page_exp(32 * 1024, 1).unwrap();
        let budget = page_size << minimum_exp;
        let options = PerfOptions {
            stack_size: 32 * 1024,
            ring_stacks: DEFAULT_RING_BUFFER_STACKS,
            maximum_ring_bytes: budget,
            sample_callchain: true,
            ..PerfOptions::default()
        };

        let plan = options.ring_plan().unwrap();
        let wakeup_bytes = ring_wakeup_bytes(plan.requested_exp).unwrap();

        assert_eq!(plan.requested_exp, minimum_exp);
        assert_eq!(plan.fallback_exp, minimum_exp);
        assert!(u64::from(wakeup_bytes) <= budget / RING_WAKEUP_FRACTION);
        let WakeUpOn::Bytes(watermark) = options.perf_open_opts(wakeup_bytes).wake_up.on else {
            panic!("expected byte watermark");
        };
        assert_eq!(watermark, wakeup_bytes);
    }

    #[test]
    fn aggregate_budget_clamps_requested_ring_but_preserves_fallback_range() {
        let page_size = crate::elf::system_page_size();
        let options = PerfOptions {
            stack_size: 64 * 1024,
            ring_stacks: DEFAULT_RING_BUFFER_STACKS,
            maximum_ring_bytes: 1024 * 1024,
            ..PerfOptions::default()
        };

        let plan = options.ring_plan().unwrap();

        assert_eq!(page_size << plan.requested_exp, 1024 * 1024);
        assert!(page_size << plan.fallback_exp >= MAX_PERF_RECORD_BYTES);
        assert!(plan.fallback_exp <= plan.requested_exp);
        assert_eq!(
            u64::from(ring_wakeup_bytes(plan.requested_exp).unwrap()),
            (page_size << plan.requested_exp) / RING_WAKEUP_FRACTION
        );
    }

    #[test]
    fn ring_plan_rejects_a_budget_smaller_than_one_record() {
        let options = PerfOptions {
            stack_size: 32 * 1024,
            maximum_ring_bytes: crate::elf::system_page_size(),
            sample_callchain: true,
            ..PerfOptions::default()
        };

        assert_eq!(
            options.ring_plan().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn ring_mmap_fallback_steps_through_every_smaller_mapping() {
        let mut attempts = Vec::new();
        let (counter, ring) = open_ring_with_fallback(8, 5, Ok, |_, exp| {
            attempts.push(exp);
            if exp == 5 {
                Ok(exp)
            } else if exp % 2 == 0 {
                Err(io::Error::from_raw_os_error(libc::ENOMEM))
            } else {
                Err(io::Error::from_raw_os_error(libc::EPERM))
            }
        })
        .unwrap();
        assert_eq!((counter, ring, attempts), (5, 5, vec![8, 7, 6, 5]));
    }

    #[test]
    fn ring_mmap_fallback_stops_on_non_resource_errors() {
        let mut attempts = Vec::new();
        let error = open_ring_with_fallback(8, 5, Ok, |_, exp| {
            attempts.push(exp);
            Err::<u8, _>(io::Error::from_raw_os_error(libc::EIO))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(attempts, vec![8]);
    }

    #[test]
    fn ring_mmap_fallback_returns_resource_error_at_minimum() {
        let mut attempts = Vec::new();
        let error = open_ring_with_fallback(6, 4, Ok, |_, exp| {
            attempts.push(exp);
            Err::<u8, _>(io::Error::from_raw_os_error(libc::ENOMEM))
        })
        .unwrap_err();

        assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
        assert_eq!(attempts, vec![6, 5, 4]);
    }

    #[test]
    fn ring_mmap_fallback_does_not_retry_counter_open_errors() {
        let mut attempts = Vec::new();
        let error = open_ring_with_fallback(
            8,
            5,
            |exp| {
                attempts.push(exp);
                Err::<u8, _>(io::Error::from_raw_os_error(libc::EPERM))
            },
            |_, _| Ok(()),
        )
        .unwrap_err();

        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        assert_eq!(attempts, vec![8]);
    }

    #[test]
    fn ring_fallback_attempts_use_matching_wakeup_watermarks() {
        let options = PerfOptions {
            stack_size: 32 * 1024,
            ring_stacks: DEFAULT_RING_BUFFER_STACKS,
            ..PerfOptions::default()
        };
        let plan = options.ring_plan().unwrap();
        let mut attempts = Vec::new();
        let (_, selected) = open_ring_with_fallback(
            plan.requested_exp,
            plan.fallback_exp,
            |exp| {
                attempts.push((exp, ring_wakeup_bytes(exp)?));
                Ok(exp)
            },
            |_, exp| {
                if exp == plan.fallback_exp {
                    Ok(exp)
                } else {
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                }
            },
        )
        .unwrap();

        assert_eq!(selected, plan.fallback_exp);
        for (exp, watermark) in attempts {
            let capacity = crate::elf::system_page_size() << exp;
            assert_eq!(u64::from(watermark), capacity / RING_WAKEUP_FRACTION);
        }
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
        let options = PerfOptions::default();
        let plan = options.ring_plan().unwrap();
        let opts = options.perf_open_opts(ring_wakeup_bytes(plan.requested_exp).unwrap());
        assert!(opts.extra_record.mmap.code);
        assert!(!opts.extra_record.mmap.data);
        assert!(opts.stat_format.lost_records);
    }

    #[test]
    fn configured_record_layout_matches_the_unsafe_parser() {
        for (callchain, reg_mask, stack_size) in [
            (false, 0, 0),
            (true, 0, 0),
            (false, 0b10101, 8),
            (true, u64::MAX, MAX_SAMPLE_USER_STACK),
        ] {
            let options = PerfOptions {
                sample_callchain: callchain,
                reg_mask,
                stack_size,
                ..PerfOptions::default()
            };
            let plan = options.ring_plan().unwrap();
            let opts = options.perf_open_opts(ring_wakeup_bytes(plan.requested_exp).unwrap());
            let parser = options.record_parser();
            assert_eq!(
                parser.sample_type,
                sample_type_bits(
                    opts.sample_format.call_chain.is_some(),
                    opts.sample_format.user_regs.is_some(),
                    opts.sample_format.user_stack.is_some(),
                )
            );
            assert_eq!(parser.user_regs, reg_mask.count_ones() as usize);
            assert_eq!(
                parser.read_format & u64::from(sys::PERF_FORMAT_LOST),
                u64::from(sys::PERF_FORMAT_LOST)
            );
            assert!(parser.sample_id_all);
            assert!(opts.stat_format.lost_records);
            if let Some(callchain) = &opts.sample_format.call_chain {
                assert_eq!(callchain.max_stack_frames, 0);
            }
        }
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
            options
                .perf_open_opts(
                    ring_wakeup_bytes(options.ring_plan().unwrap().requested_exp).unwrap()
                )
                .sample_format
                .user_stack,
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
    fn bench_record_omits_empty_callchain_contexts() {
        let mut spec = stack_sample_spec(32);
        spec.user_frames = 0;
        let parser = stack_sample_parser(spec.user_regs);
        let record = build_bench_sample_record(&spec, 0);

        let (_, sample) =
            parse_sample_record(record.as_bytes(), &parser).expect("sample should parse");
        let mut callchain = sample.call_chain.expect("kernel callchain").iter();
        let Some(CallChainEntry::Kernel(addresses)) = callchain.next() else {
            panic!("first callchain context should be kernel");
        };

        assert_eq!(addresses.len(), 1);
        assert!(callchain.next().is_none());
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
    fn bench_batch_parses_sample_event() {
        let spec = stack_sample_spec(16);
        let batch = BenchSampleBatch::new(spec);

        let (privilege, sample) = batch.parse(&batch.records()[0]).expect("sample record");
        assert!(matches!(privilege, Priv::User));

        assert_eq!(sample.time, Some(1_700_000_000_000_000));
        let task = sample.task.expect("sample task");
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

    #[test]
    fn borrowed_sample_parser_matches_the_dependency_parser() {
        for (stack_bytes, dynamic_stack_bytes, user_frames) in [
            (0, 0, 0),
            (8, 0, 1),
            (8, 8, 4),
            (64, 7, 0),
            (512, 511, 8),
            (4096, 4096, 16),
        ] {
            let mut spec = stack_sample_spec(stack_bytes);
            spec.user_frames = user_frames;
            let parser = stack_sample_parser(spec.user_regs);
            let mut record = build_bench_sample_record(&spec, 3);
            if stack_bytes != 0 {
                set_dynamic_stack_size(&mut record, dynamic_stack_bytes);
            }

            let (borrowed_privilege, borrowed) =
                parse_sample_record(record.as_bytes(), &parser).expect("borrowed sample");
            let (owned_privilege, owned) =
                parse_aligned_event_record(record.as_bytes(), &parser).expect("owned sample");
            let Record::Sample(owned) = owned else {
                panic!("dependency parser did not return a sample");
            };

            assert_eq!(borrowed_privilege, owned_privilege);
            assert_eq!(borrowed.time, owned.record_id.time);
            assert_eq!(
                borrowed.task.map(|task| (task.pid, task.tid)),
                owned.record_id.task.map(|task| (task.pid, task.tid))
            );
            assert_eq!(borrowed.code_addr, owned.code_addr);
            assert_eq!(
                borrowed.user_regs,
                owned
                    .user_regs
                    .as_ref()
                    .map(|(registers, _)| registers.as_slice())
            );
            assert_eq!(borrowed.user_stack, owned.user_stack.as_deref());
            assert_eq!(
                borrowed
                    .call_chain
                    .map_or(SampleCallChain::None, SampleCallChain::Borrowed)
                    .to_stack_frames(),
                owned
                    .call_chain
                    .as_deref()
                    .map_or(SampleCallChain::None, SampleCallChain::Owned)
                    .to_stack_frames()
            );
        }
    }

    #[test]
    fn borrowed_sample_parser_handles_mutated_records_without_panicking() {
        let spec = stack_sample_spec(4096);
        let parser = stack_sample_parser(spec.user_regs);
        let original = build_bench_sample_record(&spec, 7);

        for index in 0..original.len() {
            let mut mutated = AlignedBytes::from_unaligned_bytes(original.as_bytes());
            mutated.as_mut_bytes()[index] ^= 0xff;
            let _ = parse_sample_record(mutated.as_bytes(), &parser);
        }
    }

    #[test]
    fn borrowed_parser_matches_dependency_across_generated_layouts() {
        let mut seed = 0xbb67_ae85_84ca_a73b_u64;
        for sample_index in 0..256 {
            seed = seed
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493);
            let stack_bytes = (((seed as usize) % 512) + 1) * 8;
            let dynamic_stack_bytes = ((seed >> 16) as usize) % (stack_bytes + 1);
            let mut spec = stack_sample_spec(stack_bytes);
            spec.user_frames = ((seed >> 32) as usize) % 33;
            spec.kernel_frames = ((seed >> 40) as usize) % 17;
            let parser = stack_sample_parser(spec.user_regs);
            let mut record = build_bench_sample_record(&spec, sample_index);
            set_dynamic_stack_size(&mut record, dynamic_stack_bytes as u64);

            let (_, borrowed) =
                parse_sample_record(record.as_bytes(), &parser).expect("borrowed sample");
            let (_, owned) =
                parse_aligned_event_record(record.as_bytes(), &parser).expect("owned sample");
            let Record::Sample(owned) = owned else {
                panic!("dependency parser did not return a sample");
            };
            assert_eq!(
                borrowed.user_regs,
                owned.user_regs.as_ref().map(|r| r.0.as_slice())
            );
            assert_eq!(borrowed.user_stack, owned.user_stack.as_deref());
            assert_eq!(
                borrowed
                    .call_chain
                    .map_or(SampleCallChain::None, SampleCallChain::Borrowed)
                    .to_stack_frames(),
                owned
                    .call_chain
                    .as_deref()
                    .map_or(SampleCallChain::None, SampleCallChain::Owned)
                    .to_stack_frames()
            );
        }
    }
}
