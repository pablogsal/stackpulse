use std::cmp::max;
use std::fmt;
use std::io;
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
use perf_event_open::sample::iter::Iter as PerfEventIter;
use perf_event_open::sample::rb::CowChunk;
use perf_event_open::sample::record::{Priv, Record, RecordId};
use perf_event_open::sample::Sampler;
use perf_event_open_sys::bindings as sys;

pub const MAX_SAMPLE_USER_STACK: u32 = 65_528;
/// Size of the perf metadata page that precedes the ring buffer in the mmap.
const META_PAGE: u32 = 4096;

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[derive(Debug)]
pub struct PerfFrequencyLimit {
    pub requested_frequency: u64,
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
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum TaskInheritance {
    #[default]
    None,
    Threads,
    Children,
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
        if self.cpu.is_none() && self.inherit != TaskInheritance::None {
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
                exclude_kernel: false,
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

    #[inline]
    pub fn iter(&self) -> EventIter<'_> {
        EventIter {
            iter: self.sampler.iter(),
        }
    }

    pub fn consume_events(&self, cb: &mut impl FnMut(EventRef<'_>)) {
        let mut iter = self.sampler.iter().into_cow();
        while iter
            .next(|chunk, parser| dispatch_event(chunk, parser, cb))
            .is_some()
        {}
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

#[derive(Clone, Copy)]
pub struct SampleRecordRef<'a> {
    pub task: Option<TaskRef>,
    pub time: Option<u64>,
    pub code_addr: Option<(u64, bool)>,
    pub user_regs: Option<RegsRef<'a>>,
    pub user_stack: Option<&'a [u8]>,
    pub call_chain: Option<CallChainRef<'a>>,
}

#[derive(Clone, Copy)]
pub struct TaskRef {
    pub pid: u32,
    pub tid: u32,
}

#[derive(Clone, Copy)]
pub enum RegsRef<'a> {
    Borrowed(&'a [u64]),
}

impl<'a> RegsRef<'a> {
    #[inline]
    pub fn as_slice(self) -> &'a [u64] {
        match self {
            Self::Borrowed(regs) => regs,
        }
    }
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

pub struct EventIter<'a> {
    iter: PerfEventIter<'a>,
}

impl Iterator for EventIter<'_> {
    type Item = EventRef<'static>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .map(|(privilege, record)| EventRef::new(privilege, record))
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

fn dispatch_event(
    chunk: CowChunk<'_>,
    parser: &perf_event_open::sample::record::Parser,
    cb: &mut impl FnMut(EventRef<'_>),
) {
    if let Some((privilege, sample)) = parse_sample_record(chunk.as_bytes(), parser.as_unsafe()) {
        cb(EventRef {
            privilege,
            timestamp: sample.time,
            record: EventRecord::Sample(sample),
        });
        return;
    }

    let (privilege, record) = parser.parse(chunk);
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
            sample.user_regs = Some(RegsRef::Borrowed(regs));
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
        sample.user_stack = Some(bytes.get(..dyn_len)?);
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

    #[test]
    fn ring_buffer_exp_keeps_space_for_queued_stack_samples() {
        assert_eq!(ring_buffer_page_exp(0).expect("page exp"), 5);
    }
}
