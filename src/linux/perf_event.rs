use std::cmp::max;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, RawFd};

use perf_event_open::config::{
    CallChain, Clock, Cpu, Inherit, OnExecve, Opts, Proc, RecordIdFormat, RegsMask, SampleOn, Size,
    UseBuildId,
};
use perf_event_open::count::Counter;
use perf_event_open::event::hw::Hardware;
use perf_event_open::event::sw::Software;
use perf_event_open::event::Event as PerfOpenEvent;
use perf_event_open::sample::iter::Iter as PerfEventIter;
use perf_event_open::sample::record::{Priv, Record, RecordId};
use perf_event_open::sample::Sampler;

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
}

pub struct EventRef {
    privilege: Priv,
    record: Record,
    timestamp: Option<u64>,
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
    fn new(privilege: Priv, record: Record) -> Self {
        let timestamp = record_timestamp(&record);
        Self {
            privilege,
            record,
            timestamp,
        }
    }

    pub fn timestamp(&self) -> Option<u64> {
        self.timestamp
    }

    pub fn into_parts(self) -> (Priv, Record) {
        (self.privilege, self.record)
    }
}

pub struct EventIter<'a> {
    iter: PerfEventIter<'a>,
}

impl Iterator for EventIter<'_> {
    type Item = EventRef;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_exp_keeps_space_for_queued_stack_samples() {
        assert_eq!(ring_buffer_page_exp(0).expect("page exp"), 5);
    }
}
