//! Record one program run and export a symbolized Firefox Profiler profile.
//!
//! Usage:
//!   cargo run --release --example gecko_profile -- [options] -- <program> [args...]
//!
//! Options:
//!   -o, --output PATH      Output profile, .json or .json.gz (default: stackpulse_gecko.json.gz)
//!       --spool PATH       Keep the intermediate stackpulse spool at PATH
//!       --frequency HZ     Sampling frequency (default: min(kernel limit, 999))
//!       --kernel           Include kernel frames when permitted

use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::write::GzEncoder;
use flate2::Compression;
use fxprof_processed_profile::{
    CategoryColor, CategoryPairHandle, CpuDelta, Frame, FrameFlags as FxFrameFlags, FrameInfo,
    ProcessHandle, Profile, ReferenceTimestamp, SamplingInterval, StringHandle, ThreadHandle,
    Timestamp,
};
use stackpulse::process::SuspendedLaunchedProcess;
use stackpulse::{
    AttachMode, FrameFlags, FrameKind, PerfRecorder, PerfRecorderOptions, PerfSpoolReader,
    PerfSummary, PerfSymbolizer, ResolvedFrame,
};

const DEFAULT_OUTPUT: &str = "stackpulse_gecko.json.gz";
const STACK_SIZE: u32 = stackpulse::MAX_SAMPLE_USER_STACK;
const TRUNCATED_STACK_LABEL: &str = "[truncated stack]";
const UNKNOWN_NATIVE_LABEL: &str = "[unknown native frame]";
const POST_EXIT_QUIET_DRAINS: usize = 3;

#[derive(Debug)]
struct Options {
    output: PathBuf,
    spool: Option<PathBuf>,
    frequency: u32,
    include_kernel: bool,
    command: OsString,
    command_args: Vec<OsString>,
}

#[derive(Clone, Copy)]
struct Categories {
    python: CategoryPairHandle,
    native: CategoryPairHandle,
    kernel: CategoryPairHandle,
    other: CategoryPairHandle,
}

struct ThreadState {
    handle: ThreadHandle,
    last_sample_timestamp_ns: Option<u64>,
}

struct ExportState {
    main_pid: i32,
    product: String,
    processes: HashMap<i32, ProcessHandle>,
    threads: HashMap<(i32, u64), ThreadState>,
    kernel_module_labels: HashMap<KernelModuleLabelKey, StringHandle>,
}

enum GeckoFrame {
    Resolved(ResolvedFrame),
    TruncatedStack,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct KernelModuleLabelKey {
    name: Rc<str>,
    module: Rc<str>,
    module_basename_start: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(options) = parse_options().map_err(invalid_input)? else {
        print_usage();
        return Ok(());
    };
    if options.frequency == 0 {
        return Err(invalid_input("frequency must be greater than zero").into());
    }

    let product = command_display_name(&options.command);
    let started_at = SystemTime::now();
    let started_at_us = started_at.duration_since(UNIX_EPOCH)?.as_micros() as u64;

    let suspended = SuspendedLaunchedProcess::launch_in_suspended_state(
        options.command.as_os_str(),
        &options.command_args,
        &[],
    )?;
    let pid = suspended.pid();
    let pid_i32 = i32::try_from(pid).map_err(|_| invalid_input("child pid does not fit i32"))?;
    let spool = options.spool.clone().unwrap_or_else(|| {
        env::temp_dir().join(format!(
            "stackpulse-gecko-{}-{pid}.spool",
            std::process::id()
        ))
    });

    let summary = record_until_exit(&options, &spool, suspended, started_at_us)?;
    let reader = PerfSpoolReader::open(&spool)?;
    let profile = build_profile(&reader, &product, pid_i32, started_at, options.frequency)?;
    write_profile(&profile, &options.output)?;

    if options.spool.is_none() {
        let _ = std::fs::remove_file(&spool);
    }

    println!(
        "wrote {} (samples={}, lost={}, kernel={}, truncated={})",
        options.output.display(),
        summary.samples,
        summary.lost_events,
        if summary.kernel_enabled { "on" } else { "off" },
        summary.truncated_frame_markers,
    );
    for (kind, count) in summary.error_stats.iter_nonzero() {
        eprintln!("  err {:?}: {}", kind, count);
    }
    Ok(())
}

fn record_until_exit(
    options: &Options,
    spool: &Path,
    suspended: SuspendedLaunchedProcess,
    started_at_us: u64,
) -> Result<PerfSummary, Box<dyn std::error::Error>> {
    let pid = suspended.pid();
    let pid_i32 = i32::try_from(pid).map_err(|_| invalid_input("child pid does not fit i32"))?;
    let mut recorder = PerfRecorder::attach(
        pid,
        spool,
        AttachMode::AttachWithEnableOnExec,
        PerfRecorderOptions {
            frequency: options.frequency,
            stack_size: STACK_SIZE,
            include_kernel: options.include_kernel,
            inherit_child_processes: true,
            start_timestamp_us: started_at_us,
            sample_interval_us: (1_000_000 / u64::from(options.frequency)).max(1),
        },
    )?;

    let running = suspended.unsuspend_and_run()?;
    let mut main_exited = false;
    let mut quiet_drains_after_exit = 0;
    loop {
        if !recorder.has_pending_events() {
            recorder.wait()?;
        }
        recorder.consume_available()?;
        if !main_exited {
            main_exited = running.try_wait()?.is_some();
        }
        if !main_exited {
            continue;
        }

        if recorder.has_active_processes_except(pid_i32) || recorder.has_pending_events() {
            quiet_drains_after_exit = 0;
        } else if quiet_drains_after_exit + 1 >= POST_EXIT_QUIET_DRAINS {
            break;
        } else {
            quiet_drains_after_exit += 1;
        }
    }

    recorder.finish().map_err(Into::into)
}

fn build_profile(
    reader: &PerfSpoolReader,
    product: &str,
    main_pid: i32,
    started_at: SystemTime,
    frequency: u32,
) -> Result<Profile, Box<dyn std::error::Error>> {
    let mut profile = Profile::new(
        product,
        ReferenceTimestamp::from_system_time(started_at),
        SamplingInterval::from_hz(frequency as f32),
    );
    profile.set_os_name("Linux");
    profile.set_symbolicated(true);

    let categories = Categories::new(&mut profile);
    let first_sample_ns = reader.samples().first().map_or(0, |s| s.timestamp_ns);
    let mut state = ExportState::new(main_pid, product.to_string());
    state.ensure_thread(
        &mut profile,
        main_pid,
        u64::try_from(main_pid).unwrap_or_default(),
        0,
    );

    let mut symbolizer = PerfSymbolizer::for_spool(reader);
    for stack in reader.sample_stacks() {
        let sample = stack.sample;
        let timestamp_ns = sample.timestamp_ns.saturating_sub(first_sample_ns);
        let timestamp = Timestamp::from_nanos_since_reference(timestamp_ns);
        let (thread, cpu_delta) = {
            let thread = state.ensure_thread(
                &mut profile,
                sample.process_id,
                sample.thread_id,
                timestamp_ns,
            );
            let cpu_delta = thread
                .last_sample_timestamp_ns
                .map_or(CpuDelta::ZERO, |previous| {
                    CpuDelta::from_nanos(sample.timestamp_ns.saturating_sub(previous))
                });
            thread.last_sample_timestamp_ns = Some(sample.timestamp_ns);
            (thread.handle, cpu_delta)
        };

        let mut frames = Vec::new();
        symbolizer.for_each_sample_stack(stack, |frame| {
            if matches!(
                frame,
                ResolvedFrame::Native(native)
                    if native.flags.contains(FrameFlags::TRUNCATED_STACK)
            ) {
                frames.push(GeckoFrame::TruncatedStack);
            } else {
                frames.push(GeckoFrame::Resolved(frame.clone()));
            }
        });
        let stack = stack_handle_for_frames(
            &mut profile,
            thread,
            &frames,
            categories,
            &mut state.kernel_module_labels,
        );
        profile.add_sample(thread, timestamp, stack, cpu_delta, 1);
    }

    Ok(profile)
}

impl Categories {
    fn new(profile: &mut Profile) -> Self {
        Self {
            python: profile.add_category("Python", CategoryColor::Green).into(),
            native: profile.add_category("Native", CategoryColor::Blue).into(),
            kernel: profile.add_category("Kernel", CategoryColor::Orange).into(),
            other: fxprof_processed_profile::CategoryHandle::OTHER.into(),
        }
    }
}

impl ExportState {
    fn new(main_pid: i32, product: String) -> Self {
        Self {
            main_pid,
            product,
            processes: HashMap::new(),
            threads: HashMap::new(),
            kernel_module_labels: HashMap::new(),
        }
    }

    fn ensure_process(
        &mut self,
        profile: &mut Profile,
        pid: i32,
        timestamp_ns: u64,
    ) -> ProcessHandle {
        match self.processes.entry(pid) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let name = if pid == self.main_pid {
                    self.product.clone()
                } else {
                    format!("process {pid}")
                };
                let pid_u32 = u32::try_from(pid).unwrap_or_default();
                let handle = profile.add_process(
                    &name,
                    pid_u32,
                    Timestamp::from_nanos_since_reference(timestamp_ns),
                );
                entry.insert(handle);
                handle
            }
        }
    }

    fn ensure_thread(
        &mut self,
        profile: &mut Profile,
        pid: i32,
        tid: u64,
        timestamp_ns: u64,
    ) -> &mut ThreadState {
        if self.threads.contains_key(&(pid, tid)) {
            return self.threads.get_mut(&(pid, tid)).unwrap();
        }

        let process = self.ensure_process(profile, pid, timestamp_ns);
        let tid_u32 = u32::try_from(tid).unwrap_or(u32::MAX);
        let is_main = u64::try_from(pid).ok() == Some(tid);
        let handle = profile.add_thread(
            process,
            tid_u32,
            Timestamp::from_nanos_since_reference(timestamp_ns),
            is_main,
        );
        if !is_main {
            profile.set_thread_name(handle, &format!("Thread {tid}"));
        }
        profile.add_initial_visible_thread(handle);
        if self.threads.is_empty() {
            profile.add_initial_selected_thread(handle);
        }
        self.threads.insert(
            (pid, tid),
            ThreadState {
                handle,
                last_sample_timestamp_ns: None,
            },
        );
        self.threads.get_mut(&(pid, tid)).unwrap()
    }
}

fn stack_handle_for_frames(
    profile: &mut Profile,
    thread: ThreadHandle,
    frames: &[GeckoFrame],
    categories: Categories,
    kernel_module_labels: &mut HashMap<KernelModuleLabelKey, StringHandle>,
) -> Option<fxprof_processed_profile::StackHandle> {
    let frame_infos: Vec<_> = frames
        .iter()
        .rev()
        .map(|frame| {
            frame_info_for_resolved_frame(profile, frame, categories, kernel_module_labels)
        })
        .collect();
    profile.intern_stack_frames(thread, frame_infos.into_iter())
}

fn frame_info_for_resolved_frame(
    profile: &mut Profile,
    frame: &GeckoFrame,
    categories: Categories,
    kernel_module_labels: &mut HashMap<KernelModuleLabelKey, StringHandle>,
) -> FrameInfo {
    let category_pair = category_for_frame(frame, categories);
    let label = intern_label_for_frame(profile, frame, kernel_module_labels);
    FrameInfo {
        frame: Frame::Label(label),
        category_pair,
        flags: FxFrameFlags::empty(),
    }
}

fn category_for_frame(frame: &GeckoFrame, categories: Categories) -> CategoryPairHandle {
    if is_python_frame(frame) {
        return categories.python;
    }
    match frame {
        GeckoFrame::TruncatedStack => categories.other,
        GeckoFrame::Resolved(ResolvedFrame::Native(frame)) => match frame.kind {
            FrameKind::Python => categories.python,
            FrameKind::Native => categories.native,
            FrameKind::Kernel => categories.kernel,
            FrameKind::Unknown => categories.other,
            _ => categories.other,
        },
        GeckoFrame::Resolved(ResolvedFrame::Python(_)) => categories.python,
    }
}

fn is_python_frame(frame: &GeckoFrame) -> bool {
    match frame {
        GeckoFrame::Resolved(ResolvedFrame::Python(_)) => true,
        GeckoFrame::Resolved(ResolvedFrame::Native(frame)) => frame.kind == FrameKind::Python,
        GeckoFrame::TruncatedStack => false,
    }
}

fn intern_label_for_frame(
    profile: &mut Profile,
    frame: &GeckoFrame,
    kernel_module_labels: &mut HashMap<KernelModuleLabelKey, StringHandle>,
) -> StringHandle {
    let label = match frame {
        GeckoFrame::Resolved(ResolvedFrame::Native(frame)) => {
            let Some(symbol) = frame.symbol.as_ref() else {
                return profile.intern_string(UNKNOWN_NATIVE_LABEL);
            };
            let name = symbol.name.as_ref();
            let module = &symbol.module[symbol.module_basename_start..];
            if is_addressish_symbol_name(name, module) {
                Cow::Owned(format!("[unknown native frame in {module}]"))
            } else if frame.kind == FrameKind::Kernel && module != "[kernel]" {
                let key = KernelModuleLabelKey {
                    name: Rc::clone(&symbol.name),
                    module: Rc::clone(&symbol.module),
                    module_basename_start: symbol.module_basename_start,
                };
                return match kernel_module_labels.entry(key) {
                    Entry::Occupied(entry) => *entry.get(),
                    Entry::Vacant(entry) => {
                        let handle = profile.intern_string(&format!("{name} {module}"));
                        entry.insert(handle);
                        handle
                    }
                };
            } else {
                Cow::Borrowed(name)
            }
        }
        _ => label_for_frame(frame),
    };
    profile.intern_string(&label)
}

fn label_for_frame(frame: &GeckoFrame) -> Cow<'_, str> {
    match frame {
        GeckoFrame::TruncatedStack => Cow::Borrowed(TRUNCATED_STACK_LABEL),
        GeckoFrame::Resolved(ResolvedFrame::Python(frame)) => {
            if frame.file_name.is_empty() {
                Cow::Borrowed(frame.func_name.as_ref())
            } else {
                Cow::Owned(format!("{}:{}", frame.func_name, frame.file_name))
            }
        }
        GeckoFrame::Resolved(ResolvedFrame::Native(frame)) => {
            let Some(symbol) = frame.symbol.as_ref() else {
                return Cow::Borrowed(UNKNOWN_NATIVE_LABEL);
            };
            let name = symbol.name.as_ref();
            let module = &symbol.module[symbol.module_basename_start..];
            if is_addressish_symbol_name(name, module) {
                return Cow::Owned(format!("[unknown native frame in {module}]"));
            }
            if frame.kind == FrameKind::Kernel && module != "[kernel]" {
                return Cow::Owned(format!("{name} {module}"));
            }
            Cow::Borrowed(name)
        }
    }
}

fn is_addressish_symbol_name(name: &str, module: &str) -> bool {
    name.starts_with("0x")
        || name.starts_with("<0x")
        || name
            .strip_prefix(module)
            .is_some_and(|suffix| suffix.starts_with("+0x"))
}

fn write_profile(profile: &Profile, output: &Path) -> io::Result<()> {
    let file = File::create(output)?;
    let writer = BufWriter::new(file);
    if output.extension() == Some(OsStr::new("gz")) {
        let mut gz = GzEncoder::new(writer, Compression::new(2));
        serde_json::to_writer(&mut gz, profile).map_err(io::Error::other)?;
        gz.finish()?;
    } else {
        serde_json::to_writer(writer, profile).map_err(io::Error::other)?;
    }
    Ok(())
}

fn parse_options() -> Result<Option<Options>, String> {
    let mut output = PathBuf::from(DEFAULT_OUTPUT);
    let mut spool = None;
    let mut frequency = default_frequency();
    let mut include_kernel = false;
    let mut args = env::args_os().skip(1);
    let mut command = None;
    let mut command_args = Vec::new();

    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-h" | "--help") => return Ok(None),
            Some("-o" | "--output") => {
                output = args.next().ok_or("missing value for --output")?.into();
            }
            Some("--spool") => {
                spool = Some(args.next().ok_or("missing value for --spool")?.into());
            }
            Some("--frequency") => {
                frequency = parse_u32(args.next().ok_or("missing value for --frequency")?)?;
            }
            Some("--kernel") => include_kernel = true,
            Some("--") => {
                command = Some(args.next().ok_or("missing command after --")?);
                command_args.extend(args);
                break;
            }
            Some(value) if value.starts_with('-') => {
                return Err(format!("unknown option {value}"));
            }
            _ => {
                command = Some(arg);
                command_args.extend(args);
                break;
            }
        }
    }

    let command = command.ok_or("missing command to profile")?;
    Ok(Some(Options {
        output,
        spool,
        frequency,
        include_kernel,
        command,
        command_args,
    }))
}

fn parse_u32(value: OsString) -> Result<u32, String> {
    let value = value.to_str().ok_or("option value must be valid UTF-8")?;
    value
        .parse()
        .map_err(|_| format!("expected unsigned integer, got {value:?}"))
}

fn default_frequency() -> u32 {
    stackpulse::max_sample_rate()
        .and_then(|limit| u32::try_from(limit.min(999)).ok())
        .filter(|&limit| limit > 0)
        .unwrap_or(999)
}

fn command_display_name(command: &OsStr) -> String {
    let path = Path::new(command);
    path.file_name()
        .unwrap_or(command)
        .to_string_lossy()
        .into_owned()
}

fn print_usage() {
    eprintln!(
        "usage: cargo run --release --example gecko_profile -- [options] -- <program> [args...]"
    );
    eprintln!("  -o, --output PATH      output .json or .json.gz profile");
    eprintln!("      --spool PATH       keep intermediate stackpulse spool at PATH");
    eprintln!("      --frequency HZ     sampling frequency");
    eprintln!("      --kernel           include kernel frames when permitted");
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stackpulse::{LocationInfo, PythonFrame};

    #[test]
    fn python_frames_are_not_javascript() {
        let mut profile = Profile::new(
            "test",
            ReferenceTimestamp::from_millis_since_unix_epoch(0.0),
            SamplingInterval::from_hz(1.0),
        );
        let categories = Categories::new(&mut profile);
        let frame = GeckoFrame::Resolved(ResolvedFrame::Python(PythonFrame::new(
            "example.py",
            LocationInfo::default(),
            "work",
            None,
            true,
        )));
        let mut kernel_module_labels = HashMap::new();
        let frame_info = frame_info_for_resolved_frame(
            &mut profile,
            &frame,
            categories,
            &mut kernel_module_labels,
        );

        assert_eq!(frame_info.flags, FxFrameFlags::empty());
    }
}
