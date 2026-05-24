//! Tiny text-based profiler with a human-readable, colored output.
//!
//! Usage:
//!   cargo run --example mini_profile -- <pid> [seconds]
//!
//! Honors NO_COLOR. Hides Python runtime machinery (frames flagged
//! HIDDEN_DEFAULT) so user-visible call stacks stay readable.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::env;
use std::io::{self, IsTerminal};
use std::time::{Duration, Instant};

use stackpulse::{
    AttachMode, ErrorStatsFormatter, FrameFlags, FrameKind, PerfRecorder, PerfRecorderOptions,
    PerfSpoolReader, PerfSymbolizer, ResolvedFrame, SymbolOrigin,
};

const TOP_FUNCS: usize = 10;
const TOP_STACKS: usize = 6;

// --- Colors --------------------------------------------------------------

#[derive(Clone, Copy)]
struct C(bool);

impl C {
    fn detect() -> Self {
        Self(io::stdout().is_terminal() && env::var_os("NO_COLOR").is_none())
    }
    fn wrap(self, code: &str, s: &str) -> String {
        if self.0 {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn bold(self, s: &str) -> String {
        self.wrap("1", s)
    }
    fn dim(self, s: &str) -> String {
        self.wrap("2", s)
    }
    fn red(self, s: &str) -> String {
        self.wrap("31", s)
    }
    fn green(self, s: &str) -> String {
        self.wrap("32", s)
    }
    fn yellow(self, s: &str) -> String {
        self.wrap("33", s)
    }
    fn blue(self, s: &str) -> String {
        self.wrap("34", s)
    }
    fn magenta(self, s: &str) -> String {
        self.wrap("35", s)
    }
    fn cyan(self, s: &str) -> String {
        self.wrap("36", s)
    }

    /// Pad to `width` first, then colour-wrap. Width is measured on the
    /// plain string, so columns line up correctly even when ANSI escapes
    /// would otherwise inflate the byte length seen by `{:<N}`.
    fn dim_pad(self, key: &str, width: usize) -> String {
        self.dim(&format!("{key:<width$}"))
    }
    fn bold_rpad(self, key: &str, width: usize) -> String {
        self.bold(&format!("{key:>width$}"))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Python,
    Native,
    Kernel,
    Unknown,
}

fn classify(frame: &ResolvedFrame) -> Kind {
    match frame {
        ResolvedFrame::Python(_) => Kind::Python,
        ResolvedFrame::Native(n) => match n.kind {
            FrameKind::Python => Kind::Python,
            FrameKind::Native => Kind::Native,
            FrameKind::Kernel => Kind::Kernel,
            FrameKind::Unknown => Kind::Unknown,
        },
    }
}

fn paint(c: C, kind: Kind, text: &str) -> String {
    match kind {
        Kind::Python => c.green(text),
        Kind::Native => text.to_string(),
        Kind::Kernel => c.magenta(text),
        Kind::Unknown => c.dim(text),
    }
}

fn kind_tag(c: C, kind: Kind) -> String {
    match kind {
        Kind::Python => c.green("py"),
        Kind::Native => c.dim("native"),
        Kind::Kernel => c.magenta("kernel"),
        Kind::Unknown => c.dim("?"),
    }
}

fn is_hidden(frame: &ResolvedFrame) -> bool {
    match frame {
        ResolvedFrame::Native(n) => n.flags.contains(FrameFlags::HIDDEN_DEFAULT),
        _ => false,
    }
}

/// kptr_restrict ≥ 1 zeroes out the addresses in /proc/kallsyms for
/// unprivileged readers, which makes kernel symbolization impossible
/// (every name is then "_text+0xffff...").
fn kallsyms_addresses_visible() -> bool {
    use std::io::BufRead;
    let Ok(file) = std::fs::File::open("/proc/kallsyms") else {
        return false;
    };
    for line in std::io::BufReader::new(file).lines().take(64).flatten() {
        if let Some(addr) = line.split_whitespace().next() {
            if u64::from_str_radix(addr, 16).unwrap_or(0) != 0 {
                return true;
            }
        }
    }
    false
}

fn read_sysctl_i64(path: &str) -> Option<i64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn read_link(path: &str) -> Option<String> {
    std::fs::read_link(path)
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
}

fn read_cmdline(pid: u32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let s: Vec<String> = raw
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    if s.is_empty() {
        None
    } else {
        Some(s.join(" "))
    }
}

fn target_has_python_perf_env(pid: u32) -> bool {
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/environ")) else {
        return false;
    };
    raw.split(|b| *b == 0).any(|kv| {
        let s = String::from_utf8_lossy(kv);
        s.starts_with("PYTHONPERFSUPPORT=1") || s.starts_with("PYTHONPERFJITSUPPORT=1")
    })
}

fn paranoid_explain(v: i64) -> &'static str {
    match v {
        x if x <= -1 => "all events permitted",
        0 => "user + kernel allowed",
        1 => "no CPU events for unprivileged",
        2 => "no kernel profiling for unprivileged",
        _ => "restricted",
    }
}

// --- Main ----------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let c = C::detect();

    let mut args = env::args().skip(1);
    let pid: u32 = args
        .next()
        .ok_or("usage: mini_profile <pid> [seconds]")?
        .parse()?;
    let seconds: u64 = args.next().map(|s| s.parse()).transpose()?.unwrap_or(5);

    let spool = "mini_profile.spool";

    // 999 Hz is plenty for a human-readable summary. Cap to the kernel max if
    // it's lower (sample writer can choke at very high rates with kernel on).
    let kernel_cap = stackpulse::max_sample_rate().unwrap_or(999);
    let frequency = kernel_cap.min(999) as u32;
    if frequency == 0 {
        return Err(format!(
            "kernel max_sample_rate is 0 (perf sampling is disabled on this host). \
             Raise /proc/sys/kernel/perf_event_max_sample_rate.",
        )
        .into());
    }

    let mut recorder = PerfRecorder::attach(
        pid,
        spool,
        AttachMode::StopAttachEnableResume,
        PerfRecorderOptions {
            frequency,
            stack_size: 32 * 1024,
            include_kernel: true,
            ..Default::default()
        },
    )?;
    let kernel_on = recorder.summary().kernel_enabled;
    let kallsyms_visible = kallsyms_addresses_visible();

    // Snapshot environment for the report later.
    let paranoid = read_sysctl_i64("/proc/sys/kernel/perf_event_paranoid");
    let kptr = read_sysctl_i64("/proc/sys/kernel/kptr_restrict");
    let exe = read_link(&format!("/proc/{pid}/exe")).unwrap_or_else(|| "?".to_string());
    let cmdline = read_cmdline(pid).unwrap_or_else(|| "?".to_string());
    let pypef = target_has_python_perf_env(pid);

    let live = io::stderr().is_terminal() && c.0;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let total_ms = (seconds * 1000) as f64;
    let spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let mut tick = 0usize;
    let mut last_redraw = Instant::now() - Duration::from_secs(1);
    let mut last_sample_count: u64 = 0;
    let mut last_sample_time = started;

    if !live {
        eprintln!(
            "{}",
            c.dim(&format!("recording pid={pid} for {seconds}s..."))
        );
    }

    // `recorder.wait()` blocks for up to ~100ms internally, so only sleep on it
    // when there's still meaningful time before the deadline. Otherwise just do
    // a final drain and exit promptly.
    let wait_slack = Duration::from_millis(100);

    while Instant::now() + wait_slack < deadline && recorder.process_is_active(pid as i32) {
        recorder.wait()?;
        recorder.consume_available()?;

        if live && last_redraw.elapsed() >= Duration::from_millis(120) {
            let now = Instant::now();
            let elapsed_ms = (now - started).as_millis() as f64;
            let pct = (elapsed_ms / total_ms).min(1.0);
            let s = recorder.summary();

            // bar
            let width = 24;
            let filled = (pct * width as f64).round() as usize;
            let bar = format!(
                "{}{}",
                c.green(&"█".repeat(filled)),
                c.dim(&"·".repeat(width - filled)),
            );

            // samples/sec since last redraw
            let dt = (now - last_sample_time).as_secs_f64().max(0.001);
            let rate = (s.samples.saturating_sub(last_sample_count)) as f64 / dt;
            last_sample_count = s.samples;
            last_sample_time = now;

            let lost_str = if s.lost_events > 0 {
                c.red(&format!("lost {}", s.lost_events))
            } else {
                c.dim("lost 0")
            };

            eprint!(
                "\r\x1b[K  {} {}  {}  {} samples  {}  {}",
                c.cyan(&spinner[tick % spinner.len()].to_string()),
                bar,
                c.yellow(&format!("{:>3.0}%", pct * 100.0)),
                c.bold(&s.samples.to_string()),
                c.dim(&format!("{rate:>5.0}/s")),
                lost_str,
            );
            let _ = io::Write::flush(&mut io::stderr());
            tick += 1;
            last_redraw = now;
        }
    }
    // Final drain — perf records may have landed after the loop's last
    // `consume_available`. `finish()` flushes the spool but does not drain.
    recorder.consume_available()?;

    if live {
        eprint!("\r\x1b[K");
        let _ = io::Write::flush(&mut io::stderr());
    }
    let summary = recorder.finish()?;

    // Aggregate.
    let reader = PerfSpoolReader::open(spool)?;
    let mut symbolizer = PerfSymbolizer::for_spool(&reader);

    let mut leaf_counts: HashMap<(String, Kind), u64> = HashMap::new();
    let mut stack_counts: HashMap<Vec<(String, Kind)>, u64> = HashMap::new();
    let mut total: u64 = 0;
    let mut origin_counts: HashMap<&'static str, u64> = HashMap::new();
    let mut total_frames: u64 = 0;

    for sample in reader.samples() {
        let raw = reader.stack_frame_refs(sample.stack_id)?;
        let frames =
            symbolizer.stack_refs_to_cached_frames(sample.process_id, sample.stack_id, raw);

        for f in frames.iter() {
            total_frames += 1;
            let origin = match f {
                ResolvedFrame::Python(_) => "perfmap",
                ResolvedFrame::Native(n) => match n.origin {
                    SymbolOrigin::Elf => "elf",
                    SymbolOrigin::PerfMap => "perfmap",
                    SymbolOrigin::KernelSymbols => "kallsyms",
                    SymbolOrigin::AddressOnly => "address-only",
                },
            };
            *origin_counts.entry(origin).or_default() += 1;
        }

        // root → leaf, with runtime machinery filtered out, consecutive dups collapsed.
        let mut visible: Vec<(String, Kind)> = frames
            .iter()
            .rev()
            .filter(|f| !is_hidden(f))
            .map(|f| (f.func_name(), classify(f)))
            .collect();
        visible.dedup_by(|a, b| a.0 == b.0);

        if visible.is_empty() {
            continue;
        }
        total += 1;
        if let Some(leaf) = visible.last().cloned() {
            *leaf_counts.entry(leaf).or_default() += 1;
        }
        *stack_counts.entry(visible).or_default() += 1;
    }

    // --- Header ---
    println!();
    println!(
        "{}",
        c.bold(&c.cyan("┌─ stackpulse · mini profile ──────────────────────────"))
    );
    println!(
        "  {}  pid={}  duration={}s  freq={}Hz  kernel={}",
        c.dim("recording"),
        c.bold(&pid.to_string()),
        seconds,
        c.bold(&frequency.to_string()),
        if kernel_on {
            c.green("on")
        } else {
            c.red("off")
        },
    );
    println!(
        "  {}  samples={}  shown={}  lost={}  empty={}",
        c.dim("counters"),
        c.bold(&summary.samples.to_string()),
        c.bold(&total.to_string()),
        if summary.lost_events > 0 {
            c.red(&summary.lost_events.to_string())
        } else {
            c.bold("0")
        },
        c.bold(&summary.empty_stack_samples.to_string()),
    );
    println!(
        "{}",
        c.bold(&c.cyan("└──────────────────────────────────────────────────────"))
    );

    // --- Environment block ---
    println!("\n{}", c.bold(&c.cyan("▌ Environment")));
    println!("  {} {}", c.dim_pad("exe", 14), exe);
    let cmd_short: String = cmdline
        .lines()
        .next()
        .unwrap_or(&cmdline)
        .chars()
        .take(80)
        .collect();
    println!("  {} {}", c.dim_pad("cmdline", 14), c.dim(&cmd_short));
    println!(
        "  {} {} ({})",
        c.dim_pad("paranoid", 14),
        c.bold(&paranoid.map_or("?".into(), |v| v.to_string())),
        paranoid.map_or("unknown".into(), |v| paranoid_explain(v).to_string()),
    );
    println!(
        "  {} {} {}",
        c.dim_pad("kptr_restrict", 14),
        c.bold(&kptr.map_or("?".into(), |v| v.to_string())),
        if kallsyms_visible {
            c.green("(kallsyms addresses visible)")
        } else {
            c.red("(kallsyms addresses hidden)")
        },
    );
    println!(
        "  {} {} (kernel cap: {})",
        c.dim_pad("frequency", 14),
        c.bold(&format!("{frequency} Hz")),
        kernel_cap,
    );
    println!(
        "  {} {}",
        c.dim_pad("python perf", 14),
        if pypef {
            c.green("PYTHONPERFSUPPORT=1 in target env")
        } else {
            c.dim("env var not set — Python frames may be missing")
        },
    );

    if total == 0 {
        println!("\n{}", c.yellow("no samples collected"));
        return Ok(());
    }

    // --- Top hot functions ---
    println!("\n{}", c.bold(&c.cyan("▌ Hot functions (leaf, self time)")));
    let mut hot: Vec<_> = leaf_counts.into_iter().collect();
    hot.sort_by_key(|row| Reverse(row.1));
    let max_hot = hot.first().map(|(_, n)| *n).unwrap_or(1).max(1);

    for ((name, kind), count) in hot.iter().take(TOP_FUNCS) {
        let pct = (*count as f64 / total as f64) * 100.0;
        let bar_width = ((*count as f64 / max_hot as f64) * 20.0).round() as usize;
        let bar = "█".repeat(bar_width);
        let pad = " ".repeat(20 - bar_width);
        println!(
            "  {}  {}  {}{}  {}",
            c.bold_rpad(&count.to_string(), 4),
            c.yellow(&format!("{pct:>5.1}%")),
            c.blue(&bar),
            pad,
            paint(c, *kind, name),
        );
    }

    // --- Top stacks (vertical) ---
    println!(
        "\n{}",
        c.bold(&c.cyan("▌ Hot stacks (call chains, runtime hidden)"))
    );
    let mut stacks: Vec<_> = stack_counts.into_iter().collect();
    stacks.sort_by_key(|row| Reverse(row.1));

    for (idx, (frames, count)) in stacks.iter().take(TOP_STACKS).enumerate() {
        let pct = (*count as f64 / total as f64) * 100.0;
        println!();
        println!(
            "  {} {} samples  {}",
            c.bold(&c.cyan(&format!("#{}", idx + 1))),
            c.bold(&count.to_string()),
            c.yellow(&format!("({pct:.1}%)")),
        );
        for (depth, (name, kind)) in frames.iter().enumerate() {
            let is_leaf = depth + 1 == frames.len();
            let arrow = if depth == 0 {
                c.dim("●")
            } else if is_leaf {
                c.dim("└")
            } else {
                c.dim("├")
            };
            println!(
                "    {arrow}  {}  {}",
                paint(c, *kind, name),
                c.dim(&format!("[{}]", kind_tag(c, *kind))),
            );
        }
    }

    // --- Diagnostics ---
    println!("\n{}", c.bold(&c.cyan("▌ Diagnostics")));

    // Sample disposition.
    let written = summary.samples;
    let raw_events = summary.sample_events;
    println!(
        "  {} raw={}  written={}  shown={}  empty={}  lost={}",
        c.dim_pad("sample disposition", 22),
        c.bold(&raw_events.to_string()),
        c.bold(&written.to_string()),
        c.bold(&total.to_string()),
        c.bold(&summary.empty_stack_samples.to_string()),
        if summary.lost_events > 0 {
            c.red(&summary.lost_events.to_string())
        } else {
            c.bold("0")
        },
    );

    // Skip-counter detail (only show non-zero).
    let skips: &[(&str, u64)] = &[
        ("missing_pid", summary.missing_pid_samples),
        ("missing_tid", summary.missing_tid_samples),
        ("idle_tid", summary.idle_tid_samples),
        ("missing_ts", summary.missing_timestamp_samples),
        ("truncated", summary.truncated_frame_markers),
        (
            "user_callchain_ignored",
            summary.ignored_user_callchain_frames,
        ),
    ];
    let nonzero: Vec<_> = skips.iter().filter(|(_, n)| *n > 0).collect();
    if !nonzero.is_empty() {
        let parts: Vec<String> = nonzero
            .iter()
            .map(|(k, v)| format!("{k}={}", c.bold(&v.to_string())))
            .collect();
        println!("  {} {}", c.dim_pad("skip counters", 22), parts.join("  "));
    }

    // Resolution breakdown by SymbolOrigin.
    if total_frames > 0 {
        let mut origins: Vec<_> = origin_counts.iter().collect();
        origins.sort_by_key(|(_, n)| Reverse(**n));
        let parts: Vec<String> = origins
            .iter()
            .map(|(k, v)| {
                let pct = (**v as f64 / total_frames as f64) * 100.0;
                let coloured = match **k {
                    "elf" => c.green(&format!("{k} {pct:.0}%")),
                    "kallsyms" => c.magenta(&format!("{k} {pct:.0}%")),
                    "perfmap" => c.green(&format!("{k} {pct:.0}%")),
                    "address-only" => c.red(&format!("{k} {pct:.0}%")),
                    _ => format!("{k} {pct:.0}%"),
                };
                format!("{coloured} ({v})")
            })
            .collect();
        println!(
            "  {} {} frames · {}",
            c.dim_pad("symbol resolution", 22),
            c.bold(&total_frames.to_string()),
            parts.join("  "),
        );
    }

    // Module / exec counts.
    println!(
        "  {} modules={}  exec markers={}",
        c.dim_pad("recording state", 22),
        c.bold(&reader.modules().len().to_string()),
        c.bold(&reader.process_execs().len().to_string()),
    );

    // SampleErrorStats detail.
    if summary.error_stats.has_errors() {
        let mut report = String::new();
        ErrorStatsFormatter::new(&summary.error_stats, raw_events, written)
            .write_to(&mut report)?;
        // Reindent each line under the diagnostics section.
        let indented: String = report
            .lines()
            .map(|l| format!("    {l}"))
            .collect::<Vec<_>>()
            .join("\n");
        println!("  {}", c.dim("error stats"));
        println!("{}", c.dim(&indented));
    }

    // --- Legend ---
    if c.0 {
        println!(
            "\n  {}  {} python   native   {} kernel   {} unknown",
            c.dim("legend:"),
            c.green("■"),
            c.magenta("■"),
            c.dim("■"),
        );
    }

    // --- Warnings ---
    let mut warned = false;
    let mut warn = |msg: String| {
        if !warned {
            println!();
            warned = true;
        }
        println!("  {} {msg}", c.yellow("!"));
    };

    if summary.lost_events > 0 {
        warn(format!(
            "{} sample(s) lost. Drain more often or lower frequency.",
            c.bold(&summary.lost_events.to_string()),
        ));
    }
    if kernel_on && !kallsyms_visible {
        warn(format!(
            "kernel frames show as addresses because {} ≥ 1 hides {}. Run {} to see symbols.",
            c.bold("/proc/sys/kernel/kptr_restrict"),
            c.bold("/proc/kallsyms"),
            c.bold("sudo sysctl kernel.kptr_restrict=0"),
        ));
    }
    if !kernel_on {
        warn(format!(
            "kernel sampling was denied; recording fell back to user-only frames.",
        ));
    }
    // `fun_<offset>` hint — only emit when we actually have such frames.
    let address_only_count: u64 = stacks
        .iter()
        .filter(|(frames, _)| frames.iter().any(|(n, _)| n.starts_with("fun_")))
        .map(|(_, c)| *c)
        .sum();
    if address_only_count > 0 {
        warn(format!(
            "{} sample(s) contain {} frames — that's the address-only fallback when ELF/debug info is missing. Install matching -dbg packages or build with the {} feature.",
            c.bold(&address_only_count.to_string()),
            c.dim("fun_<offset>"),
            c.dim("debuginfod"),
        ));
    }

    Ok(())
}
