//! Executable mapping ingestion and process module-table updates.

use std::ffi::CString;
use std::io;

use perf_event_open::sample::record::mmap::{Info as MmapInfo, Mmap};
use perf_event_open::sample::record::Priv;

use crate::spool::{ModuleOwner, ModuleRecord, ModuleTable, PerfSpoolWriter};

use super::{c_string_to_string, i32_from_u32, is_kernel_mode, ProcessTable};

pub(super) fn record_module<W: std::io::Write>(
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
    module: ModuleRecord,
) -> io::Result<()> {
    if module.path.is_empty() {
        return Ok(());
    }
    let update = modules.apply_module(module, writer)?;
    if update.active.is_empty() {
        return Ok(());
    }
    for activation in &update.active {
        let module = &activation.module;
        if let Some(pid) = module.pid() {
            processes.apply_module_update(pid.get(), &update);
            break;
        }
    }
    Ok(())
}

struct MmapEvent<'a> {
    pid: i32,
    privilege: Priv,
    is_executable: bool,
    address: u64,
    length: u64,
    page_offset: u64,
    path: &'a CString,
    inode: u64,
    device_major: u32,
    device_minor: u32,
    inode_generation: u64,
}

fn record_mmap_event<W: std::io::Write>(
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
    event: MmapEvent<'_>,
) -> io::Result<()> {
    let is_kernel = is_kernel_mode(event.privilege);
    if !is_kernel && !event.is_executable {
        return Ok(());
    }
    let owner = if is_kernel {
        ModuleOwner::Kernel
    } else {
        let Some(pid) = crate::Pid::new(event.pid) else {
            return Ok(());
        };
        ModuleOwner::Process(pid)
    };
    record_module(
        modules,
        processes,
        writer,
        ModuleRecord {
            id: 0,
            owner,
            start: event.address,
            end: event.address.saturating_add(event.length),
            file_offset: event.page_offset,
            path: c_string_to_string(event.path).into(),
            inode: event.inode,
            device_major: event.device_major,
            device_minor: event.device_minor,
            inode_generation: event.inode_generation,
        },
    )
}

pub(super) fn record_mmap<W: std::io::Write>(
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
    mmap: &Mmap,
    privilege: Priv,
) -> io::Result<()> {
    let (inode, device_major, device_minor, inode_generation) = match &mmap.ext {
        Some(ext) => match &ext.info {
            MmapInfo::Device {
                major,
                minor,
                inode,
                inode_gen,
            } => (*inode, *major, *minor, *inode_gen),
            MmapInfo::BuildId(_) => (0, 0, 0, 0),
        },
        None => (0, 0, 0, 0),
    };
    let Some(pid) = i32_from_u32(mmap.task.pid) else {
        return Ok(());
    };
    record_mmap_event(
        modules,
        processes,
        writer,
        MmapEvent {
            pid,
            privilege,
            is_executable: mmap_is_executable(mmap),
            address: mmap.addr,
            length: mmap.len,
            page_offset: mmap.page_offset,
            path: &mmap.file,
            inode,
            device_major,
            device_minor,
            inode_generation,
        },
    )
}

pub(super) fn mmap_is_executable(mmap: &Mmap) -> bool {
    const PROT_EXEC: u32 = 0b100;
    match &mmap.ext {
        Some(ext) => ext.prot & PROT_EXEC != 0,
        None => mmap.executable,
    }
}

pub(super) fn read_existing_maps(pid: u32) -> io::Result<String> {
    std::fs::read_to_string(format!("/proc/{pid}/maps"))
}

pub(super) fn register_existing_maps_snapshot<W: std::io::Write>(
    pid: u32,
    maps: &str,
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<bool> {
    register_existing_modules(
        executable_modules_from_maps(pid, maps),
        modules,
        processes,
        writer,
    )
}

pub(super) fn executable_modules_from_maps(
    pid: u32,
    maps: &str,
) -> impl Iterator<Item = ModuleRecord> + '_ {
    let owner = crate::Pid::try_from(pid).ok().map(ModuleOwner::Process);
    crate::proc_maps::parse_iter(maps)
        .filter(|region| region.is_executable && !region.path.is_empty())
        .filter_map(move |region| {
            Some(ModuleRecord {
                id: 0,
                owner: owner?,
                start: region.address.start,
                end: region.address.end,
                file_offset: region.file_offset,
                path: region.path.into(),
                inode: region.inode,
                device_major: region.device_major,
                device_minor: region.device_minor,
                inode_generation: 0,
            })
        })
}

pub(super) fn register_existing_modules<W, I>(
    snapshot: I,
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<bool>
where
    W: std::io::Write,
    I: IntoIterator<Item = ModuleRecord>,
{
    let mut saw_python_runtime = false;
    for module in snapshot {
        saw_python_runtime |= crate::is_python_runtime_module_path(&module.path);
        record_module(modules, processes, writer, module)?;
    }
    Ok(saw_python_runtime)
}
