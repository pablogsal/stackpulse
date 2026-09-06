//! Executable mapping ingestion and process module-table updates.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;

use perf_event_open::sample::record::mmap::{Info as MmapInfo, Mmap};
use perf_event_open::sample::record::Priv;

use crate::spool::{ModuleOwner, ModuleRecord, ModuleTable, PerfSpoolWriter};

use super::{i32_from_u32, is_kernel_mode, ProcessTable};

pub(super) fn record_module<W: std::io::Write>(
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
    module: ModuleRecord,
) -> io::Result<()> {
    if module.path.as_os_str().is_empty() {
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
    let is_kernel = is_kernel_mode(privilege);
    if !is_kernel && !mmap_is_executable(mmap) {
        return Ok(());
    }
    let owner = if is_kernel {
        ModuleOwner::Kernel
    } else {
        let Some(pid) = crate::Pid::new(pid) else {
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
            start: mmap.addr,
            end: mmap.addr.saturating_add(mmap.len),
            file_offset: mmap.page_offset,
            path: std::path::Path::new(OsStr::from_bytes(mmap.file.as_bytes())).into(),
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

pub(super) fn read_existing_maps(pid: u32) -> io::Result<Vec<u8>> {
    std::fs::read(format!("/proc/{pid}/maps"))
}

pub(super) fn register_existing_maps_snapshot<W: std::io::Write>(
    pid: u32,
    maps: &(impl AsRef<[u8]> + ?Sized),
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
    maps: &(impl AsRef<[u8]> + ?Sized),
) -> impl Iterator<Item = ModuleRecord> + '_ {
    let owner = crate::Pid::try_from(pid).ok().map(ModuleOwner::Process);
    crate::proc_maps::parse_iter(maps)
        .filter(|region| region.is_executable && !region.path.as_os_str().is_empty())
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
