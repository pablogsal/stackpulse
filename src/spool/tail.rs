use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;

use super::{
    invalid_data, read_frame, read_index_within, read_module_mmap, read_process_id,
    read_python_runtime, read_sample, read_stack_node, read_thread, MmapSpoolCursor, ModulePath,
    PythonRuntimeRecord, SampleRecord, SpoolDefinitions, SpoolFrameModuleContexts,
    StackFrameContexts, StackFrameRefs, REC_FRAME, REC_MODULE, REC_MODULE_DEACTIVATE,
    REC_MODULE_DEACTIVATE_ONE, REC_PYTHON_RUNTIME, REC_SAMPLE, REC_STACK, REC_THREAD,
};

/// Incremental reader for a spool file that is still being appended.
///
/// The writer must only append. A record cut off at the current end of file is
/// left in place and retried by the next [`Self::poll`].
pub struct PerfSpoolTailReader {
    file: File,
    mmap: Arc<Mmap>,
    spool_version: u8,
    position: usize,
    definitions: SpoolDefinitions,
    threads: Vec<(i32, u64)>,
    frame_module_limits: Vec<usize>,
    module_deactivated_at: Vec<Option<usize>>,
    last_timestamp_ns: u64,
    first_sample_timestamp_ns: Option<u64>,
    sample_count: usize,
    pending_samples: Vec<SampleRecord>,
}

impl PerfSpoolTailReader {
    /// Open a growing spool and decode its current complete prefix.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path)?;
        let mmap = Arc::new(unsafe { Mmap::map(&file)? });
        let mut cursor = MmapSpoolCursor::new(Arc::clone(&mmap));
        let spool_version = cursor.check_magic()?;
        let start_timestamp_us = cursor.read_varint::<u64>()?;
        let sample_interval_us = cursor.read_varint::<u64>()?;
        let position = cursor.position;
        let mut reader = Self {
            file,
            mmap,
            spool_version,
            position,
            definitions: SpoolDefinitions {
                start_timestamp_us,
                sample_interval_us,
                modules: Vec::new(),
                frames: Vec::new(),
                frame_contexts: SpoolFrameModuleContexts::default(),
                stack_nodes: Vec::new(),
                python_runtime_records: Vec::new(),
                truncated_tail: false,
            },
            threads: Vec::new(),
            frame_module_limits: Vec::new(),
            module_deactivated_at: Vec::new(),
            last_timestamp_ns: 0,
            first_sample_timestamp_ns: None,
            sample_count: 0,
            pending_samples: Vec::new(),
        };
        reader.pending_samples = reader.parse_available()?;
        Ok(reader)
    }

    /// Decode and return samples added since the previous poll.
    pub fn poll(&mut self) -> io::Result<Vec<SampleRecord>> {
        self.remap_if_grown()?;
        let mut samples = std::mem::take(&mut self.pending_samples);
        samples.extend(self.parse_available()?);
        Ok(samples)
    }

    /// Return the profile timeline anchor in microseconds.
    pub fn start_timestamp_us(&self) -> u64 {
        self.definitions.start_timestamp_us
    }

    /// Return the recorded sample interval in microseconds.
    pub fn sample_interval_us(&self) -> u64 {
        self.definitions.sample_interval_us
    }

    /// Return code areas decoded so far.
    pub fn modules(&self) -> &[super::ModuleRecord] {
        &self.definitions.modules
    }

    /// Return frame definitions decoded so far.
    pub fn frames(&self) -> &[super::FrameRecord] {
        &self.definitions.frames
    }

    /// Return Python-runtime status records decoded so far.
    pub fn python_runtime_records(&self) -> &[PythonRuntimeRecord] {
        &self.definitions.python_runtime_records
    }

    /// Return the total number of samples decoded across all polls.
    pub fn sample_count(&self) -> usize {
        self.sample_count
    }

    /// Borrow raw frames for an interned stack.
    pub fn stack_frame_refs(&self, stack_id: u32) -> io::Result<StackFrameRefs<'_>> {
        self.definitions.stack_frame_refs(stack_id)
    }

    /// Borrow raw frames and their positional module contexts.
    pub fn stack_frame_contexts(
        &self,
        process_id: i32,
        stack_id: u32,
    ) -> io::Result<StackFrameContexts<'_>> {
        Ok(StackFrameContexts {
            definitions: &self.definitions,
            process_id,
            frames: self.stack_frame_refs(stack_id)?,
        })
    }

    /// Convert a sample timestamp to the profile timeline in microseconds.
    pub fn timestamp_us(&self, sample: &SampleRecord) -> u64 {
        let first = self
            .first_sample_timestamp_ns
            .unwrap_or(sample.timestamp_ns);
        self.definitions
            .start_timestamp_us
            .saturating_add(sample.timestamp_ns.saturating_sub(first) / 1_000)
    }

    pub(crate) fn frame_module_contexts(&self) -> SpoolFrameModuleContexts {
        self.definitions.frame_contexts.clone()
    }

    fn remap_if_grown(&mut self) -> io::Result<()> {
        let file_len = usize::try_from(self.file.metadata()?.len())
            .map_err(|_| invalid_data("spool file is too large to map"))?;
        if file_len < self.mmap.len() {
            return Err(invalid_data("spool file shrank while being tailed"));
        }
        if file_len > self.mmap.len() {
            self.mmap = Arc::new(unsafe { Mmap::map(&self.file)? });
        }
        Ok(())
    }

    fn parse_available(&mut self) -> io::Result<Vec<SampleRecord>> {
        let mut cursor = MmapSpoolCursor::at_position(Arc::clone(&self.mmap), self.position);
        let mut samples = Vec::new();
        let mut contexts_changed = false;
        loop {
            let record_start = cursor.position;
            let Some(tag) = cursor.read_tag()? else {
                break;
            };
            let parsed = (|| -> io::Result<()> {
                match tag {
                    REC_MODULE => {
                        let mut module = read_module_mmap(
                            &mut cursor,
                            self.definitions.modules.len(),
                            self.spool_version,
                        )?;
                        module.path = ModulePath::from(module.path.as_str());
                        self.definitions.modules.push(module);
                        self.module_deactivated_at.push(None);
                        contexts_changed = true;
                    }
                    REC_FRAME => {
                        let module_limit = self.definitions.modules.len();
                        let frame = read_frame(
                            &mut cursor,
                            &self.definitions.modules,
                            self.definitions.frames.len(),
                        )?;
                        self.definitions.frames.push(frame);
                        self.frame_module_limits.push(module_limit);
                        contexts_changed = true;
                    }
                    REC_STACK => self.definitions.stack_nodes.push(read_stack_node(
                        &mut cursor,
                        &self.definitions.stack_nodes,
                        self.definitions.frames.len(),
                    )?),
                    REC_THREAD => self
                        .threads
                        .push(read_thread(&mut cursor, self.threads.len())?),
                    REC_SAMPLE => {
                        let sample = read_sample(
                            &mut cursor,
                            &self.threads,
                            self.definitions.stack_nodes.len(),
                            &mut self.last_timestamp_ns,
                        )?;
                        self.first_sample_timestamp_ns
                            .get_or_insert(sample.timestamp_ns);
                        self.sample_count = self
                            .sample_count
                            .checked_add(1)
                            .ok_or_else(|| invalid_data("sample count exceeds address space"))?;
                        samples.push(sample);
                    }
                    REC_PYTHON_RUNTIME => self
                        .definitions
                        .python_runtime_records
                        .push(read_python_runtime(&mut cursor)?),
                    REC_MODULE_DEACTIVATE => {
                        let process_id = read_process_id(&mut cursor)?;
                        let deactivated_at = self.definitions.frames.len();
                        for (module, deactivated) in self
                            .definitions
                            .modules
                            .iter()
                            .zip(&mut self.module_deactivated_at)
                        {
                            if module.process_id == process_id && !module.is_kernel {
                                deactivated.get_or_insert(deactivated_at);
                            }
                        }
                        contexts_changed = true;
                    }
                    REC_MODULE_DEACTIVATE_ONE => {
                        if self.spool_version < 2 {
                            return Err(invalid_data(
                                "targeted module deactivation requires spool version 2",
                            ));
                        }
                        let module_id = read_index_within(
                            &mut cursor,
                            self.definitions.modules.len(),
                            "module deactivation",
                        )?;
                        self.module_deactivated_at[module_id]
                            .get_or_insert(self.definitions.frames.len());
                        contexts_changed = true;
                    }
                    other => return Err(invalid_data(format!("unknown spool record tag {other}"))),
                }
                Ok(())
            })();
            if let Err(error) = parsed {
                if error.kind() == io::ErrorKind::UnexpectedEof && cursor.at_eof() {
                    cursor.position = record_start;
                    break;
                }
                return Err(error);
            }
            self.position = cursor.position;
        }
        if contexts_changed {
            self.definitions.frame_contexts = SpoolFrameModuleContexts::new(
                self.frame_module_limits.clone(),
                self.module_deactivated_at.clone(),
            );
        }
        Ok(samples)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::spool::{
        FrameMode, FrameRecord, ModulePath, ModuleRecord, PerfSpoolReader, PerfSpoolWriter,
    };
    use crate::test_support::TempDir;

    fn module() -> ModuleRecord {
        ModuleRecord {
            id: 0,
            process_id: 7,
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 1,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: ModulePath::from("/tmp/test.so"),
            is_kernel: false,
        }
    }

    fn frame() -> FrameRecord {
        FrameRecord {
            module_id: Some(0),
            file_relative_ip: 0x10,
            abs_ip: 0x1010,
            mode: FrameMode::User,
        }
    }

    #[test]
    fn polls_flushed_prefixes_and_matches_finished_reader() {
        let dir = TempDir::new("tail-prefixes");
        let path = dir.path().join("recording.spool");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        writer.flush().unwrap();
        let mut tail = PerfSpoolTailReader::open(&path).unwrap();
        assert!(tail.poll().unwrap().is_empty());

        writer.write_module(&module()).unwrap();
        writer.write_sample_frames(1_000, 7, 8, [frame()]).unwrap();
        writer.flush().unwrap();
        let first = tail.poll().unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(tail.timestamp_us(&first[0]), 123);

        writer.write_sample_frames(3_000, 7, 8, [frame()]).unwrap();
        writer.flush().unwrap();
        let second = tail.poll().unwrap();
        assert_eq!(tail.timestamp_us(&second[0]), 125);
        drop(writer);

        let finished = PerfSpoolReader::open(&path).unwrap();
        assert_eq!(tail.modules(), finished.modules());
        assert_eq!(tail.frames(), finished.frames());
        assert_eq!(tail.sample_count(), finished.samples().len());
    }

    #[test]
    fn retries_a_sample_cut_off_mid_record_without_double_delta() {
        let dir = TempDir::new("tail-partial-sample");
        let path = dir.path().join("recording.spool");
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 10).unwrap();
        writer
            .write_sample_frames(
                1_000,
                7,
                8,
                [FrameRecord {
                    module_id: None,
                    file_relative_ip: 0,
                    abs_ip: 0x1010,
                    mode: FrameMode::User,
                }],
            )
            .unwrap();
        let bytes = writer.into_inner();
        let split = bytes.len() - 1;
        std::fs::write(&path, &bytes[..split]).unwrap();

        let mut tail = PerfSpoolTailReader::open(&path).unwrap();
        assert!(tail.poll().unwrap().is_empty());
        let mut append = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        append.write_all(&bytes[split..]).unwrap();
        append.flush().unwrap();
        let samples = tail.poll().unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].timestamp_ns, 1_000);
    }
}
