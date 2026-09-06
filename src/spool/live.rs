use std::fs::File;
use std::io::{self, BufWriter, Seek, Write};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use crate::native_module::ExactImageStore;
use crate::RecordingSummary;

use super::{Tail, TailBatch};

/// An empty file owned by a recording, with an explicit retention policy.
#[derive(Debug)]
pub struct Spool {
    pub(crate) file: File,
    pub(crate) disposable: bool,
}

/// The validated file-writing capability owned by a recorder.
#[doc(hidden)]
#[derive(Debug)]
pub struct SpoolFile(pub(crate) BufWriter<File>);

impl Write for SpoolFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Spool {
    pub(crate) fn into_writer(self) -> SpoolFile {
        SpoolFile(BufWriter::new(self.file))
    }

    /// Preserve the recording for subsequent replay.
    pub fn retained(file: File) -> io::Result<Self> {
        Self::new(file, false)
    }

    /// Allow the live reader to discard delivered records on its next advance.
    ///
    /// The file can no longer be replayed from the beginning after reclamation.
    pub fn disposable(file: File) -> io::Result<Self> {
        Self::new(file, true)
    }

    fn new(mut file: File, disposable: bool) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spool requires an empty regular file",
            ));
        }
        file.rewind()?;
        let flags = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_GETFL)?;
        if flags & libc::O_ACCMODE == libc::O_RDONLY || flags & libc::O_APPEND != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spool requires a writable file without append mode",
            ));
        }
        let _reader = File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        Ok(Self { file, disposable })
    }
}

/// Result of advancing a recorder-linked reader or symbolization session.
#[derive(Debug)]
pub enum ReadStatus<T> {
    /// Newly published data.
    Batch(T),
    /// No new data became available before the timeout.
    Pending,
    /// All published data was consumed and capture finished successfully.
    Finished(Arc<RecordingSummary>),
}

/// State of automatic filesystem block reclamation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reclamation {
    /// The spool preserves all records.
    Retained,
    /// Reclamation will be attempted as the reader advances.
    Enabled,
    /// The filesystem does not support reclamation.
    Unsupported,
}

/// Current storage and definition retention of a live reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReaderStats {
    /// Bytes committed by successful producer flushes.
    pub published_bytes: u64,
    /// Complete record prefix decoded by this reader.
    pub consumed_bytes: u64,
    /// Total successfully reclaimed byte ranges.
    pub reclaimed_bytes: u64,
    /// Frame definitions retained by the reader.
    pub retained_frames: usize,
    /// Stack-node definitions retained by the reader.
    pub retained_stacks: usize,
    /// Mapping definitions retained by the reader.
    pub retained_modules: usize,
    /// Current reclamation policy or detected lack of support.
    pub reclamation: Reclamation,
}

#[derive(Clone)]
enum End {
    Open,
    Finished(Arc<RecordingSummary>),
    Aborted(Option<Arc<crate::Error>>),
}

struct Published {
    end: u64,
    status: End,
}

struct Shared {
    state: Mutex<Published>,
    changed: Condvar,
}

#[derive(Clone)]
pub(crate) struct Publisher(Arc<Shared>);

impl Publisher {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Shared {
            state: Mutex::new(Published {
                end: 0,
                status: End::Open,
            }),
            changed: Condvar::new(),
        }))
    }

    fn lock(&self) -> MutexGuard<'_, Published> {
        self.0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn publish(&self, end: u64) {
        let mut state = self.lock();
        if matches!(state.status, End::Open) && state.end != end {
            state.end = end;
            self.0.changed.notify_all();
        }
    }

    pub(crate) fn finish(&self, end: u64, summary: RecordingSummary) {
        let mut state = self.lock();
        if matches!(state.status, End::Open) {
            state.end = end;
            state.status = End::Finished(Arc::new(summary));
            self.0.changed.notify_all();
        }
    }

    pub(crate) fn abort(&self, error: Option<Arc<crate::Error>>) {
        let mut state = self.lock();
        if matches!(state.status, End::Open) {
            state.status = End::Aborted(error);
            self.0.changed.notify_all();
        }
    }
}

/// A recorder-linked reader with publication, completion, and reclamation ownership.
pub struct LiveReader {
    tail: Tail,
    publisher: Publisher,
    reclaim_previous: bool,
    reclamation: Reclamation,
}

impl std::fmt::Debug for LiveReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveReader")
            .field("tail", &self.tail)
            .field("reclamation", &self.reclamation)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("capture failed: {0}")]
struct CaptureFailure(#[source] Arc<crate::Error>);

impl LiveReader {
    pub(crate) fn new(
        file: File,
        discarder: Option<File>,
        images: ExactImageStore,
        publisher: Publisher,
    ) -> crate::Result<Self> {
        let end = publisher.lock().end;
        let reclamation = if discarder.is_some() {
            Reclamation::Enabled
        } else {
            Reclamation::Retained
        };
        let tail = Tail::from_file_bounded(
            file,
            discarder,
            Some(images),
            Some(
                usize::try_from(end)
                    .map_err(|_| io::Error::other("published spool is too large"))?,
            ),
        )
        .map_err(crate::Error::spool)?;
        Ok(Self {
            tail,
            publisher,
            reclaim_previous: false,
            reclamation,
        })
    }

    pub(crate) fn tail(&self) -> &Tail {
        &self.tail
    }

    /// Wait for published data, reclaiming the preceding batch before advancing.
    ///
    /// Reclamation failures leave the next batch unread and may be retried.
    /// Drive the reader through Finished to reclaim the final delivered batch.
    pub fn poll(&mut self, timeout: Duration) -> crate::Result<ReadStatus<TailBatch<'_>>> {
        if self.reclaim_previous && self.reclamation == Reclamation::Enabled {
            match self.tail.discard_consumed() {
                Ok(()) => {}
                Err(error) if error.kind() == crate::ErrorKind::Unsupported => {
                    self.reclamation = Reclamation::Unsupported
                }
                Err(error) => return Err(error),
            }
        }
        self.reclaim_previous = false;
        let state = self.publisher.lock();
        let (state, _) = self
            .publisher
            .0
            .changed
            .wait_timeout_while(state, timeout, |state| {
                !self.tail.initial_samples_pending
                    && self.tail.position as u64 >= state.end
                    && matches!(state.status, End::Open)
            })
            .unwrap_or_else(|error| error.into_inner());
        let end = state.end;
        let status = state.status.clone();
        drop(state);
        if self.tail.initial_samples_pending || (self.tail.position as u64) < end {
            self.tail.visible_len = Some(
                usize::try_from(end)
                    .map_err(|_| io::Error::other("published spool is too large"))?,
            );
            let batch = self.tail.poll()?;
            self.reclaim_previous = true;
            return Ok(ReadStatus::Batch(batch));
        }
        match status {
            End::Open => Ok(ReadStatus::Pending),
            End::Finished(summary) => Ok(ReadStatus::Finished(summary)),
            End::Aborted(Some(error)) => {
                Err(crate::Error::new(error.kind(), CaptureFailure(error)))
            }
            End::Aborted(None) => Err(crate::Error::message(
                crate::ErrorKind::Io,
                "recording was abandoned before finish",
            )),
        }
    }

    /// Source wall time paired with the recording's monotonic origin.
    pub fn started_at(&self) -> Option<std::time::SystemTime> {
        self.tail
            .definitions
            .clock_origin
            .map(|origin| origin.wall_time)
    }

    /// Nominal sample interval carried by the recording header.
    pub fn nominal_interval(&self) -> Option<Duration> {
        let nanos = self.tail.definitions.sample_interval_ns;
        (nanos != 0).then(|| Duration::from_nanos(nanos))
    }

    /// Observe backlog and retained definitions without filesystem I/O.
    pub fn stats(&self) -> ReaderStats {
        let state = self.publisher.lock();
        ReaderStats {
            published_bytes: state.end,
            consumed_bytes: self.tail.position as u64,
            reclaimed_bytes: self
                .tail
                .discarder
                .as_ref()
                .map_or(0, |discarder| discarder.position as u64),
            retained_frames: self.tail.definitions.frames.len(),
            retained_stacks: self.tail.definitions.stack_nodes.len(),
            retained_modules: self.tail.definitions.modules.len(),
            reclamation: self.reclamation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spool::{FrameMode, FrameRecord, PerfSpoolWriter, Snapshot};
    use crate::test_support::TempDir;
    use std::io::BufWriter;
    use std::os::unix::fs::MetadataExt;

    fn sample(writer: &mut PerfSpoolWriter<BufWriter<File>>, timestamp: u64) {
        writer
            .write_sample_frames(
                timestamp,
                7,
                8,
                [FrameRecord {
                    module_id: None,
                    file_relative_ip: 4096,
                    abs_ip: 4096,
                    mode: FrameMode::User,
                }],
            )
            .unwrap();
    }

    fn reader(
        writer: &mut PerfSpoolWriter<BufWriter<File>>,
        disposable: bool,
    ) -> (Publisher, LiveReader) {
        writer.flush().unwrap();
        let publisher = Publisher::new();
        publisher.publish(writer.position());
        let reader = LiveReader::new(
            writer.open_reader().unwrap(),
            disposable.then(|| writer.open_discarder().unwrap()),
            ExactImageStore::default(),
            publisher.clone(),
        )
        .unwrap();
        (publisher, reader)
    }

    #[test]
    fn only_published_bytes_are_visible_and_finish_is_persistent() {
        let dir = TempDir::new("live-publication");
        let mut writer = PerfSpoolWriter::create(dir.path().join("capture"), 0, 1).unwrap();
        let (publisher, mut reader) = reader(&mut writer, false);
        assert!(matches!(
            reader.poll(Duration::ZERO).unwrap(),
            ReadStatus::Batch(_)
        ));
        sample(&mut writer, 1);
        writer.flush().unwrap();
        assert!(matches!(
            reader.poll(Duration::ZERO).unwrap(),
            ReadStatus::Pending
        ));
        publisher.publish(writer.position());
        let ReadStatus::Batch(batch) = reader.poll(Duration::ZERO).unwrap() else {
            panic!("published sample missing")
        };
        assert_eq!(batch.samples().len(), 1);
        publisher.finish(writer.position(), RecordingSummary::default());
        assert!(matches!(
            reader.poll(Duration::ZERO).unwrap(),
            ReadStatus::Finished(_)
        ));
        assert!(matches!(
            reader.poll(Duration::ZERO).unwrap(),
            ReadStatus::Finished(_)
        ));
    }

    #[test]
    fn aborted_producer_never_exposes_unpublished_suffix() {
        let dir = TempDir::new("live-abort");
        let mut writer = PerfSpoolWriter::create(dir.path().join("capture"), 0, 1).unwrap();
        let (publisher, mut reader) = reader(&mut writer, false);
        reader.poll(Duration::ZERO).unwrap();
        sample(&mut writer, 1);
        writer.flush().unwrap();
        publisher.abort(None);
        assert!(reader.poll(Duration::ZERO).is_err());
        assert_eq!(
            reader.stats().consumed_bytes,
            reader.stats().published_bytes
        );
    }

    #[test]
    fn publication_wakes_waiting_reader_without_losing_completion() {
        let dir = TempDir::new("live-wake");
        let mut writer = PerfSpoolWriter::create(dir.path().join("capture"), 0, 1).unwrap();
        let (publisher, mut reader) = reader(&mut writer, false);
        reader.poll(Duration::ZERO).unwrap();
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                let ReadStatus::Batch(batch) = reader.poll(Duration::from_secs(3)).unwrap() else {
                    panic!("publication not observed")
                };
                assert_eq!(batch.samples().len(), 1);
                assert!(matches!(
                    reader.poll(Duration::from_secs(3)).unwrap(),
                    ReadStatus::Finished(_)
                ));
            });
            sample(&mut writer, 1);
            writer.flush().unwrap();
            publisher.publish(writer.position());
            publisher.finish(writer.position(), RecordingSummary::default());
            worker.join().unwrap();
        });
    }

    #[test]
    fn disposable_reclaims_final_batch_while_retained_preserves_replay() {
        for disposable in [false, true] {
            let dir = TempDir::new("live-retention");
            let path = dir.path().join("capture");
            let mut writer = PerfSpoolWriter::create(&path, 0, 1).unwrap();
            for timestamp in 1..=20_000 {
                sample(&mut writer, timestamp);
            }
            let (publisher, mut reader) = reader(&mut writer, disposable);
            let before = std::fs::metadata(&path).unwrap().blocks();
            publisher.finish(writer.position(), RecordingSummary::default());
            let mut count = 0;
            loop {
                match reader.poll(Duration::ZERO).unwrap() {
                    ReadStatus::Batch(batch) => count += batch.samples().len(),
                    ReadStatus::Finished(_) => break,
                    ReadStatus::Pending => panic!("finished source must not wait"),
                }
            }
            assert_eq!(count, 20_000);
            if disposable && reader.stats().reclamation == Reclamation::Enabled {
                assert!(reader.stats().reclaimed_bytes > 0);
                assert!(std::fs::metadata(&path).unwrap().blocks() < before);
                assert!(Snapshot::open(&path).is_err());
            } else if !disposable {
                assert_eq!(reader.stats().reclaimed_bytes, 0);
                assert_eq!(Snapshot::open(&path).unwrap().samples().len(), 20_000);
            }
        }
    }

    #[test]
    fn reclamation_failure_does_not_consume_the_next_publication() {
        let dir = TempDir::new("live-reclaim-failure");
        let mut writer = PerfSpoolWriter::create(dir.path().join("capture"), 0, 1).unwrap();
        for timestamp in 1..=20_000 {
            sample(&mut writer, timestamp);
        }
        writer.flush().unwrap();
        let publisher = Publisher::new();
        publisher.publish(writer.position());
        let mut reader = LiveReader::new(
            writer.open_reader().unwrap(),
            Some(writer.open_reader().unwrap()),
            ExactImageStore::default(),
            publisher.clone(),
        )
        .unwrap();
        let ReadStatus::Batch(batch) = reader.poll(Duration::ZERO).unwrap() else {
            panic!("initial publication missing")
        };
        assert!(batch.samples().len() > 0);
        let consumed = reader.stats().consumed_bytes;
        sample(&mut writer, 20_001);
        writer.flush().unwrap();
        publisher.finish(writer.position(), RecordingSummary::default());
        for _ in 0..2 {
            assert!(reader.poll(Duration::ZERO).is_err());
            assert_eq!(reader.stats().consumed_bytes, consumed);
            assert_eq!(reader.stats().reclaimed_bytes, 0);
            assert_eq!(reader.stats().reclamation, Reclamation::Enabled);
        }
    }

    #[test]
    fn empty_owned_spool_rewinds_cursor() {
        use std::io::{Seek, SeekFrom};
        let dir = TempDir::new("spool-cursor");
        let mut file = File::create(dir.path().join("capture")).unwrap();
        file.seek(SeekFrom::Start(4096)).unwrap();
        let mut spool = Spool::retained(file).unwrap();
        assert_eq!(spool.file.stream_position().unwrap(), 0);
    }
}
