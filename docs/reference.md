# Reader selection

| Reader | Storage and lifecycle |
| --- | --- |
| `Snapshot` | Loads decoded samples for random access through `sample(index)`. |
| `Replay` | Validates a completed file and iterates samples with a bounded range index. |
| `LiveReader` | Consumes recorder-published batches and observes producer completion. |
| `Tail` | Reads an externally managed growing file; the caller owns its completion protocol. |

All readers expose the same immutable sample and stack vocabulary. Samples
cannot be detached from the source definitions needed to interpret their
stacks and clock correlation.

`Sample::recorded_at` returns `Result<Option<SystemTime>, TimestampOutOfRange>`.
Absence means the recording has no clock correlation; an error means the
correlated time cannot be represented. `monotonic_timestamp` preserves the raw
recording clock without converting it to wall time.

`ResolvedStack::frames()` iterates frames. `iter()` additionally yields a
`FrameKey` issued by that symbolizer. Repeated iteration does not consume the
collection. A new symbolizer has a different frame-key namespace.

The root reexports common entry points. The `record`, `process`, `spool`,
`symbolize`, and `profile` modules provide the complete public surface.
