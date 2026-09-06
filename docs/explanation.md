# Ownership across capture and replay

Capture owns perf counters, event ordering, spool writes, and publication.
Replay owns decoded definitions. A live symbolization session exclusively
borrows its reader and owns its native backends and symbol caches. A cached
session additionally owns values prepared by the application.

This boundary keeps capture independent of symbolization cost. A replay worker
can be slower than capture without blocking perf draining on symbol lookup.
The file absorbs the backlog; reader statistics report how much published data
remains. Applications still choose cancellation and output backpressure policy.

Publication follows a successful flush of complete records. Readers never infer
completion from an empty poll and never consume an unpublished suffix written
by a failing buffer's destructor. Successful finish publishes the last offset
and final statistics; failure or abandonment preserves the last valid prefix
and a terminal error.

Disposable storage acknowledges delivery at the next explicit reader advance.
The prior batch's exclusive borrow has ended, so complete consumed pages may be
reclaimed. Reclamation is fallible and explicit in the advancing call. An
unsupported filesystem disables subsequent attempts; other errors preserve the
next unread batch for retry.

Symbol refresh occurs before consuming the next batch. Generation observations
are committed when the corresponding update succeeds. Process invalidation
covers native enrichment and perf-map changes together, including changes that
would otherwise leave an external prepared stack stale.

Prepared collector handles can outlive cache entries. Therefore cache eviction
does not imply a collector reset. The application must flush pending samples
before invalidating its own handle arena and clear StackPulse's cached values
at that boundary.
