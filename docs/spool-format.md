# SPULSE spool format

A spool file is the on-disk profile that `Recorder` produces: an
append-only binary stream designed so that recording only ever issues small
writes. If recording dies partway through the final record, readers keep the
complete prefix that precedes it. A finished file can be read fully in memory
through `Snapshot` or replayed sequentially with bounded memory through
`Replay`.

## Compatibility

`Snapshot` and `Replay` read every released SPULSE
version. StackPulse 0.8 writes SPULSE3 and continues to read SPULSE1 and
SPULSE2. When existing records cannot express new data, a future writer adds
a new magic version; the meaning of an existing record never changes in
place.

A reader accepts a file that ends partway through its final record. It retains
the complete prefix and reports recovery through
`Snapshot::recovered_from_truncated_tail`. Corruption within the
complete prefix remains an error.

## Stream header

Every file begins with:

1. An eight-byte magic value: `SPULSE1\0`, `SPULSE2\0`, or `SPULSE3\0`.
2. The profile start timestamp in microseconds, encoded as an unsigned varint.
3. The requested sample interval in microseconds, encoded as an unsigned
   varint.

Integers after the magic use the `integer-encoding` varint representation.
Signed values use that crate's signed encoding.

## Record types

Each record starts with a one-byte tag.

| Tag | Record | Purpose |
| ---: | --- | --- |
| 1 | module | Defines an executable mapping and its stable module id. |
| 2 | frame | Interns a module-relative or absolute instruction address. |
| 3 | stack | Interns one prefix-linked stack node. |
| 4 | thread | Interns a process and thread identity. |
| 5 | sample | Associates a timestamp delta, thread, and stack. |
| 6 | Python runtime | Marks a process as entering or leaving Python-runtime mode. |
| 7 | process module deactivation | Retires active mappings for one process. |
| 8 | module deactivation | Retires one mapping generation. |

Definitions are ordered and ids are dense. A record may only refer to an id
defined earlier in the stream. Readers reject forward references, duplicate
definition ids, overflowing address arithmetic, and references outside a
module's mapped span.

## Version differences

SPULSE1 contains the core module, frame, stack, thread, sample, and runtime
records. SPULSE2 adds mapping-generation-aware module deactivation. SPULSE3
extends module identity with device major, device minor, and inode generation,
which prevents stale symbol reuse across remapped files.

## Frame encoding

A frame matched to a known module stores that module's id and a file-relative
address. A frame with no matching module stores an absolute address and a
user/kernel mode bit. A reserved tag encodes a truncated-stack marker with a
zero payload.

Return addresses are normalized to the calling instruction before a frame is
written. Module-relative addresses use checked subtraction and addition;
overflow or an address outside the mapping is rejected.

## Replay and resource bounds

`Snapshot` retains decoded samples for random access.
`Replay` retains definitions and a bounded sample-range index,
then decodes sample records sequentially. Once the range index reaches its
configured limit, replay scans the validated suffix without retaining one
index entry per sample.

Both readers validate the complete retained prefix when opened. Sequential
iteration only visits records and references that passed those checks.
