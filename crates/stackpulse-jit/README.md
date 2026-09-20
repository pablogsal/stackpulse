# stackpulse-jit

GDB JIT registry discovery, generated symbols, and live unwind data for Linux
x86-64 and AArch64. Requires Rust 1.88. Registered ELF images must be 64-bit and
little-endian.

`Registry<P, D>` accepts the caller's `MemoryReader` and `Mapping` snapshot.
The caller owns process access, mapping generations, sampling, unwinding, and
symbol storage. Discovery reads ELF files and procfs metadata; live registration
and CFI reads go through `MemoryReader`. The registry does not scan process
mappings or start a polling thread.

Call `refresh(generation, mappings)` before a sampling batch, then
`drain_updates` to install modules and symbols. Retirements precede loads.
`initialize` discovers registrations before a direct capture's first unwind.
After an unresolved known JIT frame, `refresh_for_address` can refresh its CFI;
drain the resulting updates before retrying the captured stack.

`Update<D>::Loaded` returns `framehop::Module<D>` from `framehop-stackpulse`
0.17 with its `std` feature. Consumers must resolve the same Framehop package
version and source. Section storage defaults to `Arc<[u8]>`; a caller-owned
type can implement `From<Arc<[u8]>> + Deref<Target = [u8]> + Clone`. A load with
`symbols: None` preserves the current symbol identity. Retained symbols remain
owned by the consumer after removal or address reuse.

There are no default features or recorder dependencies. StackPulse re-exports
this API as `stackpulse::jit` and retains its perf recording integration.

`fixtures::GDB_JIT_OVERLAY_SOURCE` supplies GNU assembler source for Linux
x86-64 tests. Write it to a `.S` file and compile with `cc`, defining
`FUNCTION_NAME` and `CFA_OFFSET`. No benchmark feature or StackPulse dependency
is needed.

When releasing the workspace, publish `framehop-stackpulse` first if its version
changed, then `stackpulse-jit`, then `stackpulse`. Path dependencies also declare
registry versions so packaged crates resolve in that order.
The tag workflow publishes only StackPulse, so publish new dependency versions
before tagging it.
