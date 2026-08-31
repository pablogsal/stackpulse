SHELL := /bin/sh

CARGO ?= cargo
CARGO_FLAGS ?=
CLIPPY_ARGS ?= --workspace --all-targets --all-features --locked $(CARGO_FLAGS) -- -D warnings

.PHONY: check test test-features fmt fmt-check clippy clippy-strict doc coverage coverage-html coverage-lcov ci clean require-cargo-llvm-cov

check:
	$(CARGO) check --workspace --all-targets --locked $(CARGO_FLAGS)

test:
	$(CARGO) test --workspace --all-targets --locked $(CARGO_FLAGS)

test-features:
	$(CARGO) test --workspace --all-features --locked $(CARGO_FLAGS)
	$(CARGO) test --workspace --no-default-features --locked $(CARGO_FLAGS)

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy $(CLIPPY_ARGS)

clippy-strict:
	$(CARGO) clippy --workspace --lib --all-features --locked -- \
		-D warnings \
		-D clippy::unwrap_used \
		-D clippy::expect_used \
		-D clippy::panic \
		-D clippy::unreachable \
		-D clippy::undocumented_unsafe_blocks

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --all-features --no-deps --locked $(CARGO_FLAGS)

coverage: require-cargo-llvm-cov
	$(CARGO) llvm-cov --workspace --all-targets --locked $(CARGO_FLAGS)

coverage-html: require-cargo-llvm-cov
	$(CARGO) llvm-cov --workspace --all-targets --locked $(CARGO_FLAGS) --html

coverage-lcov: require-cargo-llvm-cov
	$(CARGO) llvm-cov --workspace --all-targets --locked $(CARGO_FLAGS) --lcov --output-path lcov.info

ci: fmt-check clippy clippy-strict test-features doc

clean:
	$(CARGO) clean

require-cargo-llvm-cov:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "cargo-llvm-cov is required. Install with: cargo install cargo-llvm-cov"; exit 1; }
