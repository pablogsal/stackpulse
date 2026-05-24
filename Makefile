SHELL := /bin/sh

CARGO ?= cargo
CARGO_FLAGS ?=

.PHONY: check test fmt fmt-check clippy doc coverage coverage-html coverage-lcov ci clean require-cargo-llvm-cov

check:
	$(CARGO) check --workspace --all-targets $(CARGO_FLAGS)

test:
	$(CARGO) test --workspace --all-targets $(CARGO_FLAGS)

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --workspace --all-targets $(CARGO_FLAGS) -- -D warnings

doc:
	$(CARGO) doc --workspace --no-deps $(CARGO_FLAGS)

coverage: require-cargo-llvm-cov
	$(CARGO) llvm-cov --workspace --all-targets $(CARGO_FLAGS)

coverage-html: require-cargo-llvm-cov
	$(CARGO) llvm-cov --workspace --all-targets $(CARGO_FLAGS) --html

coverage-lcov: require-cargo-llvm-cov
	$(CARGO) llvm-cov --workspace --all-targets $(CARGO_FLAGS) --lcov --output-path lcov.info

ci: fmt-check clippy test

clean:
	$(CARGO) clean

require-cargo-llvm-cov:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "cargo-llvm-cov is required. Install with: cargo install cargo-llvm-cov"; exit 1; }
