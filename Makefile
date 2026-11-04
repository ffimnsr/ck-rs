# List of binary targets produced by this workspace.
BINARIES := ck ck-server
CARGO ?= cargo
CRATE ?= chainkeeper-core

.PHONY: build test verify verify-phase fmt clippy doc deny

build:
	$(CARGO) build --workspace

test:
	$(CARGO) test --quiet --workspace --all-features

fmt:
	$(CARGO) fmt --all --check

clippy:
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps

deny:
	$(CARGO) deny check

# Full pre-release gate. CI also runs each stage in its own job.
verify: fmt clippy test doc deny

# Only the checks that can fail for one crate.
verify-phase:
	$(CARGO) fmt --all --check
	$(CARGO) clippy -p $(CRATE) --all-targets --all-features -- -D warnings
	$(CARGO) test --quiet -p $(CRATE) --all-features
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc -p $(CRATE) --no-deps
