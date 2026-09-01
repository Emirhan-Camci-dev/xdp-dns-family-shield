.PHONY: all community enterprise clean

all: community enterprise

community:
	@echo "Building Community Edition (Control Plane)..."
	cd community && cargo build --release
	@echo "Note: eBPF C code (community/ebpf/src) requires clang and vmlinux.h to compile."

enterprise:
	@echo "Building Enterprise Edition (Control Plane)..."
	cd enterprise && cargo build --release
	@echo "Note: eBPF C code (enterprise/ebpf/src) requires clang and vmlinux.h to compile."

test:
	@echo "Running tests..."
	cd enterprise && cargo test

clean:
	cd community && cargo clean
	cd enterprise && cargo clean
