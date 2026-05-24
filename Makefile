# proto-mcp build orchestration.
#
# The Go binary doesn't need Make — `go build ./cmd/protonmcp` is
# enough. This Makefile exists for the Swift helper (4/C) and the
# composite target you typically want: "build everything" before
# Claude Desktop spawns it.

BINDIR        := bin
PROTONMCP     := $(BINDIR)/protonmcp
PROTONMCPD    := $(BINDIR)/protonmcpd
SHIM          := $(BINDIR)/protonmcp-shim
TOUCHID_DIR   := helpers/touchid
TOUCHID       := $(TOUCHID_DIR)/protonmcp-touchid
LOCKWATCH_DIR := helpers/lockwatch
LOCKWATCH     := $(LOCKWATCH_DIR)/protonmcp-lockwatch

.PHONY: all
all: $(PROTONMCP) $(PROTONMCPD) $(SHIM) $(TOUCHID) $(LOCKWATCH)

.PHONY: protonmcp
protonmcp: $(PROTONMCP)

.PHONY: protonmcpd
protonmcpd: $(PROTONMCPD)

.PHONY: shim
shim: $(SHIM)

$(PROTONMCP): $(shell find cmd internal -name '*.go' 2>/dev/null) go.mod go.sum
	@mkdir -p $(BINDIR)
	go build -o $@ ./cmd/protonmcp

# Daemon variant. Phase 6/A: same internal/serve.Runtime, transport
# is a Unix socket accept loop instead of stdin/stdout.
$(PROTONMCPD): $(shell find cmd internal -name '*.go' 2>/dev/null) go.mod go.sum
	@mkdir -p $(BINDIR)
	go build -o $@ ./cmd/protonmcpd

# Phase 6/B: stdio↔socket forwarder Claude clients spawn instead
# of serve-stdio. Tiny binary, no internal/ deps; the cross-binary
# coordination lives in the daemon.
$(SHIM): $(shell find cmd/protonmcp-shim -name '*.go' 2>/dev/null) go.mod go.sum
	@mkdir -p $(BINDIR)
	go build -o $@ ./cmd/protonmcp-shim

# Touch ID helper. swiftc is part of the Xcode command-line tools;
# CI's macos-14 runner has it, dev machines need `xcode-select
# --install` if missing.
$(TOUCHID): $(TOUCHID_DIR)/main.swift
	swiftc -O -o $@ $<

.PHONY: touchid
touchid: $(TOUCHID)

# Phase 7/A — screen-lock / sleep watcher. CFRunLoop-based; uses
# AppKit's NSWorkspace and DistributedNotificationCenter. Linked
# against AppKit + Foundation.
$(LOCKWATCH): $(LOCKWATCH_DIR)/main.swift
	swiftc -O -o $@ $<

.PHONY: lockwatch
lockwatch: $(LOCKWATCH)

.PHONY: test
test:
	go test ./...

.PHONY: race
race:
	go test -race ./...

.PHONY: clean
clean:
	rm -f $(PROTONMCP) $(PROTONMCPD) $(SHIM) $(TOUCHID) $(LOCKWATCH)
