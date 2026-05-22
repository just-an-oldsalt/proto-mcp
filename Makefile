# proto-mcp build orchestration.
#
# The Go binary doesn't need Make — `go build ./cmd/protonmcp` is
# enough. This Makefile exists for the Swift helper (4/C) and the
# composite target you typically want: "build everything" before
# Claude Desktop spawns it.

BINDIR        := bin
PROTONMCP     := $(BINDIR)/protonmcp
TOUCHID_DIR   := helpers/touchid
TOUCHID       := $(TOUCHID_DIR)/protonmcp-touchid

.PHONY: all
all: $(PROTONMCP) $(TOUCHID)

.PHONY: protonmcp
protonmcp: $(PROTONMCP)

$(PROTONMCP): $(shell find cmd internal -name '*.go' 2>/dev/null) go.mod go.sum
	@mkdir -p $(BINDIR)
	go build -o $@ ./cmd/protonmcp

# Touch ID helper. swiftc is part of the Xcode command-line tools;
# CI's macos-14 runner has it, dev machines need `xcode-select
# --install` if missing.
$(TOUCHID): $(TOUCHID_DIR)/main.swift
	swiftc -O -o $@ $<

.PHONY: touchid
touchid: $(TOUCHID)

.PHONY: test
test:
	go test ./...

.PHONY: race
race:
	go test -race ./...

.PHONY: clean
clean:
	rm -f $(PROTONMCP) $(TOUCHID)
