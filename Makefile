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
	rm -rf dist

# -----------------------------------------------------------------------------
# Phase 7/C — Developer ID signing + notarization.
#
# Operator setup in scripts/signing-setup.md. High-level shape:
#
#   make all              # build unsigned
#   make sign             # codesign each binary with hardened runtime + entitlements
#   make verify-sign      # codesign --verify (signature shape valid)
#   make notarize         # zip + submit to notarytool (no staple for CLI binaries)
#   make verify-notarized # codesign --test-requirement "=notarized"
#
# Required environment:
#   DEVELOPER_ID   "Developer ID Application: <NAME> (<TEAMID>)"
#   NOTARY_PROFILE Keychain profile (default "protonmcp-notary")
# -----------------------------------------------------------------------------

SIGN_TARGETS := $(PROTONMCP) $(PROTONMCPD) $(SHIM) $(TOUCHID) $(LOCKWATCH)
ENTITLEMENTS := scripts/protonmcp.entitlements
NOTARY_PROFILE ?= protonmcp-notary
DIST_DIR     := dist
DIST_ZIP     := $(DIST_DIR)/protonmcp.zip

.PHONY: sign
sign: $(SIGN_TARGETS)
	@if [ -z "$$DEVELOPER_ID" ]; then \
		echo "error: DEVELOPER_ID environment variable not set."; \
		echo "  Run: export DEVELOPER_ID='Developer ID Application: <NAME> (<TEAMID>)'"; \
		echo "  See scripts/signing-setup.md."; \
		exit 1; \
	fi
	@for bin in $(SIGN_TARGETS); do \
		echo "  codesign $$bin"; \
		codesign --force --timestamp --options=runtime \
			--entitlements $(ENTITLEMENTS) \
			--sign "$$DEVELOPER_ID" \
			"$$bin" || exit 1; \
	done
	@echo "All binaries signed with $$DEVELOPER_ID"

.PHONY: verify-sign
verify-sign:
	@fail=0; \
	for bin in $(SIGN_TARGETS); do \
		echo "  verify $$bin"; \
		codesign --verify --deep --strict --verbose=2 "$$bin" || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then echo "verify-sign FAILED"; exit 1; fi; \
	echo "All binaries pass codesign --verify (signature shape valid)."; \
	echo "Run 'make verify-notarized' AFTER 'make notarize' to confirm Gatekeeper acceptance."

# Post-notarization check. Uses codesign --test-requirement
# "=notarized" — the correct query for CLI binaries (spctl --assess
# --type execute is for .app bundles and rejects bare Mach-O as
# "not an app" even when notarized).
#
# A "passes" result means Apple's notary database has the binary on
# its accept list. Gatekeeper looks this up online at first launch
# and lets the binary run without a developer-unknown warning.
.PHONY: verify-notarized
verify-notarized:
	@fail=0; \
	for bin in $(SIGN_TARGETS); do \
		echo "  check $$bin"; \
		codesign --test-requirement="=notarized" --verify --verbose=2 "$$bin" || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then \
		echo "verify-notarized FAILED — one or more binaries not in Apple's notary database"; \
		exit 1; \
	fi; \
	echo "All binaries satisfy the =notarized requirement (Apple has accepted them)."

$(DIST_ZIP): sign
	@mkdir -p $(DIST_DIR)
	@rm -f $(DIST_ZIP)
	zip -j $(DIST_ZIP) $(SIGN_TARGETS)

.PHONY: notarize
notarize: $(DIST_ZIP)
	@echo "submitting $(DIST_ZIP) to notarytool (profile: $(NOTARY_PROFILE))…"
	xcrun notarytool submit $(DIST_ZIP) \
		--keychain-profile $(NOTARY_PROFILE) \
		--wait
	@echo ""
	@echo "Notarization registered with Apple."
	@echo ""
	@echo "Stapling skipped: bare Mach-O CLI binaries cannot be"
	@echo "stapled (error 73). Gatekeeper looks up the notarization"
	@echo "ticket online at first launch and caches it. To distribute"
	@echo "with an offline-checkable ticket, wrap the binaries in a"
	@echo ".pkg or .dmg (Phase 7/E) and staple THAT."
	@echo ""
	@echo "Confirm acceptance with: make verify-notarized"
