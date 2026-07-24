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

# Build inputs for the Go binaries. NOT just *.go: the binaries also
# compile cgo (.c/.h, e.g. internal/keystore/access_control_darwin.*)
# and embed assets via //go:embed (internal/policy/default.yaml,
# internal/store/migrations/*.sql). Listing those here means editing a
# migration, the default policy, or the keychain cgo actually triggers a
# rebuild — with a *.go-only prerequisite, `make all` would report
# "nothing to be done" and ship a stale binary.
GO_INPUTS := $(shell find cmd internal -type f \( \
	-name '*.go' -o -name '*.c' -o -name '*.h' -o \
	-name '*.yaml' -o -name '*.sql' \) 2>/dev/null)

# -----------------------------------------------------------------------------
# Version stamping.
#
# VERSION is overridable so `make release VERSION=v1.0.0` stamps the tag
# being cut rather than whatever `git describe` reports. The leading "v"
# is stripped so `protonmcp version` prints "1.0.2", matching the cask
# version and the release tarball name.
#
# DATE is the *commit* timestamp, not the wall clock: stamping the build
# time would make two builds of the same commit differ, which breaks
# reproducibility and — because the daemon pins its own SHA-256 at
# install time — would force a `daemon install` after every rebuild.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null)
DATE    := $(shell git log -1 --format=%cI 2>/dev/null)

BUILDINFO := github.com/just-an-oldsalt/proto-mcp/internal/buildinfo
LDFLAGS   := -X $(BUILDINFO).version=$(VERSION:v%=%) \
             -X $(BUILDINFO).commit=$(COMMIT) \
             -X $(BUILDINFO).date=$(DATE)

# The shim keeps its own stdlib-only version var (see its package doc),
# so it gets a different -X target.
SHIM_LDFLAGS := -X main.version=$(VERSION:v%=%)

.PHONY: version
version:
	@echo "VERSION=$(VERSION:v%=%) COMMIT=$(COMMIT) DATE=$(DATE)"

# -----------------------------------------------------------------------------
# Universal (arm64 + x86_64) builds.
#
# `make all` builds for the host arch only — that's what you want while
# developing. `make universal` builds both slices and lipo's them, which
# is what a release ships: the cask previously declared
# `depends_on arch: :arm64`, so every Intel Mac was simply unable to
# install.
#
# Cross-compiling the Go binaries needs CGO (internal/keystore wraps
# Security.framework), which means handing the C compiler an explicit
# -arch. The macOS clang that ships with the command line tools can
# target both, so no extra toolchain is required.
UNIVERSAL_DIR := $(BINDIR)/universal
GO_PRODUCTS   := protonmcp protonmcpd protonmcp-shim

# cgoCC maps a GOARCH to the clang -arch flag for that slice.
cc_for_arm64 := clang -arch arm64
cc_for_amd64 := clang -arch x86_64

# Deployment target for the Swift helpers. Matches the cask's
# `depends_on macos: :ventura` (13.0) — building against a newer SDK is
# fine, but the minimum has to agree or the helper refuses to launch on
# the oldest supported OS.
SWIFT_MACOS_MIN := 13.0

.PHONY: universal
universal: $(addprefix $(UNIVERSAL_DIR)/,$(GO_PRODUCTS)) \
           $(UNIVERSAL_DIR)/protonmcp-touchid \
           $(UNIVERSAL_DIR)/protonmcp-lockwatch
	@echo "Universal binaries in $(UNIVERSAL_DIR):"
	@for b in $^; do printf '  %s: ' "$$b"; lipo -archs "$$b"; done

# One rule per Go product: build each slice into a temp path, then lipo.
# $* is the product name (protonmcp, protonmcpd, protonmcp-shim).
$(UNIVERSAL_DIR)/%: $(GO_INPUTS) go.mod go.sum
	@mkdir -p $(UNIVERSAL_DIR)
	@ldflags='$(LDFLAGS)'; \
	if [ "$*" = "protonmcp-shim" ]; then ldflags='$(SHIM_LDFLAGS)'; fi; \
	for arch in arm64 amd64; do \
		case $$arch in \
			arm64) cc='$(cc_for_arm64)';; \
			amd64) cc='$(cc_for_amd64)';; \
		esac; \
		echo "  go build $* ($$arch)"; \
		CGO_ENABLED=1 GOOS=darwin GOARCH=$$arch CC="$$cc" \
			go build -ldflags "$$ldflags" -o $@.$$arch ./cmd/$* || exit 1; \
	done
	@lipo -create -output $@ $@.arm64 $@.amd64
	@rm -f $@.arm64 $@.amd64

$(UNIVERSAL_DIR)/protonmcp-touchid: $(TOUCHID_DIR)/main.swift
	@mkdir -p $(UNIVERSAL_DIR)
	swiftc -O -target arm64-apple-macos$(SWIFT_MACOS_MIN)  -o $@.arm64 $<
	swiftc -O -target x86_64-apple-macos$(SWIFT_MACOS_MIN) -o $@.amd64 $<
	@lipo -create -output $@ $@.arm64 $@.amd64
	@rm -f $@.arm64 $@.amd64

$(UNIVERSAL_DIR)/protonmcp-lockwatch: $(LOCKWATCH_DIR)/main.swift
	@mkdir -p $(UNIVERSAL_DIR)
	swiftc -O -target arm64-apple-macos$(SWIFT_MACOS_MIN)  -o $@.arm64 $<
	swiftc -O -target x86_64-apple-macos$(SWIFT_MACOS_MIN) -o $@.amd64 $<
	@lipo -create -output $@ $@.arm64 $@.amd64
	@rm -f $@.arm64 $@.amd64

.PHONY: all
all: $(PROTONMCP) $(PROTONMCPD) $(SHIM) $(TOUCHID) $(LOCKWATCH)

.PHONY: protonmcp
protonmcp: $(PROTONMCP)

.PHONY: protonmcpd
protonmcpd: $(PROTONMCPD)

.PHONY: shim
shim: $(SHIM)

$(PROTONMCP): $(GO_INPUTS) go.mod go.sum
	@mkdir -p $(BINDIR)
	go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/protonmcp

# Daemon variant. Phase 6/A: same internal/serve.Runtime, transport
# is a Unix socket accept loop instead of stdin/stdout.
$(PROTONMCPD): $(GO_INPUTS) go.mod go.sum
	@mkdir -p $(BINDIR)
	go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/protonmcpd

# Phase 6/B: stdio↔socket forwarder Claude clients spawn instead
# of serve-stdio. Tiny binary, no internal/ deps; the cross-binary
# coordination lives in the daemon.
$(SHIM): $(shell find cmd/protonmcp-shim -name '*.go' 2>/dev/null) go.mod go.sum
	@mkdir -p $(BINDIR)
	go build -ldflags "$(SHIM_LDFLAGS)" -o $@ ./cmd/protonmcp-shim

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

# Overridable so the release path can sign the universal binaries
# instead of the host-arch ones:
#
#   make sign SIGN_TARGETS="$(UNIVERSAL_TARGETS)"
#
# Defaults to the host-arch layout, which is what you want when signing
# a local build for testing.
UNIVERSAL_TARGETS := $(addprefix $(UNIVERSAL_DIR)/,$(GO_PRODUCTS) protonmcp-touchid protonmcp-lockwatch)
SIGN_TARGETS ?= $(PROTONMCP) $(PROTONMCPD) $(SHIM) $(TOUCHID) $(LOCKWATCH)
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

# Post-notarization check. Uses `spctl --assess -t open
# --context context:primary-signature` — the right invocation for
# bare Mach-O CLI binaries.
#
# Why not `codesign --test-requirement="=notarized"`: that test
# checks for an attached staple ticket. CLI binaries can't be
# stapled (Apple error 73), so the requirement is never satisfied
# locally even after Apple's notary service has Accepted the
# submission. `spctl` instead triggers an online lookup and
# accurately reports "Notarized Developer ID" for our case.
#
# Why not `--type execute`: that type is for .app bundles; bare
# Mach-O fails with "the code is valid but does not seem to be an
# app" even when notarized.
.PHONY: verify-notarized
verify-notarized:
	@fail=0; \
	for bin in $(SIGN_TARGETS); do \
		echo "  check $$bin"; \
		result=$$(spctl -a -vv -t open --context context:primary-signature "$$bin" 2>&1); \
		echo "$$result"; \
		echo "$$result" | grep -q "source=Notarized Developer ID" || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then \
		echo "verify-notarized FAILED — one or more binaries did not return source=Notarized Developer ID"; \
		exit 1; \
	fi; \
	echo "All binaries assessed as Notarized Developer ID (Gatekeeper accepts)."

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

# Full local release pipeline: clean → build → sign → notarize →
# package tarball + sha256 → tag + create draft GitHub release.
#
# Runs entirely from your machine — no secrets in cloud. Requires
# DEVELOPER_ID env var, notarytool keychain profile, and `gh` CLI
# authenticated. See scripts/release-howto.md.
#
# Usage:
#   export DEVELOPER_ID='Developer ID Application: <NAME> (<TEAMID>)'
#   make release VERSION=v1.0.0
.PHONY: release
release:
	@if [ -z "$$VERSION" ]; then \
		echo "error: VERSION not set."; \
		echo "  Usage: make release VERSION=v1.0.0"; \
		exit 1; \
	fi
	./scripts/release.sh "$$VERSION"

# Bootstrap or update the Homebrew tap repo
# (github.com/just-an-oldsalt/homebrew-proto-mcp). Without args,
# creates the tap repo (if missing) and pushes a placeholder cask
# so `brew tap` succeeds. With VERSION + SHA256, updates the cask
# to point at a real release. See scripts/bootstrap-tap.sh.
.PHONY: bootstrap-tap
bootstrap-tap:
	./scripts/bootstrap-tap.sh $$VERSION $$SHA256
