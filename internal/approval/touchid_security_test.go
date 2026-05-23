package approval

// SECURITY D4 — the production-mode refusal of PROTONMCP_TOUCHID
// can't be unit-tested directly: testing.Testing() is true for the
// entire duration of `go test`, and a subprocess spawned via
// exec.Command("go", "run", ...) can't import this package because
// of Go's internal/ rule (file outside the module subtree → import
// refused). The cmd/protonmcp binary would work, but driving it
// through enough setup to actually reach ResolveHelperPath needs a
// Keychain etc., which we deliberately don't pull into unit tests.
//
// Coverage that DOES exist:
//
//   - TestResolveHelperPathHonorsEnv exercises the env-var path
//     during tests (testing.Testing() = true → override allowed).
//     If a refactor accidentally removes the testing.Testing() gate
//     it would still pass — that's the gap.
//
// Mitigation: the gate is five lines and lives at the top of
// resolveHelperPath in path.go, named PROTONMCP_TOUCHID, with an
// error message that mentions SECURITY D4. Removing it is a
// reviewable change.
//
// Future hardening (Phase 6 or later): an integration test that
// builds cmd/protonmcp into a temp dir, then execs it with
// PROTONMCP_TOUCHID and the right subcommand to make the resolver
// path reach the gate. Out of scope for this PR.
