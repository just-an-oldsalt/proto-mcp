//go:build !darwin

package caller

// resolveBinary on non-macOS platforms is a stub. CI runs Linux for
// vulncheck-only steps, but the actual binary is macOS-only — see
// the build matrix in .github/workflows/ci.yml. Compile-clean here
// lets `go vet` and unit tests run on the Linux containers without
// dragging in libproc.
func resolveBinary(pid int) (string, error) {
	return "", nil
}
