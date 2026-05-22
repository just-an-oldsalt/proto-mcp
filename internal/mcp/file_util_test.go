package mcp

import "os"

// writeBytesAtomic is a tiny helper used by middleware_test.go to
// drop a YAML override file into a t.TempDir(). Not atomic in any
// real sense; the name is aspirational — tests don't need atomicity.
func writeBytesAtomic(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
