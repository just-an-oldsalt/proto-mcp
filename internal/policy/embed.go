package policy

import _ "embed"

// defaultYAML is the policy that ships with the binary. Embedded at
// build time via //go:embed so users get a sane default even with
// no override file present.
//
// Edits to default.yaml require a rebuild. The intent is that this
// file rarely changes — once Phase 5 ships, modifying defaults is
// a deliberate security decision, not a config tweak.
//
//go:embed default.yaml
var defaultYAML []byte
