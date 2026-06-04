package main

import (
	"encoding/xml"
	"strings"
	"testing"
)

// TestRenderPlistValidXML — the plist must parse as XML even if
// xml.Unmarshal doesn't grok the full plist schema (key/value
// pairs without nesting are ambiguous). A failing parse here means
// we've produced something launchctl will reject at bootstrap.
func TestRenderPlistValidXML(t *testing.T) {
	out, err := renderPlist("/usr/local/bin/protonmcpd", "/Users/x/Library/Logs/protonmcp/daemon.log")
	if err != nil {
		t.Fatalf("renderPlist: %v", err)
	}
	dec := xml.NewDecoder(strings.NewReader(string(out)))
	for {
		_, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("xml parse: %v\n%s", err, out)
		}
	}
}

func TestRenderPlistContainsExpectedKeys(t *testing.T) {
	out, err := renderPlist("/usr/local/bin/protonmcpd", "/Users/x/Library/Logs/protonmcp/daemon.log")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		`<key>Label</key>`,
		`<string>zone.dort.protonmcpd</string>`,
		`<key>ProgramArguments</key>`,
		`<string>/usr/local/bin/protonmcpd</string>`,
		`<key>RunAtLoad</key>`,
		`<true/>`,
		`<key>KeepAlive</key>`,
		`<key>SuccessfulExit</key>`,
		`<key>StandardErrorPath</key>`,
		`/Users/x/Library/Logs/protonmcp/daemon.log`,
		`<key>ProcessType</key>`,
		`<string>Background</string>`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("plist missing %q\n%s", want, s)
		}
	}
}

// TestRenderPlistEscapesXMLInPaths — guards against a future
// install path containing characters XML doesn't tolerate raw
// (apostrophes, ampersands, angle brackets).
func TestRenderPlistEscapesXMLInPaths(t *testing.T) {
	out, err := renderPlist("/Users/Joe & Sue/bin/protonmcpd", "/tmp/log<test>.log")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// Raw ampersand or angle bracket would break the parser.
	if strings.Contains(s, "Joe & Sue") {
		t.Errorf("unescaped ampersand survived: %s", s)
	}
	if strings.Contains(s, "log<test>") {
		t.Errorf("unescaped angle bracket survived: %s", s)
	}
	// Escaped forms must be present.
	if !strings.Contains(s, "Joe &amp; Sue") {
		t.Errorf("expected &amp; entity: %s", s)
	}

	// And the result still parses as XML.
	dec := xml.NewDecoder(strings.NewReader(s))
	for {
		_, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("xml parse: %v\n%s", err, s)
		}
	}
}

// TestRenderPlistKeepAliveOnlyOnCrash — D44 guard: KeepAlive must be
// the {SuccessfulExit: false} dict form (restart on crash only), not
// a bare <true/> (restart always). A bare true turns the daemon's
// deliberate "login required" exit-0 into a relaunch loop that
// re-fires the Touch ID startup gate every ~10 seconds.
func TestRenderPlistKeepAliveOnlyOnCrash(t *testing.T) {
	out, err := renderPlist("/usr/local/bin/protonmcpd", "/tmp/daemon.log")
	if err != nil {
		t.Fatal(err)
	}
	// Compare with whitespace stripped so indentation changes don't
	// produce false failures.
	flat := strings.Join(strings.Fields(string(out)), "")
	want := `<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>`
	if !strings.Contains(flat, want) {
		t.Errorf("KeepAlive is not the SuccessfulExit=false dict form:\n%s", out)
	}
	if strings.Contains(flat, `<key>KeepAlive</key><true/>`) {
		t.Errorf("KeepAlive regressed to bare <true/> (D44):\n%s", out)
	}
}

// TestDaemonLabelMatchesPlist — guard against a refactor where
// the const label and the plist's Label tag drift apart.
func TestDaemonLabelMatchesPlist(t *testing.T) {
	out, _ := renderPlist("/bin/x", "/tmp/x.log")
	if !strings.Contains(string(out), "<string>"+daemonLabel+"</string>") {
		t.Errorf("plist Label drifted from const daemonLabel %q", daemonLabel)
	}
}
