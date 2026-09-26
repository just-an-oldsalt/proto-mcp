package mcp

import (
	"fmt"
	"sync"
	"time"
)

// PROTO-152 — agent-requested unlock.
//
// A locked daemon used to hand the model a dead end: "run `protonmcp
// unlock`", an instruction only the human can carry out, in a
// terminal, in another window. The daemon locks on screen lock and
// sleep, so this is the normal state every morning — Claude reports
// that mail is broken and the user has to go fix it out-of-band.
//
// The security property that matters is that a *human authorizes with
// Touch ID*, not that a human types the command. So a locked tool
// call may now raise the prompt itself and retry once the user
// approves. The sensor still gates it; the model can ask, never
// grant.
//
// What that does introduce is a lever on the prompt. Anything the
// model reads — mail bodies above all — can try to steer it into
// calling a tool, and each locked call is a chance to raise a dialog.
// The failure mode isn't unauthorized access, since an attacker can't
// supply a fingerprint; it's prompt fatigue, a user eventually
// tapping the sensor to stop the nagging. unlockGate is what bounds
// that: one prompt in flight at a time, and a cooldown after any
// prompt the user didn't approve.

// defaultUnlockCooldown is how long a declined (or failed) unlock
// suppresses further prompts.
//
// Long enough that declining twice in a row is a deliberate act
// rather than something a tool-call loop can produce in a second;
// short enough that a user who declines by accident isn't locked out
// of the convenience for the rest of the session. `protonmcp unlock`
// bypasses it entirely, so the cooldown is never a dead end.
const defaultUnlockCooldown = 60 * time.Second

type unlockGate struct {
	mu       sync.Mutex
	inFlight bool
	// nextOK is the earliest time another prompt may be raised. Zero
	// means "no restriction".
	nextOK   time.Time
	cooldown time.Duration
	// now is injectable so the cooldown is testable without sleeping.
	now func() time.Time
}

func newUnlockGate() *unlockGate {
	return &unlockGate{cooldown: defaultUnlockCooldown, now: time.Now}
}

func (g *unlockGate) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

// begin reserves the right to raise a prompt. Returns false plus a
// user-facing explanation when a prompt is already pending or the
// cooldown is still in force. Every successful begin must be paired
// with an end.
func (g *unlockGate) begin() (bool, string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.inFlight {
		return false, "an unlock prompt is already waiting for approval on this Mac"
	}
	if now := g.clock(); !g.nextOK.IsZero() && now.Before(g.nextOK) {
		wait := g.nextOK.Sub(now).Round(time.Second)
		return false, fmt.Sprintf(
			"an unlock prompt was not approved; not asking again for %s "+
				"(run `protonmcp unlock` to override)", wait)
	}
	g.inFlight = true
	return true, ""
}

// end releases the reservation. A non-nil err starts the cooldown —
// including on a cancelled context, since a client that abandons
// requests mid-prompt can otherwise re-raise the dialog as fast as it
// can retry.
func (g *unlockGate) end(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.inFlight = false
	if err == nil {
		g.nextOK = time.Time{}
		return
	}
	cooldown := g.cooldown
	if cooldown <= 0 {
		cooldown = defaultUnlockCooldown
	}
	g.nextOK = g.clock().Add(cooldown)
}
