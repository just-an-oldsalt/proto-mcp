# Proton AppVersion Request

Draft email to Proton's developer relations team requesting a
legitimate AppVersion (user-agent identifier) for proto-mcp.

The current behaviour, baked in since Phase 0, is to send Proton API
requests with `AppVersion: macos-bridge@3.24.2` — impersonating
Proton's own Bridge desktop client. This works because go-proton-api
hardcodes that user-agent for its compatibility surface, but it
creates two risks for any public distribution of proto-mcp:

1. If Proton notices unusual Bridge-tagged traffic patterns coming
   from non-Bridge clients (different IP fan-out, different request
   timing, different endpoint mix), they could change auth in a way
   that breaks us. Bridge gets compatibility commitments; we don't.
2. Public distribution under an impersonated client ID violates the
   spirit of Proton's API terms, which expect each integrator to
   identify themselves honestly.

Phase 7 closes both. Once a real `protonmcp@<version>` AppVersion is
granted, the user-agent constant in `internal/proton/client.go`
flips and every subsequent build (including the eventual Homebrew
cask) ships with a legitimate identifier.

The email below is the outreach. Send to the contact path Proton
publishes for Bridge / API integration partnerships (likely
`developer@proton.me` or via their open-source coordination form).

---

## Email draft

**To:** developer@proton.me (verify current contact via
https://proton.me/business and the Bridge GitHub repo)

**Subject:** AppVersion request for proto-mcp (open-source MCP
bridge for Claude Desktop)

> Hi Proton developer team,
>
> I'm building **proto-mcp**, an open-source macOS daemon that
> bridges Proton Mail to local LLM applications via the Model
> Context Protocol. It is the personal-use equivalent of Bridge for
> Claude Desktop / Claude Code: the user logs in once with their
> Proton credentials, proto-mcp resumes the session from the macOS
> Keychain on each launch, and Claude can then read, search,
> compose, label, and send mail through MCP tool calls — every
> sensitive operation gated by macOS Touch ID and an explicit
> NSAlert showing the literal recipient list before sending.
>
> The repository is here: https://github.com/just-an-oldsalt/proto-mcp
>
> proto-mcp is built on `go-proton-api` (your published Go client)
> and follows the same protocol Bridge uses. Currently it sends
> requests with `AppVersion: macos-bridge@3.24.2` because that is
> the default the Go client ships with. I would like to switch to
> a dedicated AppVersion that identifies proto-mcp honestly:
>
> - **Proposed AppVersion:** `protonmcp@1.0.0` (semver, bumped on
>   each release tag)
> - **Project URL:** https://github.com/just-an-oldsalt/proto-mcp
> - **Distribution:** open-source, signed + notarized Mac
>   binaries, planned Homebrew tap. No SaaS component; every
>   instance runs locally as the end-user's own Mac process.
> - **User base:** personal use today; opening to a small group of
>   technical Claude users once Phase 7 (code signing + Keychain
>   ACL hardening) lands. Not commercial.
> - **Account types supported:** standard Proton Mail accounts
>   (Free / Mail Plus / Unlimited / Visionary). Two-password mode
>   handled. No business / VPN / Drive / Calendar access at this
>   time (Mail only).
> - **Scope:** read + search + compose + send mail. Local SQLite
>   mirror for fast search; no message bodies leave the user's
>   machine except through normal Proton Mail send.
>
> Could you grant proto-mcp a dedicated AppVersion identifier?
> Happy to provide more detail on the architecture, security
> model, or expected request volume per user. The current Phase 7
> work includes Developer ID signing and Keychain ACL hardening,
> so the binary identity story will be solid by the time the
> AppVersion lands in production.
>
> Thanks for the work you do on Bridge and on the API in general —
> the published Go client made this project possible.
>
> Best,
> Richard Dort
> claude.ai.colonial719@passmail.net
> https://github.com/just-an-oldsalt

---

## Lead time and follow-up

- Initial response: expect 3–10 business days.
- AppVersion grant: typically arrives via email with a confirmation
  of the identifier string they've allocated for us.
- If no response after 2 weeks, send a polite follow-up. Try the
  Proton Bridge GitHub repo's discussion forum as a secondary
  channel (they're more responsive there for technical questions
  than the support email).

Once granted, the change is mechanical:

```go
// internal/proton/client.go (currently set in pkg init)
const defaultAppVersion = "protonmcp@" + Version  // was: "macos-bridge@3.24.2"
```

Plus a one-line README update noting the legitimate identifier.

## Status

- [ ] Email drafted (this document)
- [ ] Email sent — date:
- [ ] Acknowledgement received — date:
- [ ] AppVersion granted — identifier:
- [ ] User-agent flip merged — PR:
