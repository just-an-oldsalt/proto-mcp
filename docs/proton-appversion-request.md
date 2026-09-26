# Proton AppVersion Request

Draft outreach to Proton asking for an honest client identifier
(`x-pm-appversion`) for proto-mcp, one that is granted **Mail and
Calendar** scope.

## Why this matters now

proto-mcp sends `x-pm-appversion: macos-bridge@3.24.2`, so it
identifies itself as Proton Bridge. That is our choice, not the SDK's:
go-proton-api defaults to `go-proton-api` (`DefaultAppVersion` in its
`manager_builder.go`), and the Bridge value is set in
`internal/proton/client.go` (`AppVersion`).

It has two costs:

1. **Calendar events are blocked (issue #110).** Proton scopes the
   access token to the client identity at `/auth/v4` login. Bridge is a
   mail-only client, so the session has no `calendar` scope. The
   calendar listing (`GET /calendar/v1`) still returns 200, but every
   events request returns 403:

   ```json
   {"Code":9100,"Error":"Access token does not have sufficient scope",
    "Details":{"MissingScopes":["calendar"]}}
   ```

   Neither login nor refresh takes a scope parameter, `GET
   auth/v4/scopes` is read-only, and session forks need a first-party
   client ID. So this can't be fixed in code; it needs an identifier
   from Proton that carries the calendar scope.
2. **It pollutes Proton's telemetry.** Third-party traffic that reports
   as an official client makes Bridge issues harder for Proton to
   debug. It also runs against the expectation that integrators
   identify themselves honestly.

Until this lands, proto-mcp degrades gracefully: calendar sync records
the block, `calendar_events` says events are unavailable instead of
returning an empty list, and `protonmcp doctor` shows a `calendar` warn
line.

## Precedent

Proton's Drive team introduced honest third-party identifiers of the
form

```
external-<product>-<project>@X.Y.Z-stable      (or -beta)
```

and contacted rclone to adopt them:
[rclone/rclone#9189](https://github.com/rclone/rclone/pull/9189) and
[rclone/rclone#9260](https://github.com/rclone/rclone/pull/9260). They
gave the same reason as cost 2 above. There is no published Mail or
Calendar equivalent yet, so the ask is to extend that scheme.

For proto-mcp that would look like `external-mail-protonmcp@X.Y.Z-stable`,
with the version taken from the release tag. The `<product>` segment is
Proton's call. Identifiers are product-scoped, so the email asks them to
say which one grants both scopes, rather than assuming `mail` does.

## Where to send it

- **Email:** `developer@proton.me`. **Unverified:** this address was a
  guess when the first draft was written, and nobody has confirmed that
  it exists or reaches the right team. Before sending, check Proton's
  current published contact for API or third-party integrations, or ask
  in the channel below.
- **Public issue on
  [ProtonMail/go-proton-api](https://github.com/ProtonMail/go-proton-api/issues)**:
  file this as well. It's the SDK we build on, the thread is visible to
  other third-party integrators with the same question, and it's a
  record we can link from issue #110. Keep it short: what we are, the
  9100 body, the rclone precedent, and the request.

## Email draft

**To:** developer@proton.me *(unverified, see above)*

**Subject:** Third-party client identifier with Calendar scope for
proto-mcp (open-source MCP server)

> Hi Proton team,
>
> I maintain **proto-mcp**
> (https://github.com/just-an-oldsalt/proto-mcp), an open-source macOS
> daemon that lets a user's local Claude app read their Proton Mail
> and Calendar through the Model Context Protocol. It runs entirely on
> the user's Mac. The user logs in once, the session is kept in the
> macOS Keychain, and there is no server component. Sending mail is
> gated by Touch ID and a confirmation dialog that shows the literal
> recipient list.
>
> **The request: an `external-…` client identifier for proto-mcp that
> is granted the Mail and Calendar scopes.**
>
> Today proto-mcp sends `x-pm-appversion: macos-bridge@3.24.2`. That
> was the wrong choice, for two reasons:
>
> - A Bridge session has no `calendar` scope. `GET /calendar/v1`
>   succeeds, but every events request returns
>   `{"Code":9100,"Error":"Access token does not have sufficient
>   scope","Details":{"MissingScopes":["calendar"]}}`. Calendar is half
>   of what the project does, and as far as I can tell there is no way
>   to request the scope except through the client identity.
> - Our traffic shows up as Bridge in your telemetry, which I
>   understand is exactly why the Drive team asked rclone to switch to
>   `external-drive-…` identifiers (rclone/rclone#9189, #9260).
>
> I'd like to follow the same scheme. Something like
> `external-mail-protonmcp@X.Y.Z-stable`, with the version taken from
> our release tag. I'm happy to use whatever product segment grants
> both the Mail and Calendar scopes, if that isn't `mail`.
>
> - **Scopes needed:** Mail (read, search, label, draft, send) and
>   Calendar (read events; write access is not needed yet).
> - **Built on:** `go-proton-api`, the same protocol Bridge uses.
> - **Distribution:** open source; Developer ID signed and notarized
>   macOS binaries through a Homebrew tap. Not commercial.
> - **Usage:** each install is one user on their own Mac. It uses a
>   local SQLite mirror, polls every 2 minutes, and nothing leaves the
>   machine except through normal Proton API calls.
>
> I'm happy to give more detail on the architecture, the security
> model, or expected request volume. I'll switch identifiers in the
> first release after you allocate one.
>
> Thanks for go-proton-api. This project wouldn't exist without it.
>
> Best,
> Richard Dort
> claude.ai.colonial719@passmail.net
> https://github.com/just-an-oldsalt

## A cheap experiment before (or while) waiting

This one is for the maintainer to run, because it needs a live login.
It is not part of the test suite.

hydroxide sends the generic `x-pm-appversion: Other`, and its CalDAV
work reports that it can read events. That suggests a generic
identifier may get a broader scope than Bridge does. To compare:

1. Log in with `AppVersion = "macos-bridge@3.24.2"` and record
   `auth.Scope` from the `/auth/v4` response. It is returned today but
   nothing reads it.
2. Log in with `AppVersion = "Other"` and record `auth.Scope` again.
3. If the second includes `calendar`, check that `/calendar/v1/{id}/events`
   returns 200.

Known downside: `Other` draws more human-verification (captcha, Code
9001) challenges (hydroxide#354). proto-mcp now handles 9001 through
Proton's browser flow, but it is still friction on every fresh login.
Even if it works, `Other` is a stopgap. It is no more honest an
identity than Bridge, and the request above is still the real fix.

## Once an identifier is granted

The code change is mechanical:

```go
// internal/proton/client.go
const AppVersion = "external-<product>-protonmcp@" + <release version> + "-stable"
```

Also:

- Update or drop the Bridge-mimicking `UserAgent` alongside it, and
  re-test the session-refresh behaviour that constant exists to
  protect.
- Add a README note giving the identifier.
- Close #110 once `calendar-backfill` fetches events without the 9100
  warning and `doctor` no longer shows the `calendar` line.

## Status

- [x] Draft rewritten for Calendar scope (this document)
- [ ] Contact address verified
- [ ] Email sent (date: )
- [ ] go-proton-api issue filed (link: )
- [ ] `Other` scope experiment run (result: )
- [ ] Acknowledgement received (date: )
- [ ] Identifier granted (value: )
- [ ] AppVersion switch merged (PR: )
