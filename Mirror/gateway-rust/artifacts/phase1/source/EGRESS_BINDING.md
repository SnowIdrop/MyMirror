# Read-path generation / egress binding — scoped candidate contract

This is not end-to-end browser fingerprint acceptance. No new business paths,
remote browser, impersonation transport, real token, or production change is included.

## Supported profiles and scope

- Absent/default `mirror_proxy`, or explicit `enabled:false`: direct via a client
  with environment proxies disabled. Unused URL/credential fields do not select an exit.
- `enabled:true`: one explicit HTTP numeric-loopback proxy origin (`proxy_url`),
  optional string/null `username/password` for proxy Basic authentication.
- `transport_mode` is `reqwest` only. Nodes must be absent/empty; any selected
  `proxy_node_id` fails before chat egress. No node schema/selection is claimed.
- Enabled proxy plus configured `CF_BYPASS_URL` fails explicitly: the existing
  global clearance cache has no verified proxy/profile provenance. No old clearance
  is silently moved to the proxy. This combination remains unfinished.
- Selected profile applies to access/session-token exchange, login validation,
  token diagnostics/user-info, authenticated me/list and auth-session refresh.
  Django authority/management, public CDN and the CF sidecar still use their
  separately configured direct service clients. Files/voice/WS are not opened.
- Business and explicit proxy diagnostic clients do not follow redirects and
  have reqwest protocol retries disabled. No generation retry is added; generation
  routes remain gated. A diagnostic reports 302 rather than following it.

## Binding and transitions

The existing encrypted `rust_authorizations.payload` gets server-owned
`rust_egress_binding` and `rust_credential_binding`. Client values are overwritten.
The binding covers the actual credential/cookie bundle and account, normalized
approved proxy settings, a persisted epoch, configured upstream references, and
the implemented read transport/UA profile identifier. It does not represent
browser Client Hints, JS runtime, TLS equivalence or a discovered device identity.

Ordinary requests retain the original mirror-token hash. Following authority
network waits, and when loading credentials, the original token and binding must
still match. They cannot select a new login's token/cookies by `(user,account)`.
No database lock is held while awaiting network. An already dispatched read may
finish using its captured old client/bundle; it never switches to a new exit.

Effective proxy changes atomically rotate `rust_egress_epoch` in settings, so
A→B→A does not revive an old binding. Old sessions require a new login (401);
configuration changes during login reject the commit (409). A missing/dead proxy
fails rather than trying direct. Unsupported node/profile input fails explicitly.
Meaningful restore of sessions/proxy/epoch settings rotates the epoch too; an
empty no-op restore does not. Restarts preserve unchanged bindings with the same
database, encryption key and configured profile/origins. Old pre-binding sessions
fail closed; they are not silently backfilled or imported.

This is still not a complete backup/ACL/resource/real-time revocation acceptance.

## First real read-only validation (not armed by this document)

Prefer a new owned loopback gateway process with `DATABASE_PATH=:memory:`, fresh
admin/encryption keys, fixed approved chat origin and explicit tested egress.
POST only `/api/diagnose-chatgpt-auth` with **access_token only**, no session_token:
this performs GET `/backend-api/me` and does not create sessions/accounts or call
close-memory. The safe adapter must discard `user_info`, `last_error` and all raw
responses; output only allowed booleans/sanitized status.

Stable binary/source hashes, independent egress verification and the separate
safe-runner input/owned-listener gates must pass before any secret file is read.
Never use Django's existing add-account/refresh button: it invokes close-memory.
Never put the real token in argv, environment, transcripts, logs, Git or evidence.
This narrow check is not complete login/handoff, Django identity/ACL, HTML or
end-to-end upstream identity acceptance.
