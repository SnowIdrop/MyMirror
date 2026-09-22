# Static batch review

- Scope: `source/src/server/static_assets.rs`, its two entry-point lines, and `source/tests/static_assets.rs`.
- Positive request/response header lists are justified by observed original Authorization forwarding and a test Set-Cookie response; no credential-bearing sender is reused.
- URL validation rejects traversal/encoded paths before `Url::set_path`; target host comes only from immutable Config. No generic external proxy was added.
- JS/CSS MIME, redirect, method and path gates protect the newly public route; errors remain failures rather than successful empty assets. No buffer, DB lock, retry or speculative resource ownership was introduced.
- Five integration tests cover credentials, path/verb gates, response types/redirects, HEAD/304/errors and first-chunk streaming. The unit matrix covers path translation/traversal.
- Auth refresh and HTML initialization remain unimplemented/gated; no cross-user safety claim is made for the synthetic upstream HTML.

## Auth follow-up

- `refresh_auth_session` scopes the DB guard to the exact-token credential snapshot; request construction, decode and both upstream waits occur after its drop. A post-I/O session check rejects intervening revocation/re-login. The concurrent revocation test verifies the DB is not held during an upstream wait.
- Plan fallback on account HTTP failure is backed by the original fixture; malformed/transport failures remain 502. Wrong-account me data returns no session rather than changing ownership.
- Fixture cleanup uses explicit SQLite connection close (transaction context alone did not close the Windows handle); this was a verifier failure, not a product exception. Candidate test artifacts now also use their own target directory, separate from all three probe variants.
- Independent ACL source was spot-checked at trusted identity parsing, administrator-only share changes, default-private/unknown rules and dynamic project audience transactions before applying its verified two-file patch. It is not exported or called by product routes.
