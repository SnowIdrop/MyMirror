# Static batch review

- Scope: `source/src/server/static_assets.rs`, its two entry-point lines, and `source/tests/static_assets.rs`.
- Positive request/response header lists are justified by observed original Authorization forwarding and a test Set-Cookie response; no credential-bearing sender is reused.
- URL validation rejects traversal/encoded paths before `Url::set_path`; target host comes only from immutable Config. No generic external proxy was added.
- JS/CSS MIME, redirect, method and path gates protect the newly public route; errors remain failures rather than successful empty assets. No buffer, DB lock, retry or speculative resource ownership was introduced.
- Five integration tests cover credentials, path/verb gates, response types/redirects, HEAD/304/errors and first-chunk streaming. The unit matrix covers path translation/traversal.
- Auth refresh and HTML initialization remain unimplemented/gated; no cross-user safety claim is made for the synthetic upstream HTML.
