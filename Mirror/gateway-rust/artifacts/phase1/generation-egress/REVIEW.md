# Scoped implementation review

- Exact token predicate and server-owned encrypted credential binding protect me/list from adopting a new login/bundle. Existing auth-refresh assertions remain present. The original seven-case gate failed before implementation; the final twelve-case gate is identical across prior/current/rollback archives.
- A persisted random epoch is necessary for demonstrated A→B→A transitions; normalized unchanged settings do not rotate it. Meaningful session/proxy backup restores also rotate it so restoring an old settings row cannot reactivate a stale binding. No new database table or second identity store was added.
- Network calls occur after scoped database guards are released. New clients are built from captured settings with no environment proxy, no redirect and no protocol retry. There is no general pool/registry or fallback state machine.
- Selected nodes, unsupported transport and proxy plus unbound global CF clearance are explicit failures, not partial success. Disabled/default proxy with no selected node is an explicit direct profile.
- The selected account profile does not govern Django/CDN/CF service traffic or unopened media/voice/WS. No full browser/TLS/device consistency claim is made.
- Initial E0308 API-error conversion and E0502 payload borrow errors are retained in `after-first.log` and `bundle-first-compile-error.json`; fixed locally before all-target tests/Clippy passed. No test was skipped or weakened.
- Real token was not read; native `:memory:` diagnosis used a synthetic marker and only one loopback GET me. The live adapter must still pass independent safety review before any secret-file read.
