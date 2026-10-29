# Artefact Finder v0.4.0-beta.2

## Added

- Offline IP association views: configurable IPv4/IPv6 network buckets,
  supplied registration/operator/ASN mappings, overlapping group membership,
  shared endpoints across accounts and adjacent login sequences.
- Cross-mailbox comparison of shared authentication endpoints, last failure
  to first success, and subsequent mail actions or positive RETR/del counters.
- Large-transfer context with separately labelled candidate login IPs.
- Bulk copy/delete-flag/expunge grouping with distinct mailbox/UID/Message-ID keys.
- MIME-decoded security-subject candidates followed by full Message-ID within
  the exact account and host; empty IDs cannot merge unrelated actions.
- Offline HTML review generation, policy/module hashes and report metadata.
- Separate YAML comparison policies and expanded methodology documentation.

## Interpretation and compatibility

- No network enrichment, blocking, live mailbox access or automatic incident verdicts.
- Multiple devices and dynamic IPs may belong to one user; shared NAT/VPN IPs
  may represent different people. Transitive/overlapping groups are not actors.
- Proxy endpoints do not reveal webmail browser IPs. Their mail actions remain visible.
- Nearby actions do not inherit a login IP. RETR counts commands, not unique
  messages or a confirmed full mailbox copy; large retrieval can be synchronization.
- Copy to Trash, delete flag and expunge remain distinct. No whole-folder or
  whole-mailbox deletion is inferred. Ambiguous timestamps are not correlated.
- Existing parser/event rule behavior and raw duplicate counts are retained.
  All modules now report 0.4.0-beta.2; older analysis metadata is preserved.
- Comparison indexes and output folders must be new. Compatible retained indexes
  require provenance verification by the caller.

## Validation and licensing

52 synthetic tests cover parsing, policies, temporal boundaries, account/host
separation, duplicate message keys, empty IDs, unknown action attribution, proxy
handling, and HTML escaping. Python 3.10+; PyYAML and timezone data as declared.
MIT licensed; no CrowdSec/Fail2ban source or filter expressions are bundled.
Release artifacts contain source, documentation and synthetic tests only.
No customer logs, customer email addresses, IP inventories, ownership caches,
case timelines, generated reports or credentials are included.
