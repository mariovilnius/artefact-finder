# Artefact Finder v0.5.0-beta.1

## Added

- Explicitly opt-in offline client-continuity module for reviewing a possible
  traveling client configured with multiple mailboxes. It is not run by default.
- Observed account bundles, protocol membership, active days and bounded median
  polling gaps; canonical mapped IPv6 and same-second endpoint deduplication.
- Exact candidate first/last login, preceding and subsequent reference endpoint
  evidence, intermediate IP intervals and concurrent reference-endpoint activity.
- Separate outcomes: compatible-but-unconfirmed handover, overlapping endpoint
  activity, insufficient history and observation gaps beyond configured bounds.
- Repeatable account scope, caller-supplied or explicitly described automatic
  reference selection, confirmed proxy exclusions and a separate YAML policy.
- HTML/JSON outputs with exact source lines, offsets, component versions,
  source/policy/module provenance and explicit interpretation limits.
- Methodology and official-source product research documenting proposals and
  license boundaries without copying third-party implementations or rules.

## Interpretation and compatibility

- Account bundles, polling rhythms and IPs do not identify a person or device.
  One user can have multiple devices; NAT/VPN can represent different people.
- Login timing overlap is not reconstructed session overlap. Travel does not
  change the server timezone. Missing or ambiguous UTC is not correlated.
- No physical geolocation, impossible-travel verdict, automatic risk suppression,
  blocking, live mailbox access or network enrichment is introduced.
- Existing authentication, PIN, transfer and deletion findings remain visible.
  The optional hypothesis never inherits a missing action IP or closes an incident.
- All release modules report 0.5.0-beta.1. Older input parser metadata remains
  unchanged when a verified retained evidence index is used.

## Validation and licensing

58 synthetic tests pass locally. The expanded suite covers compatible switching,
overlapping endpoints, missing history, long gaps, empty data, canonical mapped
IPs, duplicate endpoints, proxy exclusions and ambiguous timestamps, alongside
the existing parser/correlation/rendering tests. Python 3.10+.

MIT license retained. Source, documentation, policies and synthetic tests only:
no customer logs, addresses, IP inventories, ownership caches, reports, private
indexes or credentials are included. No competitor source/rule expressions are
bundled. The previous v0.4.0-beta.2 release and tag remain unchanged.

---

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
