# Repeated multi-IP login coincidence semantics

Version 0.3.0 supports temporal coincidence of successful POP3/IMAP logins. It does **not** reconstruct the duration or actual overlap of sessions, identify device owners, or establish unauthorized access.

## Grouping and time

Use the same host, exact account string, protocol and canonical unordered IP pair. IPv4-mapped IPv6 is normalized to IPv4 for this detector only. Different hosts/protocols/accounts are never silently merged. Confirm year and timezone first; only unique UTC timestamp candidates enter correlation. Missing, nonexistent and repeated-hour ambiguous times remain in original evidence and are counted as excluded from the detector.

Qualifying logins can occur in different files and in any input order. SQLite stores and sorts them by UTC. One representative per host/account/protocol/IP/UTC-second is retained deterministically, so repeated rows and same-second endpoint logins cannot inflate pairs. All original raw rows remain in events.jsonl.

## Window and counts

Two distinct endpoints within the inclusive configured number of seconds form a pair occurrence. Window zero requires the exact same second. For each pair, count at most one occurrence per **ending UTC second**. If several candidate matches end at that second, keep the shortest gap; ties use deterministic evidence ordering. This permits a later exact-second match to replace an earlier near match without increasing occurrence count.

Pair summaries report occurrences, distinct local ending days, and exact-second occurrences. Three endpoints yield three pairs, not one incident. A polling burst can contribute several ending seconds; these are not asserted to be independent polling cycles. YAML thresholds select repeated patterns; all summaries and occurrence evidence remain exported even below threshold.

## Outputs

- `multi-ip-occurrences.jsonl`: both login event IDs, source hashes, file/line/byte offsets, endpoint IPs, local timestamps with offsets, UTC timestamps and gap.
- `multi-ip-summary.jsonl`: pair identity/counts, first/last UTC/local times, first/last evidence and an evidence-file reference.
- `correlation.sqlite`: disk-backed logins and pair-occurrence state retained for traceability; contains sensitive data.
- `findings.jsonl`: qualifying summaries with `finding_type: correlation`, `correlation_id`, rule metadata and `status: unreviewed`. Ordinary findings have `finding_type: event` and `event_id`.
- `manifest.json`: effective window, override, exact excluded IPs, grouping/count/time policies and coverage counters. `review_candidate_correlations` is separate from `review_candidate_events`.

Repeat `--exclude-correlation-ip` for confirmed proxy endpoints; exclusions never delete raw events or suppress PIN/mail actions. There is no automatic proxy trust list. Custom rule directories without an active correlation rule disable the detector; correlation CLI settings then fail rather than being ignored.

## Report metadata

Each report must state: report revision; generation date/time/timezone; engine name; engine URL; engine version. Example: “Report revision 1.0 | Generated 2026-01-01T12:00:00+00:00 | Engine Artefact Finder | https://github.com/mariovilnius/artefact-finder | Engine 0.3.0-beta.1”. This is a synthetic format example, not a case timestamp. Engine and generation metadata are available in the manifest; the downstream report builder assigns its own real report revision.
