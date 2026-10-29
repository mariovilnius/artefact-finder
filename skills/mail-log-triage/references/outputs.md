# Beta helper output contract

`events.jsonl`: parsed Dovecot-prefixed rows, including unknown event types. Each contains original text, source hash, line, byte offset, deterministic event ID, time candidates and applicable fields. Actions do not receive an inferred source IP. A null value means unknown, not success or zero.

`unparsed.jsonl`: rows not recognized as Dovecot syslog, with provenance. This is necessary to assess coverage.

`findings.jsonl`: YAML rule review candidates referencing event IDs. Each `rules` item includes ID, version, title, level, explanation and false positives. `level` is a review label, not confidence of compromise. Version 0.2 replaces the former `reasons` array. Built-ins cover explicit auth failures, PIN-subject operations, large RETR counters and extended-profile incomplete connections.

`ip-summary.csv`: raw per-account/IP/protocol/event-type counts. Formula-triggering initial characters are prefixed for safe spreadsheet viewing; JSONL preserves original data. There is no company allowlist or automatic malicious classification.

`manifest.json`: source hashes/sizes/line counts, parser version, invocation time settings, rule IDs/versions/hashes, selected profile, threshold override, coverage and limitations. Parser counts are not a full record of SMTP, webmail or control-panel activity. `review_candidate_events` counts events matching one or more rules, not total rule hits.

Outputs may contain sensitive addresses, subjects and message IDs. Do not commit them. Use only synthetic examples in bug reports and public tests. The helper refuses an existing output directory; if a run fails, consider the new directory incomplete and use a different new directory for a retry. It never deletes an output directory automatically.

Version 0.3 adds pair summaries/occurrences, disk-backed state and correlation findings described in [correlation semantics](correlation.md). Manifests also contain `engine` (name, URL, version), manifest schema version, analysis start UTC, generated UTC and optional generated local timestamp. These describe result generation, not event times or a downstream report's revision.

Version 0.4 adds offline IP association exports and cross-mailbox comparisons, security-message action tracking, and an HTML review renderer. See [IP associations](ip-relations.md) and [cross-mailbox outputs](cross-mailbox.md). No multi-year inference, compressed input, PDF generator, online RDAP lookup, general session attribution or concurrent session reconstruction is included. Login-time coincidence detection is not actual session reconstruction.
