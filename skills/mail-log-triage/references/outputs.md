# Beta helper output contract

`events.jsonl`: parsed Dovecot-prefixed rows, including unknown event types. Each contains original text, source hash, line, byte offset, deterministic event ID, time candidates and applicable fields. Actions do not receive an inferred source IP. A null value means unknown, not success or zero.

`unparsed.jsonl`: rows not recognized as Dovecot syslog, with provenance. This is necessary to assess coverage.

`findings.jsonl`: lexical PIN-subject and large-RETR review candidates referencing event IDs. No severity verdict, session linking or false-positive filtering is implied.

`ip-summary.csv`: raw per-account/IP/protocol/event-type counts. Formula-triggering initial characters are prefixed for safe spreadsheet viewing; JSONL preserves original data. There is no company allowlist or automatic malicious classification.

`manifest.json`: source hashes/sizes/line counts, parser version, invocation time settings, thresholds, coverage and limitations. Parser counts are not a full record of SMTP, webmail or control-panel activity.

Outputs may contain sensitive addresses, subjects and message IDs. Do not commit them. Use only synthetic examples in bug reports and public tests. The helper refuses an existing output directory; if a run fails, consider the new directory incomplete and use a different new directory for a retry. It never deletes an output directory automatically.

No multi-year inference, compressed input, HTML/PDF report builder, RDAP lookup, automatic message-ID second pass or concurrent session reconstruction is included in beta 0.1.0.
