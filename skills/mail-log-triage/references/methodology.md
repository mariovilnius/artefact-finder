# Evidence-first mail log investigations

## Establish scope

Collect target accounts, expected protocols/devices, known admin activity, confirmed source year/timezone and known proxy/company networks. Preserve who supplied each assumption. An unknown public IP is unclassified, not an attacker.

Hash originals, preserve physical line numbers and byte offsets, count unknown rows, keep raw content. Reading line-by-line avoids holding entire source files in memory. The beta helper retains unique authentication fingerprints and IP counters in memory; very large installations should use disk-backed state. Its manifest detects input changes between hashing and parsing.

## Interpret the server format

Identify server version and configured logging templates. Dovecot `rip` is the remote peer and `lip` is the local listener. A webmail peer can hide the actual browser client. Do not merge similar account names or infer the human behind an account.

Explicit login success differs from authentication failure or a disconnected unauthenticated connection. Missing TLS markers mean unknown unless server settings establish otherwise. Keep raw count, reported attempt count and unique session count distinct. The beta script reports raw rows and only marks identical session-bearing authentication rows; it does not deduplicate findings.

## Normalize time

Use an IANA timezone and provenance for the year. Retain raw, local-with-offset and UTC candidates. A repeated autumn hour needs both candidates until resolved; a nonexistent spring time is flagged. Split multiple source years/zones into separate invocations. Do not silently derive the source year from the analysis date.

## Attribute sessions

Prefer explicit shared session keys; PID requires host and process lifetime. Same-account temporal adjacency only yields candidates. Never assign a logout or message operation to the most recent login automatically: concurrent clients and long sessions invalidate that shortcut. The helper leaves source IP null on actions/logout; session correlation is a future feature.

## Search artifacts

Build account/IP/protocol/outcome baselines before prioritizing new or rare sources. Check shared IPs across accounts, failure/success sequences, unusual protocols, security-message operations and large transfers. Record facts, alternatives, confidence and needed additional evidence for every finding. These advanced correlations are analyst steps, not implemented detectors in the beta helper.

Decode MIME subjects; match words and provider-specific templates, not random encoded session substrings. Lexical PIN matches include unrelated correspondence. After reviewing matches, follow full Message-ID with account and mailbox context across source files, including rows without subjects. The helper flags lexical matches only; cross-file message tracking is an analyst step in this beta.

Copy to Trash plus expunge from INBOX does not prove removal of the Trash copy. A delete flag differs from expunge. UID is mailbox-scoped and depends on UIDVALIDITY; Message-ID can be absent, truncated or duplicated.

RETR count is command count, not demonstrated unique messages. A large byte count may reflect a new phone, profile rebuild, migration, UIDL changes or unauthorized copying. Source IP, start time and transfer rate must remain unknown if no session key establishes them. Counter pairs other than retr are retained raw pending configuration verification.

## Enrich and request evidence

When authorized, use authoritative RIR RDAP and DNS; record response/time and distinguish current ownership from historical assignment. Registration country, PTR name and hosting ASN do not identify a subscriber or prove physical location.

Suppress a confirmed provider IP as an IP-only anomaly without dropping actions through it. Ask the provider for proxy/webmail logs and trusted forwarded-address handling to identify browser IP, User-Agent and session linkage. Security-code messages require the control-panel authentication and audit trail to establish code generation, validation, login and changes. Request precise zoned time windows and stable evidence keys. Preserve logs before retention expires.

## Sources

- Dovecot 2.3 POP3 counter configuration: https://doc.dovecot.org/2.3/settings/core/
- IMAP flags and EXPUNGE semantics: https://www.rfc-editor.org/rfc/rfc9051.html
- Python zoneinfo ambiguity handling: https://docs.python.org/3/library/zoneinfo.html

Check the actual server version before applying these references to a case.
