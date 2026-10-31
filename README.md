# Artefact Finder

**0.5.0-beta.2** — offline, evidence-first mail log investigation. This beta adds account-isolated mailbox CSV exports and regression coverage for mixed RETR/deletion predicates. See [release notes](RELEASE_NOTES.md).

The helper streams log files, records SHA-256 and byte offsets, parses authentication and mail actions, decodes MIME subjects, and exports review candidates. It does not infer compromise, identify subscribers, correlate concurrent sessions, make network requests or change mail systems.

## Install the skill

Copy `skills/mail-log-triage` into your personal Codex skills directory (normally `~/.codex/skills/mail-log-triage`), then invoke `$mail-log-triage`. Read `SKILL.md` to see the workflow and limitations. The skill is also usable as standalone instructions without Codex.

## Run the helper

Python 3.10+:

```sh
python -m pip install -r requirements.txt
python skills/mail-log-triage/scripts/triage.py --year 2026 --timezone Europe/Vilnius --output results /path/to/mail.log
python -m unittest discover -s tests -v
```

The output directory must be new. Omit year/timezone when unconfirmed; do not guess them. Configured values apply to this invocation, so split input sets with different years/zones. Multi-year rollover inference is not supported. `--year` must be the year of the log events, not the analysis date.

Outputs include `events.jsonl`, `findings.jsonl`, `ip-summary.csv`, `manifest.json`, and `unparsed.jsonl`. The manifest records coverage and interpretation settings. Output may contain sensitive personal data; store it with the same care as the originals. JSONL is the evidence format; CSV is a formula-safe viewing export.

## Rules and authentication coverage

Built-in rules live in `skills/mail-log-triage/rules/*.yaml`:

| Rule | Default behavior |
|---|---|
| `AF-AUTH-001` | Explicit authentication failures, including temporary failures requiring context |
| `AF-MAIL-001` | Decoded PIN-subject message operations, excluding the known “pin brazing” false positive |
| `AF-TRANSFER-001` | POP3 RETR byte counters at or above 50,000,000 bytes |
| `AF-CONNECTION-001` | Incomplete authentication, only with `--profile extended` |
| `AF-CORRELATION-001` | Same host/account/protocol/IP pair with at least 2 distinct ending-second coincidences; default window 5 seconds |

Use `--rules-dir /path/to/local-rules` to replace the built-in rule directory, `--profile extended` for connection context, or `--large-retr-bytes 100000000` to override YAML RETR-byte thresholds. Rules are local trusted configuration, loaded with `yaml.safe_load`; there are no Python expressions or executable operators. See [rule schema](skills/mail-log-triage/references/rules.md).

The parser supports classic and selected modern login envelopes, `auth-worker` backend contexts, PAM syslog, SQL/LDAP/passwd-file failures, IPv6, and reported attempt counts. Explicit failure reasons stay separate from incomplete connections and backend infrastructure errors. Backend rows do not invent a POP3/IMAP protocol. Submission/managesieve login labels are retained but full SMTP/Sieve analysis is not implemented. This is format coverage, not a claim to support every Dovecot version/configuration.

**Output change from 0.1:** findings now contain structured `rules` entries instead of the old `reasons` list. Manifests contain rule IDs, versions and SHA-256 hashes, selected profile and threshold override. Raw duplicate counts and unknown action source IP remain unchanged.

## Repeated checks from multiple IPs

```sh
python skills/mail-log-triage/scripts/triage.py --year 2026 --timezone Europe/Vilnius --multi-ip-window 5 --exclude-correlation-ip 192.0.2.50 --output results /path/to/mail.log
```

`--multi-ip-window` overrides the YAML window (0..86400 seconds; zero means exactly the same UTC second). `--exclude-correlation-ip` is repeatable and affects only this detector: raw authentication and message actions remain available. There are no built-in customer/provider IP allowlists.

The detector considers successful POP3/IMAP logins only. It canonicalizes mapped IPv4 endpoints, groups by host/account/protocol, and sorts unique UTC times on disk across all input files. Unknown/ambiguous/nonexistent times are excluded from correlation and counted; original events are retained. It needs confirmed year and timezone. Missing time does not imply that no overlapping checks occurred.

Counts represent distinct pair ending UTC seconds, not people, devices, actual overlapping sessions or independent attacks. Repeated rows or multiple logins from the same endpoint in the same second do not inflate counts. A three-IP coincidence produces three pairs. Each pair also has a distinct local-day count and exact-second count. Adjust `pair_occurrences` and `pair_days` minimums in the YAML rule to require longer-term repetition.

All pair summaries and occurrences are exported, even below the YAML finding threshold. Evidence references identify both original login rows. `correlation.sqlite` is retained as disk-backed investigation state and may contain sensitive identifiers. New `findings.jsonl` records distinguish `finding_type: event` from `finding_type: correlation`; consumers must not assume every finding has a single event_id.

Every manifest records engine name, repository URL, engine version, schema version, analysis start and generation timestamps with explicit offsets. Reports produced from these results must additionally state their own report revision and generation date/time/timezone, separately from the engine version.

## Beta scope

- Dovecot-style English syslog, one physical line per event; no journald JSON or compressed input yet.
- PIN matching remains lexical triage with a narrow explicit false-positive exclusion; no automatic intent determination.
- No session-source attribution for actions, no SMTP analysis, no RDAP or geolocation.
- Repeated-hour timestamps retain both UTC candidates. Missing timezone/year stays unknown.
- All source rows remain counted; exact duplicates remain in events and receive a marker.
- POP3 counter fields are retained as raw pairs. Only `retr` command/byte counters receive explicit semantics; verify the server's configured format.

Examples and tests are synthetic and use reserved domains/IP ranges. No client logs or investigation data are included.

Design references and implementation provenance are documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). No CrowdSec or Fail2ban source/filter expressions are bundled.

## Contributing

Include a minimal **synthetic** input, expected observable behavior and a regression test. Do not upload real mail logs, email addresses, message contents, tokens or customer IP inventories. Security issues: do not attach sensitive logs to public issues; use private GitHub reporting if enabled, otherwise first ask the maintainer for a private channel without disclosing details.

## IP associations and cross-mailbox comparisons

All shipped modules report version 0.5.0-beta.2. Older input manifests retain
their original parser version; a comparison pass is not a fresh raw-log parse.

```sh
python skills/mail-log-triage/scripts/triage.py --year 2026 --timezone Europe/Vilnius --ip-relations --output results /path/to/mail.log
python skills/mail-log-triage/scripts/cross_mailbox.py --events results/events.jsonl --index /private/new-index.sqlite --parent-manifest results/manifest.json --output /private/new-comparison
python skills/mail-log-triage/scripts/render_cross_mailbox.py /private/new-comparison --revision 0.1
```

Use a new index and output directory. All operations stay offline. Optional
ownership records are supplied locally; ASN/operator values are never guessed.
Provider proxy exclusions label proxy endpoints without suppressing mail actions.

- [IP association semantics](skills/mail-log-triage/references/ip-relations.md):
  configurable IPv4/IPv6 buckets, registered networks, operators/ASNs, shared
  account memberships and adjacent login sequences. Groups can overlap.
- [Cross-mailbox methodology](skills/mail-log-triage/references/cross-mailbox.md):
  shared endpoints, failure to first success, nearby RETR/mail actions, large
  transfers, bulk operations and MIME-decoded security-message candidates.
- Separate policies: `relation-rules/ip-associations.yaml` and
  `relation-rules/cross-mailbox.yaml`, independent of event alert rules.

One user can have several devices and dynamic IPs; one NAT/VPN endpoint can
represent several people. Network/operator membership does not identify a person.
Actions without explicit session evidence retain unknown source IPs; nearby
logins remain candidates. RETR counts commands, not unique messages. Reports
include their revision, generation time/zone, engine URL/version and exact evidence.

Implementation is original MIT code. Release source and synthetic tests contain
no customer logs, IP inventories, ownership caches or investigation reports.

## Optional client continuity (0.5.0-beta.2)

This opt-in module reviews the uncommon traveling-laptop / multi-mailbox
hypothesis. It is not part of the default parser run and never identifies a
person/device, infers physical travel, suppresses findings or blocks addresses.
The release parser and modules report 0.5.0-beta.2; retained input manifests keep their original versions.

```sh
python skills/mail-log-triage/scripts/client_continuity.py --database /private/evidence.sqlite --parent-manifest results/manifest.json --output /private/new-continuity --account u@example.test --reference-ip 192.0.2.1
```

See [semantics and statuses](skills/mail-log-triage/references/client-continuity.md),
the separate `relation-rules/client-continuity.yaml`, and
[product research](skills/mail-log-triage/references/product-ideas.md).
58 synthetic tests now cover the full helper suite, including switching,
overlap, missing history, mapped IPs, proxy exclusions and ambiguous UTC.

## License

Licensed under the [MIT License](LICENSE). Copyright (c) 2026 mariovilnius.

## Account-scoped mailbox CSV exports

Create a portable index from parser events using the cross-mailbox module (see
[usage](skills/mail-log-triage/references/cross-mailbox.md)), then export an explicit
mailbox into a new directory:

```sh
python skills/mail-log-triage/scripts/mailbox_csv.py --database evidence.sqlite --account user@example.test --output mailbox-review
```

`mail-actions.csv` includes copy, delete flag and expunge rows.
`positive-retr-or-deletion.csv` includes rows with positive RETR command or deletion
counters, without a size threshold. Every predicate is evaluated inside the same
mandatory parameterized account scope: `account = ? AND (retr_commands > 0 OR del_counter > 0)`.
The regression suite includes another mailbox with a positive deletion counter;
its rows must never appear in the selected mailbox's CSV.

The input index is opened read-only. Source time strings, offsets, ambiguous-time
markers, source references and missing IPs are retained; no session IP is inferred.
CSV cells that could execute spreadsheet formulas are apostrophe-prefixed for
viewing. Consult original events for unchanged raw evidence. Counts are raw rows,
not unique messages, downloads or confirmed deletions. The export manifest records
the account, row counts, engine version, UTC generation time and output hashes.
Existing output directories are rejected. This command exports CSV evidence, not
an HTML/PDF report. No parser or detection policy changes are introduced.
