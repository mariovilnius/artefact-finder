# Artefact Finder

**0.3.0-beta.1** — evidence-first log investigation skills. This beta adds disk-backed repeated same-account multi-IP login coincidence detection, configurable windows and YAML thresholds to the offline Dovecot helper.

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

## Local development preview: IP associations

The experimental `scripts/ip_relations.py` module is labelled 0.4.0-beta.1;
the released base parser remains 0.3.0-beta.1. This is a local preview, not a
published release. See [association semantics](skills/mail-log-triage/references/ip-relations.md).
It adds overlapping network/operator views, IP memberships across accounts and
adjacent-login sequence evidence. No identity or maliciousness is inferred.
Use `triage.py --ip-relations` for a new parse, or run the module against a
previously verified `correlation.sqlite`. Optional offline ownership records
remain private. Configuration lives separately in `relation-rules/`.

## Local development preview: cross-mailbox comparisons

`scripts/cross_mailbox.py` (0.4.0-beta.2) compares shared endpoints and
failure/success sequences with retrieval/deletion context. It accepts retained
events JSONL or a compatible private SQLite index. See the
[comparison methodology](skills/mail-log-triage/references/cross-mailbox.md).
Policy lives in `relation-rules/cross-mailbox.yaml`. The base parser remains
0.3.0-beta.1; local preview modules have not been published as a GitHub release.
All implementation is original MIT code; no upstream filters or case data are
bundled.

## License

Licensed under the [MIT License](LICENSE). Copyright (c) 2026 mariovilnius.
