# Artefact Finder

**0.1.0-beta.2** — evidence-first log investigation skills. This beta includes the offline `mail-log-triage` Codex skill and Python helper for Dovecot POP3/IMAP investigations.

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

## Beta scope

- Dovecot-style English syslog, one physical line per event; no journald JSON or compressed input yet.
- PIN matching is lexical triage, including false positives; no automatic intent determination.
- No session-source attribution for actions, no SMTP analysis, no RDAP or geolocation.
- Repeated-hour timestamps retain both UTC candidates. Missing timezone/year stays unknown.
- All source rows remain counted; exact duplicates remain in events and receive a marker.
- POP3 counter fields are retained as raw pairs. Only `retr` command/byte counters receive explicit semantics; verify the server's configured format.

Examples and tests are synthetic and use reserved domains/IP ranges. No client logs or investigation data are included.

## Contributing

Include a minimal **synthetic** input, expected observable behavior and a regression test. Do not upload real mail logs, email addresses, message contents, tokens or customer IP inventories. Security issues: do not attach sensitive logs to public issues; use private GitHub reporting if enabled, otherwise first ask the maintainer for a private channel without disclosing details.

## License

Licensed under the [MIT License](LICENSE). Copyright (c) 2026 mariovilnius.
