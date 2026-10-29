# Comparing mailboxes and sequences

Local experimental module: `scripts/cross_mailbox.py`, version 0.4.0-beta.2.
The base parser's version stays independently recorded in the manifest. Inputs
and outputs contain private case evidence; never commit them to the public repo.

## Run offline

```text
python scripts/cross_mailbox.py --events /private/run/events.jsonl --index /private/new-index.sqlite --output /private/new-review --parent-manifest /private/run/manifest.json
```

Alternatively pass `--database` for a retained index produced by this module or
a compatible case index. Required table `events` has account, host, protocol,
kind, ip, second (unique UTC epoch or NULL), time (local candidates), file, line,
raw, session, retr_commands, retr_bytes and del_counter. Other columns are
ignored. Keep the database with its base manifest. The events path hashes the
input; reused databases require provenance validation by the calling workflow.
Supplying a parent manifest records provenance but does not itself authenticate
the database. Verify original hashes and cache origin before reporting results.

`--memberships` optionally accepts the offline IP relations module's
ip-memberships.json. Operator labels remain cached registration evidence, not
historical ownership or physical location. No network requests are made.

## Configuration and counting

`relation-rules/cross-mailbox.yaml` is a comparison policy, separate from the
parser's event alert rules. Defaults:

- Same host/account/protocol/canonical IP: last failure to first subsequent
  success within 1,800 seconds. Consume the pending failure at first success;
  earlier failures in a run do not multiply sequences. Distinct hosts and
  protocols stay separate. A failure followed by another IP's success is not
  asserted to be the same authentication attempt.
- After that success, show the same host/account's mail actions and positive
  RETR/del counters through 60 seconds, inclusive. Action protocols may differ
  because other clients can be active. Do not inherit the login's IP.
- Large RETR: at least 50,000,000 bytes, with login candidate context from
  1,800 seconds before to 60 seconds after its logout timestamp. Report every
  candidate IP with first/last exact references. The transfer's own source IP
  stays unknown unless explicitly present on that row.
- Bulk mail operations: same host/account/protocol/operation/mailbox with no
  gap over 30 seconds and at least 20 distinct (mailbox, UID, Message-ID) keys.
  Preserve repeated raw lines but count repeated message keys once. Missing
  UID and Message-ID do not prove distinct messages. Copy/delete flag/expunge
  remain different operations. This is not a whole-folder deletion detector.
- Shared endpoint: same canonical IP observed in authentication across at least
  two exact account names. Distinguish successful accounts from failed-only
  names, which do not establish that a mailbox exists. Keep per-account first
  and last success/failure timestamps and source lines.
- Security-message actions: decode MIME subjects, match the configured subject
  expression, then follow full Message-ID within the exact host/account. The
  default PIN expression excludes the known unrelated "pin brazing" phrase.
  Treat all matches as lexical review candidates, not proof of code use.
  Show each copy/delete/expunge with its own source IP or explicit unknown;
  nearby login endpoints are separate candidates, including confirmed proxies.

Only unique UTC timestamps enter sequence and temporal-context matching.
Ambiguous timestamps remain visible in authentication counts and input evidence.
Raw authentication duplicates are preserved. The first/last group references
prefer unique UTC rows; ambiguous-only groups retain unresolved references.
IPv4-mapped IPv6 is normalized for identity of endpoints, not people.

## Review priorities and alternatives

Start with shared IPs across several successful accounts, then inspect exact
failure/success sequences with nearby retrieval or deletion evidence. Show
confirmed provider proxies separately, never remove their mail actions. A
provider proxy identifies the proxy endpoint, not the browser client.

Compare synchronized failures across multiple mailboxes and domains: a common
polling client, password/configuration change or service problem can explain
the pattern. It is not automatically a distributed attack. One person can use
several devices and networks; one NAT/CGNAT/VPN endpoint can represent many
people. Overlapping operator/prefix groups and transitive graph paths are not
independent incidents or attributed actors.

Distinguish three levels in the report: (1) directly observed endpoint and auth
outcome; (2) same-account/time context without a session link; (3) unverified
identity/intent hypothesis. Never claim sniffing, an Nth password guess, complete
mailbox download or malicious deletion from these observations alone. RETR
counts commands, large retrieval can be synchronization, expunge from INBOX
does not establish deletion of a Trash copy.

## Outputs and reporting

shared-ips.json; failure-success-actions.json and CSV; large-transfers-context.json;
bulk-actions-context.json; manifest.json. JSON retains exact raw references.
`security-message-actions.json` retains matched message identities, raw actions
and nearby login candidates. These evidence files are private case outputs.
Generate a separate HTML review with `python scripts/render_cross_mailbox.py
/private/new-review --revision 0.1`. It escapes source text, includes policy
windows and report metadata, and does not produce PDF/ZIP or publish files.
Manifests include policy/module hashes, parent engine, source metadata, proxy
list, timezone and generation time. Reports also need their own revision,
generation time with zone, engine name/URL/version and exact event timestamps
with seconds, timezone/offset, IP (or explicitly unknown) and source file/line.
Keep candidate login IPs visibly separate from action attribution. Explain the
precise time window whenever reporting that no nearby action was found.
