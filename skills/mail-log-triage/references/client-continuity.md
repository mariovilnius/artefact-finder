# Optional client continuity (module 0.5.0-beta.1)

Use this uncommon, explicitly requested investigation when one person might
carry a laptop configured with several mailboxes across changing networks.
It is not enabled by triage.py, does not create an incident verdict, and never
suppresses authentication, transfer, deletion or security-message findings.

```text
python scripts/client_continuity.py --database /private/evidence.sqlite --parent-manifest /private/run/manifest.json --output /private/new-continuity --account u@example.test --reference-ip 192.0.2.1
```

Omit --account to inspect all eligible bundles. --account is repeatable; it
limits reported handover accounts while preserving full observed bundle
membership for context. --reference-ip is optional: without it, the module
selects the endpoint with the most observed accounts, then active local days,
then endpoint-seconds. This is a comparison anchor, not a trusted company IP.
The compatible private index is the events schema documented in
[cross-mailbox](cross-mailbox.md). A verified retained index can be reused;
that is not another raw-log parse. The caller verifies cache/source provenance.

## Signals and policy

- Successful, unique UTC login evidence only. Canonicalize mapped IPv6 and
  retain one host/account/protocol/IP/UTC-second endpoint observation. Preserve
  original file/line/time evidence. No physical device is identified.
- Exclude confirmed proxies supplied by the parent manifest and --exclude-ip.
  Exclusion affects this hypothesis only; original events and mail actions stay.
- Aggregate IP account bundles and protocol membership. Default minimum bundle
  size is two accounts. A shared NAT can merge different devices or people.
- Estimate a median positive login gap for the same IP/host/account/protocol,
  capped at 900 seconds. This does not describe overnight pauses or uniquely
  fingerprint Outlook. Long observation spans can combine unrelated clients.
- For each candidate IP/account, show its first/last login, the previous and
  subsequent reference-IP login, and reference-IP activity inside its interval.
- Show all intermediate endpoint intervals between those reference anchors,
  excluding anchor rows, only when the span is at most 30 days. Interval first
  and last rows are not evidence of continuous activity between them.

YAML: relation-rules/client-continuity.yaml. Thresholds are investigation
selection criteria, not probabilities or ML confidence scores.

## Status interpretation

| Status | Meaning |
|---|---|
| compatible_with_handover_unconfirmed | Both anchors exist, no reference login inside the candidate interval, span within policy. Compatible with switching, not proof of one device. |
| overlapping_endpoint_activity | Reference endpoint also logs into that account during the candidate interval. These are login timestamps, not reconstructed session overlap. The same person may still own multiple devices or use VPN/multiple interfaces. |
| insufficient_history | Missing preceding/following reference evidence; no continuity claim. |
| observation_gap_too_long | Anchors are too far apart for the configured handover review window. |

Do not turn bundled accounts, graph connectivity, registration country, similar
polling periods or absence of a reference login into a person/device identity.
Do not interpret the number of reviews as trips, users, incidents or attacks.
Several mailboxes may be used on different days of a trip; verify the actual
client profile and schedule before attributing the whole bundle to one laptop.
An account can move between servers; host/protocol evidence remains visible.

## Time and confirmation

Compare UTC ordering; retain source local timestamps with seconds and offsets.
Travel of the laptop does not change the mail server timezone. No geolocation
lookup, distance, impossible-travel speed or country-based verdict is produced.
Missing/nonunique UTC times are excluded, not silently assigned a DST fold.

Confirm with authorized travel dates, Outlook configuration and polling periods,
VPN use, other phones/computers, provider webmail client IP and User-Agent,
stable client identifiers if logged, and session/process evidence. A server
PID, one-time Dovecot session ID, TLS marker or PLAIN auth method is not a
persistent physical-device identifier.

## Outputs and provenance

manifest.json; endpoint-profiles.json; handover-evidence.json;
client-continuity.html. They contain private evidence. The manifest records
the optional module's version, parent parser version, generation time, source
metadata, policy/module hashes, account scope, exclusions and limitations.
Keep report revision and all component versions separate. The base parser can
remain at its published version when an optional analysis module is upgraded.
