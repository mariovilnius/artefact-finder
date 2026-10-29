# Product research and implementation ideas

Reviewed 2026-10-29. These are design observations from official sources, not
copied implementations, filters, rule expressions, commercial scoring formulas
or a commitment that every feature exists in Artefact Finder.

| Product / source | Useful design observation | Proposed adaptation |
|---|---|---|
| [Microsoft Defender for Cloud Apps](https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy) | Behavioral baselines and VPN/common-location context reduce noisy travel alerts. | Record a mailbox's normal IP/protocol/time distribution and explain known alternatives; do not map an IP country to a person's location. |
| [Elastic entity risk scoring](https://www.elastic.co/docs/solutions/security/advanced-entity-analytics/entity-risk-scoring) | Aggregate evidence around an entity rather than treating every alert separately. | Group review evidence by mailbox and time window, exposing contributing rule IDs and avoiding repeated counts of the same event. Do not represent a custom score as a compromise probability. |
| [Splunk UBA peer groups](https://help.splunk.com/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.3.0/assess-security-posture/review-peer-groups-in-splunk-uba) | Behavior similarity is a separate concept from device identity. | Compare account bundles and polling patterns as weak associations; keep person and device attribution unknown without stable identifiers. |
| [CrowdSec scenarios](https://docs.crowdsec.net/docs/log_processor/scenarios/intro/) | Windowed state, explicit grouping and distinct-value counting make scenarios interpretable. | Separate account-wide, per-IP and per-account/IP windows for distributed guessing reviews; preserve raw counts and distinguish duplicate evidence. |
| [Velociraptor artifacts](https://docs.velociraptor.app/docs/vql/artifacts/) and [notebooks](https://docs.velociraptor.app/docs/vql/notebooks/) | Parameterized, self-documenting artifacts and reusable investigation workspaces. | Opt-in modules with policy, preconditions, provenance, evidence tables and repeatable report generation. Missing input should result in insufficient evidence, not a silent identity verdict. |

## Priorities for a later iteration

1. Explainable baseline comparisons with adequate historical coverage and an
   explicit learning/unknown state. Never automatically suppress mail actions.
2. A deduplicated event/episode evidence store shared by every view, including
   the reason a row entered a review, and a source-link confidence hierarchy.
3. Distinct account-wide failure campaigns across rotating IPs, followed by
   separately verified successes and action context. Avoid IP-only grouping.
4. Optional case-provided device inventory and authorized known network labels;
   preserve evidence conflicts and manual review notes rather than forcing a merge.
5. Regression comparisons by source hash/file/line/semantic fields, independent
   of version-specific IDs; record exact module/policy hashes in every report.

The optional client-continuity module implements only a limited heuristic
subset: bundles, polling gaps, anchor transitions and overlap evidence. No
machine learning, stable device identification or impossible-travel classifier
is claimed. The priorities above remain proposals unless separately implemented.

## License boundaries

- CrowdSec's [core license](https://github.com/crowdsecurity/crowdsec/blob/master/LICENSE)
  is MIT. Any future copied component still requires its exact notices.
- Elastic detection-rules identifies its code/rules as
  [Elastic License v2](https://github.com/elastic/detection-rules#licensing),
  distinct from this project's MIT license. No rule expressions are copied.
- Velociraptor's main repository documents
  [AGPLv3](https://github.com/Velocidex/velociraptor/blob/master/CONTRIBUTING.md#license);
  its documentation/artifact content can have different terms. No VQL or
  artifact definitions are bundled here.
- Microsoft and Splunk documentation is used for design understanding; no
  proprietary implementation or scoring model is imported.
- Fail2ban's [COPYING](https://github.com/fail2ban/fail2ban/blob/master/COPYING)
  must be checked for any future reuse; no Fail2ban expressions/code are copied.

Artefact Finder code remains original MIT code. Researching a concept does not
grant permission to copy a product's source, rules or documentation. Recheck
the exact file's license before adding a future dependency or reused material.
