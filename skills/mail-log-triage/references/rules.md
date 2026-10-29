# YAML review rules version 1

Rules are Artefact Finder's small local schema, not Sigma or CrowdSec rules. Files use the `.yaml` extension. The helper loads all such files in the selected directory; a custom directory replaces built-ins. Empty directories, duplicate IDs, unknown schema keys/operators and unsafe YAML object constructors are rejected before output creation.

Every document requires exactly these keys:

```yaml
id: EXAMPLE-001
title: Example explicit failure
version: '1'
level: review
profiles: [normal, extended]
match:
  - field: event_type
    op: equals
    value: auth_failure
explanation: An explicit failure was observed, not a malicious-intent verdict.
false_positives:
  - An authorized client using an old password.
```

All conditions use AND. Allowed fields: `event_type`, `protocol`, `subject`, `retr_bytes`, `auth_reason`. Missing/null values never match. Supported operators:

- `equals`: exact string equality, case-sensitive.
- `in`: exact membership in a nonempty string list.
- `word`: case-insensitive literal whole-word match; no configurable regex execution.
- `not_contains`: case-insensitive literal exclusion.
- `gte`: finite nonnegative numeric threshold, supported only for `retr_bytes`.

String values must be nonempty. ID, title, version, level and explanation must be strings. Level is descriptive metadata; the engine does not infer severity or attacker intent. Profiles are explicitly `normal` and/or `extended`; extended is not a confidence upgrade.

`--large-retr-bytes` overrides every selected rule's `retr_bytes/gte` threshold for this run without modifying YAML files. It is recorded separately in the manifest. Rule IDs, versions and hashes in the manifest identify the original files; preserve those files with a case when using custom rules.

Built-in rules and tests are original MIT-licensed Artefact Finder content. Do not paste third-party GPL or DRL rules into this directory and assume the repository's MIT license replaces their terms.
