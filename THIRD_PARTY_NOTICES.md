# Design references and implementation provenance

The 0.2.0-beta.1 parser expansion, YAML rules and synthetic tests were written for Artefact Finder. No source code, regular expressions, rule files or test fixtures were copied from CrowdSec or Fail2ban. The existing MIT LICENSE applies to this project's original implementation.

The following upstream projects were consulted on 2026-10-29 to identify log-format coverage and investigation ideas:

- CrowdSec Hub Dovecot parser: https://github.com/crowdsecurity/hub/blob/master/parsers/s01-parse/crowdsecurity/dovecot-logs.yaml
  - Hub license: MIT, copyright 2025 CrowdSecurity, as published at https://github.com/crowdsecurity/hub/blob/master/LICENSE
  - Inspiration: backend-specific authentication contexts and normalized endpoint fields.
- Fail2ban Dovecot filter: https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/dovecot.conf
  - Package license: GNU GPL version 2, subject to file-specific exceptions, as published at https://github.com/fail2ban/fail2ban/blob/master/COPYING
  - Inspiration: separate explicit authentication failures from incomplete connections and test legacy/modern log envelopes. No filter or regex translation is distributed here.

These are references, not bundled dependencies. Their licenses are not replaced by this project's MIT license. Future copying of any third-party material requires a fresh review of its specific license and attribution requirements.

Runtime dependencies are installed separately: PyYAML (MIT) and tzdata (Apache-2.0 package; underlying IANA database terms also apply). Preserve their distribution notices when redistributing dependencies. This repository does not vendor either package.
