# Experimental offline association views (0.4.0-beta.1, local preview)

Run the module on a completed correlation database, or use triage.py --ip-relations.

```text
python scripts/ip_relations.py --database /case/correlation.sqlite --output /new/review --ownership /private/ownership.json
```

The optional ownership JSON is a list of records with network (CIDR), operator,
asn, source and lookup_time. Supply only verified organization labels as operator;
RDAP maintainer handles are not operators. Missing data stays unknown. Longest
matching prefix wins. No DNS, RDAP or other network calls are made by the module.
Registration is not physical location, historical ownership, device identity or a
person. An ASN can be supplied by an authoritative offline routing source; it is
never guessed from network names. Keep case ownership files private.

YAML in relation-rules is a separate association configuration, not an event
alert rule. Default sequence window is 300 seconds; comparison prefixes are
IPv4 /24 and IPv6 /64. Prefixes are comparison buckets, not classful networks or
proof of common operator. Registration-network and operator views span buckets.

Memberships show IPs shared across exact account/protocol/host contexts and
include first/last evidence, group IDs and sequence-group counts. Groups can
overlap. Do not sum their member counts as unique IPs. A group is not an incident.
Do not turn transitive connected components into inferred people or attackers.
Same users may have multiple devices on home/work/mobile networks; NAT, CGNAT
and VPN can put unrelated users behind one IP.

Sequence evidence consists of adjacent, different-IP successful endpoint login
seconds within the same host/account/protocol and configured window. It does not
assert an IP handover, simultaneous sessions, or enumerate all possible pairs.
Equal timestamps have deterministic IP ordering, not demonstrated causal order.
Repeated A-B-A patterns are observations, not device attribution. Existing
five-second pair correlation remains a separate view and counting unit.

Input inherits the parent's excluded proxies, unique UTC time policy and
successful endpoint-second deduplication. Ambiguous timestamps and failures are
not inserted into this database. Failed/successful authentication evidence must
be shown separately with both IPs, full local offset times and source lines.
Parent source hashes, engine version, policy and manifest hash are preserved;
an association pass over a verified prior database is not a fresh raw-log parse.
