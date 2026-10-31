"""Offline Dovecot triage beta. Review candidates are not incident verdicts."""
import argparse
import csv
import hashlib
import ipaddress
import json
import re
import sqlite3
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
from email.header import decode_header
from pathlib import Path
from zoneinfo import ZoneInfo
import yaml

VERSION = '0.5.0-beta.2'
ENGINE_NAME = 'Artefact Finder'
ENGINE_URL = 'https://github.com/mariovilnius/artefact-finder'
PREFIX = re.compile(r'^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+dovecot(?:-auth)?(?:\[\d+\])?:\s+(?P<body>.*)$')
MONTHS = dict(zip('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), range(1, 13)))
DEFAULT_RULES = Path(__file__).resolve().parents[1] / 'rules'


def auth_classify(description):
    """Classify observed outcomes, not attacker intent. No upstream regex copied."""
    low = description.lower()
    reasons = [('temporary authentication failure', 'temporary_failure'),
               ('proxy dest auth failed', 'proxy_auth_failure'),
               ('password mismatch', 'password_mismatch'),
               ('unknown user', 'unknown_user'),
               ('user not known', 'unknown_user'),
               ('invalid credentials', 'invalid_credentials'),
               ('permission denied', 'permission_denied'),
               ('authentication failure', 'auth_failed'),
               ('authentication failed', 'auth_failed'),
               ('auth failed', 'auth_failed')]
    for marker, reason in reasons:
        if marker in low:
            return 'auth_failure', reason
    if re.search(r'(?:disabled|disallowed)\s+\S+\s+auth', low):
        return 'auth_failure', 'auth_mechanism_rejected'
    if any(marker in low for marker in ['no auth attempts', 'before auth was ready',
                                        "didn't finish", 'during tls handshake',
                                        'aborted login', 'login aborted']):
        return 'login_aborted', 'incomplete_auth'
    return 'unknown', None


def set_ip(event, name, value):
    try:
        event[name] = str(ipaddress.ip_address(value))
    except ValueError:
        event[name + '_invalid'] = value


def load_rules(directory=None):
    """Local declarative config only: safe YAML, known fields/operators, no eval."""
    paths = sorted(Path(directory or DEFAULT_RULES).glob('*.yaml'))
    if not paths:
        raise ValueError('No YAML rules found')
    rules, ids = [], set()
    allowed_fields = {'event_type', 'protocol', 'subject', 'retr_bytes', 'auth_reason', 'pair_occurrences', 'pair_days'}
    operators = {'equals', 'in', 'gte', 'word', 'not_contains'}
    for path in paths:
        data = path.read_bytes()
        rule = yaml.safe_load(data)
        required = {'id', 'title', 'version', 'level', 'profiles', 'match', 'explanation', 'false_positives'}
        if not isinstance(rule, dict) or not required.issubset(rule) or set(rule)-required-{'correlation'}:
            raise ValueError('Invalid rule keys: ' + path.name)
        if any(not isinstance(rule[k], str) or not rule[k].strip() for k in ['id', 'title', 'version', 'level', 'explanation']):
            raise ValueError('Rule metadata must be nonempty strings')
        if rule['id'] in ids:
            raise ValueError('Duplicate rule ID: ' + rule['id'])
        ids.add(rule['id'])
        if not isinstance(rule['profiles'], list) or not rule['profiles'] or any(x not in ['normal', 'extended'] for x in rule['profiles']):
            raise ValueError('Invalid profiles')
        if not isinstance(rule['false_positives'], list) or any(not isinstance(x, str) for x in rule['false_positives']):
            raise ValueError('Invalid false positives')
        if not isinstance(rule['match'], list) or not rule['match']:
            raise ValueError('Rule needs conditions')
        for condition in rule['match']:
            if not isinstance(condition, dict) or set(condition) != {'field', 'op', 'value'}:
                raise ValueError('Invalid condition')
            field, op, value = condition['field'], condition['op'], condition['value']
            if field not in allowed_fields or op not in operators:
                raise ValueError('Unsupported field or operator')
            if op == 'gte' and (type(value) not in (int, float) or field not in {'retr_bytes', 'pair_occurrences', 'pair_days'} or not 0 <= value < float('inf')):
                raise ValueError('gte requires a finite nonnegative numeric counter threshold')
            if op == 'in' and (not isinstance(value, list) or not value or any(not isinstance(x, str) for x in value)):
                raise ValueError('in requires string values')
            if op in {'equals', 'word', 'not_contains'} and (not isinstance(value, str) or not value):
                raise ValueError('String operator requires nonempty string')
        if 'correlation' in rule:
            config = rule['correlation']
            if not isinstance(config, dict) or set(config) != {'type', 'window_seconds'} or config['type'] != 'same_account_multi_ip':
                raise ValueError('Invalid correlation configuration')
            if type(config['window_seconds']) is not int or not 0 <= config['window_seconds'] <= 86400:
                raise ValueError('Correlation window must be an integer from 0 to 86400 seconds')
        if sum('correlation' in r for r in rules) + int('correlation' in rule) > 1:
            raise ValueError('Only one multi-IP correlation rule is supported per rule directory')
        rule['_file'] = path.name
        rule['_sha256'] = hashlib.sha256(data).hexdigest()
        rules.append(rule)
    return rules


def evaluate_rules(event, rules, profile='normal', large_bytes=None):
    hits = []
    for rule in rules:
        if profile not in rule['profiles']:
            continue
        matched = True
        for condition in rule['match']:
            field, op, wanted = condition['field'], condition['op'], condition['value']
            actual = event.get(field)
            if field == 'retr_bytes' and op == 'gte' and large_bytes is not None:
                wanted = large_bytes
            if actual is None:
                matched = False
                break
            if op == 'equals': ok = actual == wanted
            elif op == 'in': ok = actual in wanted
            elif op == 'gte': ok = type(actual) in (int, float) and actual >= wanted
            elif op == 'word': ok = isinstance(actual, str) and re.search(r'\b' + re.escape(wanted) + r'\b', actual, re.I) is not None
            else: ok = isinstance(actual, str) and wanted.casefold() not in actual.casefold()
            if not ok:
                matched = False
                break
        if matched:
            hits.append({k: rule[k] for k in ['id', 'version', 'title', 'level', 'explanation', 'false_positives']})
    return hits


def canonical_ip(value):
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


class MultiIPDetector:
    """Disk-backed login coincidence analysis, never session-overlap attribution."""
    def __init__(self, database, window_seconds=5, excluded_ips=()):
        if type(window_seconds) is not int or not 0 <= window_seconds <= 86400:
            raise ValueError('Invalid multi-IP time window')
        self.window = window_seconds
        self.excluded = {canonical_ip(ip) for ip in excluded_ips}
        self.stats = Counter()
        self.db = sqlite3.connect(database)
        self.db.execute('CREATE TABLE logins(host TEXT, account TEXT, protocol TEXT, ip TEXT, second INTEGER, local TEXT, evidence TEXT, PRIMARY KEY(host,account,protocol,ip,second))')
        self.db.execute('CREATE TABLE pairs(pair_id TEXT, second INTEGER, local_day TEXT, delta INTEGER, evidence TEXT, PRIMARY KEY(pair_id,second))')

    def close(self):
        self.db.close()

    def add(self, event):
        if event.get('event_type') != 'auth_success' or event.get('protocol') not in {'pop3', 'imap'}:
            return
        self.stats['success_rows_considered'] += 1
        if not event.get('account') or not event.get('host') or not event.get('source_ip'):
            self.stats['missing_identity_or_ip'] += 1
            return
        ip = canonical_ip(event['source_ip'])
        if ip in self.excluded:
            self.stats['excluded_ip_rows'] += 1
            return
        if event.get('time_status') != 'unique' or len(event.get('utc_candidates', [])) != 1:
            self.stats['nonunique_time_rows'] += 1
            return
        stamp = datetime.fromisoformat(event['utc_candidates'][0])
        local = event['local_candidates'][0]
        evidence = {k: event.get(k) for k in ['event_id', 'source_id', 'file', 'line', 'byte_offset', 'session_id']}
        evidence.update(host=event['host'], account=event['account'], protocol=event['protocol'], ip=ip, timestamp_utc=stamp.isoformat(), timestamp_local=local)
        serialized = json.dumps(evidence, sort_keys=True)
        # Keep one deterministic representative per endpoint/UTC-second, even
        # across files or for duplicate lines with different session IDs.
        self.db.execute('INSERT INTO logins VALUES(?,?,?,?,?,?,?) ON CONFLICT(host,account,protocol,ip,second) DO UPDATE SET evidence=excluded.evidence WHERE excluded.evidence < logins.evidence',
                        (event['host'], event['account'], event['protocol'], ip, int(stamp.timestamp()), local, serialized))
        if self.stats['success_rows_considered'] % 10000 == 0:
            self.db.commit()

    def summaries(self, output):
        self.db.commit()
        self.stats['distinct_endpoint_seconds'] = self.db.execute('SELECT COUNT(*) FROM logins').fetchone()[0]
        self.db.execute('CREATE INDEX login_order ON logins(host,account,protocol,second,ip)')
        active, previous_group = {}, None
        query = 'SELECT host,account,protocol,ip,second,local,evidence FROM logins ORDER BY host,account,protocol,second,ip'
        for host, account, protocol, ip, second, local, encoded in self.db.execute(query):
            group = (host, account, protocol)
            if group != previous_group:
                active = {}
                previous_group = group
            for oldip, (oldsecond, oldencoded) in list(active.items()):
                if second-oldsecond > self.window:
                    del active[oldip]
                    continue
                if oldip == ip:
                    continue
                ips = sorted([ip, oldip])
                pair_id = hashlib.sha256(json.dumps([host, account, protocol, ips, self.window]).encode()).hexdigest()
                evidence = dict(pair_id=pair_id, host=host, account=account, protocol=protocol, ips=ips, window_seconds=self.window,
                                ending_utc=datetime.fromtimestamp(second, timezone.utc).isoformat(), ending_local=local,
                                delta_seconds=second-oldsecond, login_a=json.loads(oldencoded), login_b=json.loads(encoded),
                                attribution='login_time_coincidence_not_session_overlap')
                payload = json.dumps(evidence, sort_keys=True)
                self.db.execute('INSERT INTO pairs VALUES(?,?,?,?,?) ON CONFLICT(pair_id,second) DO UPDATE SET delta=excluded.delta,evidence=excluded.evidence WHERE excluded.delta < pairs.delta OR (excluded.delta=pairs.delta AND excluded.evidence < pairs.evidence)',
                                (pair_id, second, local[:10], second-oldsecond, payload))
            active[ip] = (second, encoded)
        self.db.commit()
        self.stats['pair_occurrences'] = self.db.execute('SELECT COUNT(*) FROM pairs').fetchone()[0]
        with (Path(output)/'multi-ip-occurrences.jsonl').open('w', encoding='utf-8') as handle:
            for (encoded,) in self.db.execute('SELECT evidence FROM pairs ORDER BY second,pair_id'):
                handle.write(encoded+'\n')
        groupquery = 'SELECT pair_id,COUNT(*),COUNT(DISTINCT local_day),SUM(delta=0),MIN(second),MAX(second) FROM pairs GROUP BY pair_id ORDER BY pair_id'
        for pair_id, count, days, exact, first, last in self.db.execute(groupquery):
            first_e = json.loads(self.db.execute('SELECT evidence FROM pairs WHERE pair_id=? AND second=?', (pair_id, first)).fetchone()[0])
            last_e = json.loads(self.db.execute('SELECT evidence FROM pairs WHERE pair_id=? AND second=?', (pair_id, last)).fetchone()[0])
            self.stats['pair_groups'] += 1
            yield dict(event_type='multi_ip_login_pair', correlation_id=pair_id, host=first_e['host'], account=first_e['account'], protocol=first_e['protocol'],
                       ips=first_e['ips'], window_seconds=self.window, pair_occurrences=count, pair_days=days, exact_second_occurrences=exact,
                       first_utc=first_e['ending_utc'], last_utc=last_e['ending_utc'], first_local=first_e['ending_local'], last_local=last_e['ending_local'],
                       first_evidence=first_e, last_evidence=last_e, evidence_file='multi-ip-occurrences.jsonl', attribution='login_time_coincidence_not_session_overlap')


def subject_decode(value):
    try:
        chunks = []
        for part, charset in decode_header(value):
            if isinstance(part, bytes):
                part = part.decode(charset or 'utf-8', errors='replace')
            chunks.append(part)
        return ''.join(chunks), 'decoded'
    except (LookupError, ValueError, UnicodeError):
        return value, 'decode_error'


def normalize_time(stamp, year=None, zone=None):
    result = {'timestamp_raw': stamp, 'year': year, 'timezone': zone, 'time_status': 'unknown', 'utc_candidates': []}
    if year is None:
        return result
    try:
        d = datetime(year, MONTHS[stamp[:3]], int(stamp[4:6]), int(stamp[7:9]), int(stamp[10:12]), int(stamp[13:15]))
    except (KeyError, ValueError):
        result['time_status'] = 'invalid'
        return result
    result['timestamp_local_naive'] = str(d)
    if zone is None:
        return result
    tz = ZoneInfo(zone)
    candidates = {}
    for fold in (0, 1):
        aware = d.replace(tzinfo=tz, fold=fold)
        utc = aware.astimezone(timezone.utc)
        if utc.astimezone(tz).replace(tzinfo=None) == d:
            candidates[utc.isoformat()] = aware.isoformat()
    result['utc_candidates'] = sorted(candidates)
    result['local_candidates'] = list(candidates.values())
    result['time_status'] = 'unique' if len(candidates) == 1 else 'ambiguous' if candidates else 'nonexistent'
    return result


def parse(raw, year=None, zone=None):
    m = PREFIX.match(raw)
    if not m:
        return None
    body = re.sub(r'^(?:Info|Warning|Error|Debug):\s*', '', m['body'])
    event = dict(host=m['host'], event_type='unknown', protocol=None, account=None, source_ip=None, local_ip=None)
    event.update(normalize_time(m['stamp'], year, zone))
    login = re.match(r'(pop3|imap|submission|managesieve)-login: (.*)', body)
    action = re.match(r'(pop3|imap)\(([^)]+)\): (.*)', body)
    if login:
        event['protocol'] = login[1]
        desc = re.sub(r'^(?:Info|Warning|Error|Debug):\s*', '', login[2])
        event['parser_variant'] = 'login'
        user = re.search(r'user=<([^>]*)>', desc)
        event['account'] = user[1] if user else None
        if desc.startswith('Login:'):
            event['event_type'], event['auth_reason'] = 'auth_success', 'explicit_login'
        else:
            event['event_type'], event['auth_reason'] = auth_classify(desc.split('user=<', 1)[0])
        attempts = re.search(r'\b(\d+) attempts?\b', desc.split('user=<', 1)[0])
        event['attempts_reported'] = int(attempts[1]) if attempts else None
        event['tls_marker'] = 'present' if re.search(r'(?:, |\b)TLS(?:,|:|\s|$)', desc) else 'unknown'
        for field, name in [('rip', 'source_ip'), ('lip', 'local_ip')]:
            match = re.search(r'\b' + field + r'=([^,\s]+)', desc)
            if match:
                set_ip(event, name, match[1])
        session = re.search(r'session=<([^>]+)>', desc)
        event['session_id'] = session[1] if session else None
    elif action:
        event['protocol'], event['account'], desc = action.groups()
        for prefix, kind in [('copy from ', 'mail_copy'), ('expunge:', 'mail_expunge'), ('delete:', 'mail_delete_flag'), ('save:', 'mail_save')]:
            if desc.startswith(prefix):
                event['event_type'] = kind
                break
        if event['event_type'] == 'unknown':
            event['event_type'] = 'logout' if 'Logged out' in desc else 'disconnect' if 'Connection closed' in desc or 'Disconnected' in desc else 'unknown'
        msgid = re.search(r'msgid=(.*?), size=', desc)
        event['message_id'] = msgid[1] if msgid else None
        if 'subject=' in desc:
            event['subject_raw'] = desc.split('subject=', 1)[1]
            event['subject'], event['subject_status'] = subject_decode(event['subject_raw'])
        retr = re.search(r'\bretr=(\d+)/(\d+)', desc)
        if retr:
            event['retr_commands'], event['retr_bytes'] = map(int, retr.groups())
            event['counter_semantics'] = 'standard_Dovecot_retr_profile_verify_configuration'
        for key in ['top', 'del']:
            match = re.search(r'\b' + key + r'=(\d+)/(\d+)', desc)
            if match:
                event[key + '_pair_raw'] = match[0].split('=', 1)[1]
    else:
        # Backend context is extracted separately from outcome text. Endpoint
        # fields belong to this row only; protocol remains unknown if absent.
        backend = re.search(r'\b(pam|sql|ldap|passwd-file|checkpassword|bsdauth)\(([^)]*)\):\s*(.*)', body)
        pam = re.search(r'\bauthentication failure;.*\brhost=([^\s;]+)', body, re.I)
        if backend and body.startswith(('auth:', 'auth(', 'auth<', 'auth-worker', 'pam(')):
            event['parser_variant'] = 'auth_backend'
            event['auth_backend'] = backend[1]
            context = backend[2].split(',')
            event['account'] = context[0] or None
            if len(context) > 1 and context[1]:
                set_ip(event, 'source_ip', context[1])
            if len(context) > 2 and context[2].startswith('<'):
                event['session_id'] = context[2].strip('<>')
            event['event_type'], event['auth_reason'] = auth_classify(backend[3])
        elif pam:
            event['parser_variant'], event['auth_backend'] = 'pam_syslog', 'pam'
            set_ip(event, 'source_ip', pam[1])
            user = re.search(r'(?:^|[;\s])user=([^\s;]+)', body)
            event['account'] = user[1] if user else None
            event['event_type'], event['auth_reason'] = auth_classify(body)
    return event


def run(inputs, output, year=None, zone=None, large_bytes=None, rules_dir=None, profile='normal', multi_ip_window=None, exclude_correlation_ips=()):
    started_at = datetime.now(timezone.utc).isoformat(timespec='seconds')
    if profile not in {'normal', 'extended'}:
        raise ValueError('Unknown profile')
    if large_bytes is not None and (type(large_bytes) is not int or large_bytes < 0):
        raise ValueError('large_bytes must be a nonnegative integer')
    rules = load_rules(rules_dir)
    correlation_rule = next((r for r in rules if 'correlation' in r and profile in r['profiles']), None)
    if multi_ip_window is not None and (type(multi_ip_window) is not int or not 0 <= multi_ip_window <= 86400):
        raise ValueError('multi_ip_window must be an integer from 0 to 86400')
    excluded_ips = sorted({canonical_ip(ip) for ip in exclude_correlation_ips})
    if correlation_rule is None and (multi_ip_window is not None or excluded_ips):
        raise ValueError('Correlation options require an active multi-IP YAML rule')
    window = multi_ip_window if multi_ip_window is not None else correlation_rule['correlation']['window_seconds'] if correlation_rule else None
    if zone:
        ZoneInfo(zone)  # Fail before creating output when timezone data is missing.
    paths = [Path(p).resolve() for p in inputs]
    for path in paths:
        if not path.is_file():
            raise ValueError('Input is not a regular file: ' + str(path))
    if len(set(paths)) != len(paths):
        raise ValueError('Duplicate input path')
    output = Path(output).resolve()
    if any(output == p or output in p.parents for p in paths):
        raise ValueError('Output may not contain source logs')
    output.mkdir(parents=True, exist_ok=False)
    counts = Counter()
    ips = Counter()
    sources = []
    # Two passes per source: hash original bytes, then parse with stable provenance.
    detector = None
    with ExitStack() as resources, (output / 'events.jsonl').open('w', encoding='utf-8') as events, (output / 'findings.jsonl').open('w', encoding='utf-8') as findings, (output / 'unparsed.jsonl').open('w', encoding='utf-8') as unparsed:
        if correlation_rule:
            detector = MultiIPDetector(output/'correlation.sqlite', window, excluded_ips)
            resources.callback(detector.close)
        for path in paths:
            h = hashlib.sha256()
            with path.open('rb') as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    h.update(chunk)
            source_id = h.hexdigest()
            second_hash = hashlib.sha256()
            seen_sessions = set()
            offset = 0
            lines = 0
            with path.open('rb') as source:
                for number, data in enumerate(source, 1):
                    lines = number
                    second_hash.update(data)
                    raw = data.decode('utf-8', errors='replace').rstrip('\r\n')
                    provenance = dict(source_id=source_id, file=path.name, line=number, byte_offset=offset, raw=raw, decode_error='\ufffd' in raw)
                    offset += len(data)
                    counts['lines'] += 1
                    event = parse(raw, year, zone)
                    if event is None:
                        counts['unparsed'] += 1
                        unparsed.write(json.dumps(provenance, ensure_ascii=False) + '\n')
                        continue
                    event.update(provenance)
                    event['event_id'] = hashlib.sha256(f'{source_id}:{provenance["byte_offset"]}:{VERSION}'.encode()).hexdigest()
                    # Bounded to authentication session fingerprints, not all original lines.
                    fingerprint = hashlib.sha256(raw.encode('utf-8')).digest()
                    event['duplicate_session_record'] = bool(event.get('session_id') and fingerprint in seen_sessions)
                    if event.get('session_id'):
                        seen_sessions.add(fingerprint)
                    if detector:
                        detector.add(event)
                    counts[event['event_type']] += 1
                    if event.get('source_ip'):
                        ips[(event['account'] or '', event['source_ip'], event['protocol'] or '', event['event_type'])] += 1
                    events.write(json.dumps(event, ensure_ascii=False) + '\n')
                    hits = evaluate_rules(event, rules, profile, large_bytes)
                    if hits:
                        counts['review_candidate_events'] += 1
                        findings.write(json.dumps(dict(finding_type='event', event_id=event['event_id'], rules=hits, status='unreviewed', file=path.name, line=number), ensure_ascii=False) + '\n')
            if second_hash.hexdigest() != source_id:
                raise ValueError('Input changed during analysis; discard incomplete output')
            sources.append(dict(file=path.name, sha256=source_id, bytes=offset, lines=lines))
        if detector:
            with (output/'multi-ip-summary.jsonl').open('w', encoding='utf-8') as summaries:
                for summary in detector.summaries(output):
                    summaries.write(json.dumps(summary, ensure_ascii=False)+'\n')
                    hits = evaluate_rules(summary, [correlation_rule], profile)
                    if hits:
                        counts['review_candidate_correlations'] += 1
                        findings.write(json.dumps(dict(summary, finding_type='correlation', rules=hits, status='unreviewed'), ensure_ascii=False)+'\n')
    with (output / 'ip-summary.csv').open('w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(['account', 'source_ip', 'protocol', 'event_type', 'raw_count'])
        for key, count in sorted(ips.items()):
            writer.writerow([("'" + v) if v.startswith(('=', '+', '-', '@', '\t', '\r', '\n')) else v for v in key] + [count])
    manifest = dict(version=VERSION, sources=sources, coverage=dict(counts), year=year, timezone=zone, time_basis='caller_supplied' if year or zone else 'unknown', large_retr_bytes_override=large_bytes, profile=profile, rules=[dict(id=r['id'], version=r['version'], file=r['_file'], sha256=r['_sha256']) for r in rules], session_attribution='not_implemented', duplicate_counts='raw_counts_preserved', privacy='offline_no_network_requests')
    manifest['multi_ip_correlation'] = dict(enabled=detector is not None, window_seconds=window, window_override=multi_ip_window, excluded_ips=excluded_ips,
                                          grouping=['host','account','protocol','canonical_ip_pair'], time_basis='unique_UTC_only',
                                          count_unit='distinct_pair_ending_UTC_seconds', stats=dict(detector.stats) if detector else {})
    generated_at = datetime.now(timezone.utc)
    manifest.update(manifest_schema_version='1.2', engine=dict(name=ENGINE_NAME, url=ENGINE_URL, version=VERSION),
                    analysis_started_at_utc=started_at, generated_at_utc=generated_at.isoformat(timespec='seconds'),
                    generated_at_local=generated_at.astimezone(ZoneInfo(zone)).isoformat(timespec='seconds') if zone else None)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inputs', nargs='+', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--year', type=int)
    parser.add_argument('--timezone')
    parser.add_argument('--large-retr-bytes', type=int, help='Override YAML retr_bytes thresholds')
    parser.add_argument('--rules-dir', type=Path, help='Local YAML rule directory')
    parser.add_argument('--profile', choices=['normal', 'extended'], default='normal')
    parser.add_argument('--multi-ip-window', type=int, help='Override YAML multi-IP window, 0..86400 seconds; 0 means same-second')
    parser.add_argument('--exclude-correlation-ip', action='append', default=[], help='Exclude this endpoint only from multi-IP correlation; repeatable')
    parser.add_argument('--ip-relations', action='store_true', help='Run experimental offline IP association module after correlation')
    parser.add_argument('--ownership', type=Path, help='Offline ownership JSON for --ip-relations; no network requests')
    parser.add_argument('--relation-rules', type=Path, default=DEFAULT_RULES.parent/'relation-rules/ip-associations.yaml')
    args = parser.parse_args()
    if args.ownership and not args.ip_relations:
        parser.error('--ownership requires --ip-relations')
    if args.year is not None and not 1 <= args.year <= 9999:
        parser.error('year must be between 1 and 9999')
    if args.large_retr_bytes is not None and args.large_retr_bytes < 0:
        parser.error('large-retr-bytes must be non-negative')
    result = run(args.inputs, args.output, args.year, args.timezone, args.large_retr_bytes, args.rules_dir, args.profile, args.multi_ip_window, args.exclude_correlation_ip)
    if args.ip_relations:
        from ip_relations import run as run_relations
        if not (args.output/'correlation.sqlite').exists():
            parser.error('--ip-relations requires an active multi-IP correlation rule')
        run_relations(args.output/'correlation.sqlite', args.output/'ip-relations', args.relation_rules, args.ownership)
    print(json.dumps(result['coverage']))


if __name__ == '__main__':
    main()
