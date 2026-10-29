"""Offline Dovecot triage beta. Review candidates are not incident verdicts."""
import argparse
import csv
import hashlib
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timezone
from email.header import decode_header
from pathlib import Path
from zoneinfo import ZoneInfo

VERSION = '0.1.0-beta.2'
PREFIX = re.compile(r'^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+dovecot(?:\[\d+\])?:\s+(?P<body>.*)$')
MONTHS = dict(zip('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), range(1, 13)))


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
    body = m['body']
    event = dict(host=m['host'], event_type='unknown', protocol=None, account=None, source_ip=None, local_ip=None)
    event.update(normalize_time(m['stamp'], year, zone))
    login = re.match(r'(pop3|imap)-login: (.*)', body)
    action = re.match(r'(pop3|imap)\(([^)]+)\): (.*)', body)
    if login:
        event['protocol'] = login[1]
        desc = login[2]
        user = re.search(r'user=<([^>]*)>', desc)
        event['account'] = user[1] if user else None
        event['event_type'] = 'auth_success' if desc.startswith('Login:') else 'auth_failure' if re.search(r'auth failed|authentication failed', desc, re.I) else 'login_aborted' if 'Aborted login' in desc else 'unknown'
        event['tls_marker'] = 'present' if re.search(r'(?:, |\b)TLS(?:,|:|\s|$)', desc) else 'unknown'
        for field, name in [('rip', 'source_ip'), ('lip', 'local_ip')]:
            match = re.search(r'\b' + field + r'=([^,\s]+)', desc)
            if match:
                try:
                    event[name] = str(ipaddress.ip_address(match[1]))
                except ValueError:
                    event[name + '_invalid'] = match[1]
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
    return event


def run(inputs, output, year=None, zone=None, large_bytes=50000000):
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
    with (output / 'events.jsonl').open('w', encoding='utf-8') as events, (output / 'findings.jsonl').open('w', encoding='utf-8') as findings, (output / 'unparsed.jsonl').open('w', encoding='utf-8') as unparsed:
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
                    counts[event['event_type']] += 1
                    if event.get('source_ip'):
                        ips[(event['account'] or '', event['source_ip'], event['protocol'], event['event_type'])] += 1
                    events.write(json.dumps(event, ensure_ascii=False) + '\n')
                    reasons = []
                    if re.search(r'\bPIN\b', event.get('subject', ''), re.I):
                        reasons.append('PIN_subject_candidate_requires_review')
                    if event.get('retr_bytes', 0) >= large_bytes:
                        reasons.append('large_RETR_bytes_not_exfiltration_verdict')
                    if reasons:
                        findings.write(json.dumps(dict(event_id=event['event_id'], reasons=reasons, status='unreviewed', file=path.name, line=number), ensure_ascii=False) + '\n')
            if second_hash.hexdigest() != source_id:
                raise ValueError('Input changed during analysis; discard incomplete output')
            sources.append(dict(file=path.name, sha256=source_id, bytes=offset, lines=lines))
    with (output / 'ip-summary.csv').open('w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(['account', 'source_ip', 'protocol', 'event_type', 'raw_count'])
        for key, count in sorted(ips.items()):
            writer.writerow([("'" + v) if v.startswith(('=', '+', '-', '@', '\t', '\r', '\n')) else v for v in key] + [count])
    manifest = dict(version=VERSION, sources=sources, coverage=dict(counts), year=year, timezone=zone, time_basis='caller_supplied' if year or zone else 'unknown', large_retr_bytes=large_bytes, session_attribution='not_implemented', duplicate_counts='raw_counts_preserved', privacy='offline_no_network_requests')
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inputs', nargs='+', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--year', type=int)
    parser.add_argument('--timezone')
    parser.add_argument('--large-retr-bytes', type=int, default=50000000)
    args = parser.parse_args()
    if args.year is not None and not 1 <= args.year <= 9999:
        parser.error('year must be between 1 and 9999')
    if args.large_retr_bytes < 0:
        parser.error('large-retr-bytes must be non-negative')
    result = run(args.inputs, args.output, args.year, args.timezone, args.large_retr_bytes)
    print(json.dumps(result['coverage']))


if __name__ == '__main__':
    main()
