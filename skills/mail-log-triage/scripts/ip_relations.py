"""Offline IP association views; never infer person/device identity from a graph."""
import argparse
import hashlib
import ipaddress
import json
import sqlite3
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
import yaml

VERSION = '0.5.0-beta.2'
ENGINE_URL = 'https://github.com/mariovilnius/artefact-finder'

def canonical(value):
    ip = ipaddress.ip_address(value)
    return ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip

def enrichment(value, records, v4=24, v6=64):
    ip = canonical(value)
    matches = [r for r in records if ip in ipaddress.ip_network(r['network'])]
    matches.sort(key=lambda r: ipaddress.ip_network(r['network']).prefixlen, reverse=True)
    best = matches[0] if matches else {}
    return dict(ip=str(ip), comparison_network=str(ipaddress.ip_network(f'{ip}/{v4 if ip.version == 4 else v6}', strict=False)),
                registration_network=best.get('network'), operator=best.get('operator'), asn=best.get('asn'),
                source=best.get('source'), lookup_time=best.get('lookup_time'),
                ownership_basis='offline_registration_cache_not_historical_identity' if best else 'unknown')

def run(database, output, rules, ownership=None):
    config = yaml.safe_load(Path(rules).read_text(encoding='utf-8'))
    window = config['sequence_window_seconds']
    if not isinstance(window, int) or not 0 <= window <= 86400:
        raise ValueError('sequence_window_seconds must be 0..86400')
    for key, maximum in [('ipv4_prefix',32),('ipv6_prefix',128)]:
        if not isinstance(config[key],int) or not 0 <= config[key] <= maximum: raise ValueError(key)
    records = json.loads(Path(ownership).read_text(encoding='utf-8')) if ownership else []
    for r in records: ipaddress.ip_network(r['network'])
    out = Path(output); out.mkdir(parents=True, exist_ok=False)
    db = sqlite3.connect(Path(database).resolve().as_uri()+'?mode=ro', uri=True)
    members = defaultdict(lambda: dict(accounts=set(), contexts=set(), count=0, first=None, last=None))
    pairs = {}; previous=None
    with (out/'sequence-evidence.jsonl').open('w',encoding='utf-8') as evidence:
        for host, account, protocol, ip, second, local, raw in db.execute('SELECT * FROM logins ORDER BY host,account,protocol,second,ip'):
            ip = str(canonical(ip)); context=(host,account,protocol); event=json.loads(raw)
            row=dict(host=host,account=account,protocol=protocol,ip=ip,second=second,time_local=local,evidence=event)
            m=members[ip];m['accounts'].add(account);m['contexts'].add(context);m['count']+=1
            if m['first'] is None or second<m['first']['second']:m['first']=row
            if m['last'] is None or second>m['last']['second']:m['last']=row
            if previous and context==previous['context'] and ip!=previous['row']['ip'] and second-previous['row']['second']<=window:
                a=previous['row']; key=(context,a['ip'],ip)
                item=dict(relation='adjacent_login_sequence',status='observed_order_not_identity_or_handover',gap_seconds=second-a['second'],before=a,after=row)
                evidence.write(json.dumps(item,ensure_ascii=False)+'\n')
                if key not in pairs:pairs[key]=dict(host=host,account=account,protocol=protocol,ip_a=a['ip'],ip_b=ip,count=0,first=item,last=item)
                pairs[key]['count']+=1;pairs[key]['last']=item
            previous=dict(context=context,row=row)
    db.close()
    ips=[];groups=defaultdict(list)
    for ip,m in sorted(members.items()):
        info=enrichment(ip,records,config['ipv4_prefix'],config['ipv6_prefix'])
        row=dict(**info,accounts=sorted(m['accounts']),contexts=[list(x) for x in sorted(m['contexts'])],endpoint_seconds=m['count'],first=m['first'],last=m['last'],status='observed_endpoint_membership_not_person')
        ips.append(row)
        for kind,field in [('network','comparison_network'),('registration_network','registration_network'),('operator','operator'),('asn','asn')]:
            if info.get(field) is not None:groups[(kind,str(info[field]))].append(row)
    result=[]
    for (kind,value),items in sorted(groups.items()):
        if len(items)<2:continue
        result.append(dict(group_id=hashlib.sha256((kind+':'+value).encode()).hexdigest()[:16],kind=kind,value=value,ips=[x['ip'] for x in items],accounts=sorted(set(a for x in items for a in x['accounts'])),status='possible_infrastructure_association_not_identity',basis='configured_prefix_only' if kind=='network' else 'supplied_offline_ownership',historical_ownership_confirmed=False))
    for row in ips:
        row['association_group_ids']=[g['group_id'] for g in result if row['ip'] in g['ips']]
        row['sequence_group_count']=sum(row['ip'] in (p['ip_a'],p['ip_b']) for p in pairs.values())
    for name,data in [('ip-memberships.json',ips),('association-groups.json',result),('sequence-summary.json',list(pairs.values()))]:
        (out/name).write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    manifest=dict(engine=dict(name='Artefact Finder',url=ENGINE_URL,version=VERSION),module='ip_relations',generated_at_utc=datetime.now(timezone.utc).isoformat(timespec='seconds'),rules=config,rule_sha256=hashlib.sha256(Path(rules).read_bytes()).hexdigest(),ownership_sha256=hashlib.sha256(Path(ownership).read_bytes()).hexdigest() if ownership else None,counts=dict(ips=len(ips),shared_ips=sum(len(x['accounts'])>1 for x in ips),association_groups=len(result),sequence_groups=len(pairs),sequence_occurrences=sum(x['count'] for x in pairs.values())),limitations=['no_person_or_device_attribution','same_user_multiple_devices_and_networks_possible','shared_NAT_VPN_CGNAT_possible','prefix_does_not_prove_common_operator','operator_does_not_prove_identity','adjacent_logins_do_not_prove_session_overlap_or_IP_change','input_database_exclusions_and_unique_time_policy_inherited','unknown_ownership_not_grouped_together','connected_components_not_identity_clusters'])
    parent=Path(database).parent/'manifest.json'
    manifest['module_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if parent.exists():
        source=json.loads(parent.read_text(encoding='utf-8'))
        manifest.update(parent_manifest_sha256=hashlib.sha256(parent.read_bytes()).hexdigest(),input_sources=source.get('sources'),base_parser_engine=source.get('engine'),inherited_correlation_policy=source.get('multi_ip_correlation'),source_timezone=source.get('timezone'))
    (out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    return manifest

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--database',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--rules',type=Path,default=Path(__file__).resolve().parents[1]/'relation-rules/ip-associations.yaml')
    p.add_argument('--ownership',type=Path,help='Offline JSON list of network/operator/asn/source/lookup_time records')
    a=p.parse_args();print(json.dumps(run(a.database,a.output,a.rules,a.ownership)['counts']))
