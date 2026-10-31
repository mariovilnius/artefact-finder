"""Offline cross-mailbox evidence comparison; temporal context is not attribution."""
import argparse,csv,hashlib,ipaddress,json,re,sqlite3
from collections import defaultdict
from datetime import datetime,timezone
from email.header import decode_header,make_header
from pathlib import Path
import yaml

VERSION='0.5.0-beta.2'
URL='https://github.com/mariovilnius/artefact-finder'
ACTIONS=('mail_copy','mail_delete_flag','mail_expunge')
SCHEMA='account TEXT,host TEXT,protocol TEXT,kind TEXT,ip TEXT,second INTEGER,time TEXT,file TEXT,line INTEGER,raw TEXT,session TEXT,retr_commands INTEGER,retr_bytes INTEGER,del_counter INTEGER'

def index_events(events,database):
    """Portable input path. Index every account-bearing event, preserving raw refs."""
    database=Path(database)
    if database.exists():raise ValueError('Index path already exists')
    db=sqlite3.connect(database);db.execute('CREATE TABLE events('+SCHEMA+')')
    batch=[];digest=hashlib.sha256()
    with Path(events).open('rb') as source:
        for raw in source:
            digest.update(raw);e=json.loads(raw)
            if not e.get('account'):continue
            candidates=e.get('utc_candidates',[])
            second=int(datetime.fromisoformat(candidates[0]).timestamp()) if len(candidates)==1 else None
            local=' / '.join(e.get('local_candidates',[])) or e.get('timestamp_local_naive') or 'unknown'
            match=re.search(r'retr=(\d+)/(\d+),\s*del=(\d+)/(\d+)',e['raw'])
            batch.append((e['account'],e.get('host'),e.get('protocol'),e['event_type'],e.get('source_ip'),second,local,e['file'],e['line'],e['raw'],e.get('session_id'),int(match[1]) if match else 0,int(match[2]) if match else 0,int(match[3]) if match else 0))
            if len(batch)>=5000:db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',batch);batch=[]
    if batch:db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',batch)
    db.execute('CREATE INDEX by_account_time ON events(account,second)');db.commit();db.close()
    return digest.hexdigest()

def endpoint(value):
    ip=ipaddress.ip_address(value)
    return str(ip.ipv4_mapped or ip) if isinstance(ip,ipaddress.IPv6Address) else str(ip)

def reference(row):
    return {k:row.get(k) for k in ('account','host','protocol','ip','second','time','file','line','raw','session','kind')}

def load_rules(path):
    config=yaml.safe_load(Path(path).read_text(encoding='utf-8'))
    for key,maximum in [('failure_success_seconds',86400),('action_after_success_seconds',86400),('transfer_login_before_seconds',86400),('transfer_login_after_seconds',86400),('large_retr_bytes',10**18),('bulk_gap_seconds',86400),('bulk_min_message_keys',1000000)]:
        if type(config.get(key)) is not int or not 0<=config[key]<=maximum:raise ValueError(key)
    if config['bulk_min_message_keys']==0:raise ValueError('bulk_min_message_keys must be positive')
    re.compile(config['security_subject_pattern']);re.compile(config['security_subject_exclude'])
    return config

def security_messages(db,config):
    """Lexical security-message candidates, followed by full account/message ID."""
    groups=defaultdict(list);subjects={};matched=set()
    pattern=re.compile(config['security_subject_pattern']);exclude=re.compile(config['security_subject_exclude'])
    for item in db.execute("SELECT * FROM events WHERE kind IN ('mail_copy','mail_delete_flag','mail_expunge') ORDER BY second,file,line"):
        row=dict(item);message=re.search(r'\bmsgid=(<[^>]*>|[^,]+)',row['raw'])
        identity=message[1] if message and message[1] not in ('<>','NIL','null','') else row['file']+':'+str(row['line'])
        key=(row['host'],row['account'],identity);groups[key].append(row)
        subject=row['raw'].split('subject=',1)[-1] if 'subject=' in row['raw'] else ''
        try:subject=str(make_header(decode_header(subject)))
        except (LookupError,UnicodeError,ValueError):pass
        if pattern.search(subject) and not exclude.search(subject):matched.add(key);subjects[key]=subject
    return [dict(host=key[0],account=key[1],message_id=key[2],subject=subjects[key],actions=[reference(x) for x in groups[key]],status='lexical_security_message_review_candidate_not_proven_code_use') for key in sorted(matched)]

def bulk_actions(db,config):
    """Mailbox-scoped UID/Message-ID keys; repeated lines cannot inflate size."""
    active={};result=[]
    def finish(group):
        if len(group['keys'])>=config['bulk_min_message_keys']:
            result.append(dict(account=group['rows'][0]['account'],host=group['rows'][0]['host'],protocol=group['rows'][0]['protocol'],operation=group['rows'][0]['kind'],box=group['box'],distinct_message_keys=len(group['keys']),raw_rows=len(group['rows']),first=reference(group['rows'][0]),last=reference(group['rows'][-1]),evidence=[reference(x) for x in group['rows']],attribution='action_IP_only_if_explicit_no_login_inheritance'))
    for item in db.execute("SELECT * FROM events WHERE kind IN ('mail_copy','mail_delete_flag','mail_expunge') AND second IS NOT NULL ORDER BY host,account,protocol,kind,second,file,line"):
        row=dict(item)
        def field(name):
            match=re.search(r'\b'+name+r'=([^,]+)',row['raw']);return match[1].strip() if match else None
        box=field('box');uid=field('uid');msgid=field('msgid')
        key=(row['host'],row['account'],row['protocol'],row['kind'],box)
        group=active.get(key)
        if group and row['second']-group['rows'][-1]['second']>config['bulk_gap_seconds']:
            finish(group);group=None
        if group is None:group=dict(box=box,rows=[],keys=set());active[key]=group
        group['rows'].append(row)
        if uid is not None or msgid is not None:group['keys'].add((box,uid,msgid))
    for group in active.values():finish(group)
    return sorted(result,key=lambda x:(-x['distinct_message_keys'],x['account'],x['first']['second']))

def run(database,output,rules,parent_manifest=None,memberships=None):
    config=load_rules(rules);out=Path(output)
    if out.exists():raise ValueError('Use a new output directory')
    db=sqlite3.connect(Path(database).resolve().as_uri()+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
    parent=json.loads(Path(parent_manifest).read_text(encoding='utf-8')) if parent_manifest else {}
    proxies={endpoint(x) for x in parent.get('multi_ip_correlation',{}).get('excluded_ips',[])}
    ownership={x['ip']:x for x in json.loads(Path(memberships).read_text(encoding='utf-8'))} if memberships else {}
    out.mkdir(parents=True)
    grouped=defaultdict(lambda:defaultdict(lambda:dict(success=0,failure=0,first=None,last=None,first_success=None,last_success=None,first_failure=None,last_failure=None)))
    pending={};chains=[];skipped=0
    cursor=db.execute("SELECT * FROM events WHERE kind IN ('auth_success','auth_failure') AND ip IS NOT NULL ORDER BY host,account,second,file,line")
    for item in cursor:
        row=dict(item);address=endpoint(row['ip']);row['ip']=address
        status='success' if row['kind']=='auth_success' else 'failure';g=grouped[address][row['account']];g[status]+=1
        for suffix in ('', '_'+status):
            first=g['first'+suffix];last=g['last'+suffix];second=row['second']
            if first is None or (second is not None and (first['second'] is None or second<first['second'])):g['first'+suffix]=reference(row)
            if last is None or (second is not None and (last['second'] is None or second>last['second'])):g['last'+suffix]=reference(row)
        if row['second'] is None:skipped+=1;continue
        key=(row['host'],row['account'],row['protocol'],address)
        if status=='failure':pending[key]=row
        elif key in pending:
            failure=pending.pop(key);gap=row['second']-failure['second']
            if 0<=gap<=config['failure_success_seconds']:
                chains.append(dict(failure=reference(failure),success=reference(row),gap_seconds=gap,_second=row['second'],status='observed_same_endpoint_auth_sequence_not_password_guess_proof'))
    shared=[]
    for address,accounts in grouped.items():
        if len(accounts)<2:continue
        # First/last are per-account and account rows are ordered in UTC; ambiguous refs remain explicit.
        success_accounts=sorted(a for a,v in accounts.items() if v['success'])
        known=ownership.get(address,{})
        shared.append(dict(ip=address,success_accounts=success_accounts,all_auth_accounts=sorted(accounts),accounts=dict(accounts),known_provider_proxy=address in proxies,operator=known.get('operator'),registration_network=known.get('registration_network'),status='observed_shared_endpoint_not_person_or_common_attacker',ownership_basis='retained_offline_cache_not_historical_identity'))
    shared.sort(key=lambda x:(x['known_provider_proxy'],-len(x['success_accounts']),-len(x['all_auth_accounts']),x['ip']))
    def nearby(account,host,first,last):
        return [dict(x) for x in db.execute('SELECT * FROM events WHERE account=? AND host IS ? AND second BETWEEN ? AND ? ORDER BY second,file,line',(account,host,first,last))]
    def mail_context(rows):
        result=[]
        for x in rows:
            if x['kind'] in ACTIONS or x['retr_commands']>0 or x['del_counter']>0:
                result.append(dict(**reference(x),retr_commands=x['retr_commands'],retr_bytes=x['retr_bytes'],del_counter=x['del_counter'],attribution='direct_IP_on_row' if x['ip'] else 'source_IP_unknown_temporal_context_only'))
        return result
    for chain in chains:
        s=chain['success'];t=chain.pop('_second')
        chain['following_actions']=mail_context(nearby(s['account'],s['host'],t,t+config['action_after_success_seconds']))
        chain['following_action_link']='same_account_host_time_window_not_session_attribution'
    transfers=[]
    for item in db.execute('SELECT * FROM events WHERE retr_bytes>=? AND retr_commands>0 ORDER BY retr_bytes DESC,file,line',(config['large_retr_bytes'],)):
        row=dict(item);candidates=[]
        if row['second'] is not None:
            context=nearby(row['account'],row['host'],row['second']-config['transfer_login_before_seconds'],row['second']+config['transfer_login_after_seconds'])
            by_ip=defaultdict(list)
            for x in context:
                if x['kind']=='auth_success' and x['ip']:by_ip[endpoint(x['ip'])].append(x)
            candidates=[dict(ip=address,raw_login_rows=len(items),first=reference(items[0]),last=reference(items[-1]),attribution='candidate_login_endpoint_not_proven_transfer_source') for address,items in sorted(by_ip.items())]
        transfers.append(dict(**reference(row),retr_commands=row['retr_commands'],retr_bytes=row['retr_bytes'],del_counter=row['del_counter'],login_candidates=candidates,attribution='direct_IP_on_row' if row['ip'] else 'transfer_source_IP_unknown',interpretation='RETR_commands_not_unique_messages_or_complete_mailbox_copy'))
    bursts=bulk_actions(db,config)
    for burst in bursts:
        a=burst['first'];b=burst['last'];rows=nearby(a['account'],a['host'],a['second']-config['action_after_success_seconds'],b['second']+config['action_after_success_seconds'])
        burst['login_candidates']=[reference(x) for x in rows if x['kind']=='auth_success']
        burst['login_candidate_attribution']='temporal_context_only_not_action_source'
    security=security_messages(db,config)
    for message in security:
        candidates={}
        for action in message['actions']:
            if action['second'] is None:continue
            for row in nearby(action['account'],action['host'],action['second']-config['action_after_success_seconds'],action['second']+config['action_after_success_seconds']):
                if row['kind']=='auth_success':candidates[(row['file'],row['line'])]=reference(row)
        message['login_candidates']=list(candidates.values());message['login_attribution']='temporal_context_not_action_source_or_code_use'
    for name,rows in [('shared-ips.json',shared),('failure-success-actions.json',chains),('large-transfers-context.json',transfers),('bulk-actions-context.json',bursts),('security-message-actions.json',security)]:
        (out/name).write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
    with (out/'failure-success-actions.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.writer(f);w.writerow(['account','protocol','ip','failure_time','failure_file','failure_line','success_time','success_file','success_line','gap_seconds','following_action_rows','action_attribution'])
        for x in chains:
            a=x['failure'];b=x['success'];values=[b['account'],b['protocol'],b['ip'],a['time'],a['file'],a['line'],b['time'],b['file'],b['line'],x['gap_seconds'],len(x['following_actions']),'temporal_context_only']
            w.writerow(["'"+v if isinstance(v,str) and v.startswith(('=','+','-','@','\t','\r')) else v for v in values])
    manifest=dict(engine=dict(name='Artefact Finder',url=URL,version=VERSION),module='cross_mailbox',release_status='beta',generated_at_utc=datetime.now(timezone.utc).isoformat(timespec='seconds'),source_timezone=parent.get('timezone'),parent_engine=parent.get('engine'),sources=parent.get('sources'),rules=config,rule_sha256=hashlib.sha256(Path(rules).read_bytes()).hexdigest(),module_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),parent_manifest_sha256=hashlib.sha256(Path(parent_manifest).read_bytes()).hexdigest() if parent_manifest else None,ownership_sha256=hashlib.sha256(Path(memberships).read_bytes()).hexdigest() if memberships else None,known_provider_proxies=sorted(proxies),counts=dict(shared_auth_ips=len(shared),shared_success_ips=sum(len(x['success_accounts'])>=2 for x in shared),failure_success_sequences=len(chains),sequences_with_following_actions=sum(bool(x['following_actions']) for x in chains),large_transfers=len(transfers),nonunique_auth_time_rows=skipped),limitations=['not_person_device_or_attacker_attribution','multiple_devices_dynamic_IP_NAT_VPN_possible','raw_auth_duplicates_preserved','only_unique_UTC_in_sequence_matching','actions_without_session_keys_remain_unattributed','large_RETR_can_be_resynchronization','provider_proxy_IP_does_not_identify_browser_client','failed_only_account_names_do_not_prove_mailbox_exists'])
    manifest['counts']['bulk_action_groups']=len(bursts)
    manifest['counts']['security_message_groups']=len(security)
    manifest['counts']['security_message_action_rows']=sum(len(x['actions']) for x in security)
    (out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8');db.close()
    return manifest

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    source=p.add_mutually_exclusive_group(required=True);source.add_argument('--database',type=Path);source.add_argument('--events',type=Path)
    p.add_argument('--index',type=Path,help='New private SQLite index for --events')
    p.add_argument('--output',required=True,type=Path);p.add_argument('--parent-manifest',type=Path);p.add_argument('--memberships',type=Path)
    p.add_argument('--rules',type=Path,default=Path(__file__).resolve().parents[1]/'relation-rules/cross-mailbox.yaml')
    args=p.parse_args();load_rules(args.rules)
    if args.output.exists():p.error('Use a new output directory')
    if args.events:
        if not args.index:p.error('--events requires --index')
        input_hash=index_events(args.events,args.index);args.database=args.index
    elif args.index:p.error('--index requires --events')
    result=run(args.database,args.output,args.rules,args.parent_manifest,args.memberships)
    if args.events:
        result['events_sha256']=input_hash;(args.output/'manifest.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result['counts']))
