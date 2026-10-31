"""Opt-in offline client-continuity hypotheses; no person/device attribution."""
import argparse,hashlib,html,ipaddress,json,sqlite3,statistics
from collections import Counter
from datetime import datetime,timezone
from functools import lru_cache
from pathlib import Path
import yaml

VERSION='0.5.0-beta.2'
URL='https://github.com/mariovilnius/artefact-finder'
@lru_cache(maxsize=8192)
def canonical(value):
    if not value:return None
    try:
        ip=ipaddress.ip_address(value)
        return str(ip.ipv4_mapped or ip) if isinstance(ip,ipaddress.IPv6Address) else str(ip)
    except ValueError:return None

def ref(row):
    if row is None:return None
    row=dict(row)
    return {k:row.get(k) for k in ('account','host','protocol','ip','time','second','file','line','raw')}

def policy(path):
    data=yaml.safe_load(Path(path).read_text(encoding='utf-8'))
    for name in ('poll_gap_max_seconds','max_handover_span_seconds','min_bundle_accounts'):
        if type(data.get(name)) is not int or data[name]<1:raise ValueError(name)
    return data

def run(database,output,rules,parent_manifest=None,reference_ip=None,accounts=(),exclude_ips=()):
    config=policy(rules);out=Path(output)
    if out.exists():raise ValueError('Use a new output directory')
    parent=json.loads(Path(parent_manifest).read_text(encoding='utf-8')) if parent_manifest else {}
    excluded={canonical(x) for x in list(exclude_ips)+parent.get('multi_ip_correlation',{}).get('excluded_ips',[])}
    if None in excluded:raise ValueError('Invalid excluded IP')
    chosen=canonical(reference_ip) if reference_ip else None
    if reference_ip and (chosen is None or chosen in excluded):raise ValueError('Invalid or excluded reference IP')
    db=sqlite3.connect(Path(database).resolve().as_uri()+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
    db.create_function('canonical_ip',1,canonical,deterministic=True)
    profiles={};previous={};last_endpoint=None;deduplicated=0
    cursor=db.execute("SELECT account,host,protocol,canonical_ip(ip) AS ip,second,time,file,line FROM events WHERE kind='auth_success' AND second IS NOT NULL AND canonical_ip(ip) IS NOT NULL ORDER BY canonical_ip(ip),second,host,account,protocol,file,line")
    for row in cursor:
        address=row['ip']
        if address in excluded:continue
        identity=(row['host'],row['account'],row['protocol'],address,row['second'])
        if identity==last_endpoint:deduplicated+=1;continue
        last_endpoint=identity
        if address not in profiles:profiles[address]=dict(ip=address,accounts={},protocols=set(),days=set(),gaps=[],endpoint_seconds=0,first=ref(row),last=None)
        p=profiles[address];p['endpoint_seconds']+=1;p['last']=ref(row);p['days'].add(row['time'][:10]);p['protocols'].add(row['protocol'])
        a=p['accounts'].setdefault(row['account'],dict(first=ref(row),last=None,endpoint_seconds=0));a['last']=ref(row);a['endpoint_seconds']+=1
        key=(address,row['host'],row['account'],row['protocol'])
        if key in previous and 0<row['second']-previous[key]<=config['poll_gap_max_seconds']:p['gaps'].append(row['second']-previous[key])
        previous[key]=row['second']
    for p in profiles.values():
        p['protocols']=sorted(p['protocols'],key=str);p['active_days']=len(p.pop('days'));gaps=p.pop('gaps');p['poll_gap_samples']=len(gaps);p['median_poll_gap_seconds']=statistics.median(gaps) if gaps else None
    if chosen and chosen not in profiles:raise ValueError('Reference IP has no eligible success evidence')
    baseline=profiles.get(chosen) if chosen else (max(profiles.values(),key=lambda x:(len(x['accounts']),x['active_days'],x['endpoint_seconds'])) if profiles else None)
    targets=set(accounts)
    relevant=sorted([x for x in profiles.values() if len(x['accounts'])>=config['min_bundle_accounts'] and (not targets or targets.intersection(x['accounts']))],key=lambda x:(-len(x['accounts']),-x['endpoint_seconds'],x['ip']))
    evidence=[]
    for candidate in relevant:
        if baseline is None or candidate['ip']==baseline['ip']:continue
        for account,a in candidate['accounts'].items():
            if targets and account not in targets:continue
            start=a['first']['second'];end=a['last']['second'];address=baseline['ip']
            before=db.execute("SELECT * FROM events WHERE account=? AND canonical_ip(ip)=? AND kind='auth_success' AND second<? ORDER BY second DESC,file,line LIMIT 1",(account,address,start)).fetchone()
            after=db.execute("SELECT * FROM events WHERE account=? AND canonical_ip(ip)=? AND kind='auth_success' AND second>? ORDER BY second,file,line LIMIT 1",(account,address,end)).fetchone()
            overlaps=[ref(x) for x in db.execute("SELECT * FROM events WHERE account=? AND canonical_ip(ip)=? AND kind='auth_success' AND second BETWEEN ? AND ? ORDER BY second,file,line LIMIT 1",(account,address,start,end))]
            count=db.execute("SELECT COUNT(*) FROM events WHERE account=? AND canonical_ip(ip)=? AND kind='auth_success' AND second BETWEEN ? AND ?",(account,address,start,end)).fetchone()[0]
            span=after['second']-before['second'] if before and after else None
            status='overlapping_endpoint_activity' if count else 'insufficient_history'
            if not count and span is not None:
                status='compatible_with_handover_unconfirmed' if span<=config['max_handover_span_seconds'] else 'observation_gap_too_long'
            path=[]
            if span is not None and span<=config['max_handover_span_seconds']:
                groups=db.execute("SELECT canonical_ip(ip) AS ip,protocol,COUNT(*) AS rows,MIN(second) AS first_second,MAX(second) AS last_second FROM events WHERE account=? AND kind='auth_success' AND second>? AND second<? AND canonical_ip(ip) IS NOT NULL GROUP BY canonical_ip(ip),protocol ORDER BY first_second",(account,before['second'],after['second'])).fetchall()
                for g in groups:
                    if g['ip'] in excluded:continue
                    points=[]
                    for second in (g['first_second'],g['last_second']):
                        points.append(ref(db.execute("SELECT * FROM events WHERE account=? AND canonical_ip(ip)=? AND protocol IS ? AND kind='auth_success' AND second=? ORDER BY file,line LIMIT 1",(account,g['ip'],g['protocol'],second)).fetchone()))
                    path.append(dict(ip=g['ip'],protocol=g['protocol'],raw_rows=g['rows'],first=points[0],last=points[1]))
            evidence.append(dict(account=account,candidate_ip=candidate['ip'],bundle_accounts=sorted(candidate['accounts']),candidate_first=a['first'],candidate_last=a['last'],reference_ip=address,reference_last_before=ref(before),reference_first_after=ref(after),reference_raw_logins_during=count,reference_overlap_sample=overlaps,intermediate_endpoint_intervals=path,status=status,identity_attribution='person_and_device_unknown',window_span_seconds=span))
    nonunique=db.execute("SELECT COUNT(*) FROM events WHERE kind='auth_success' AND second IS NULL").fetchone()[0]
    db.close();out.mkdir(parents=True)
    generated=datetime.now(timezone.utc).isoformat(timespec='seconds')
    manifest=dict(engine=dict(name='Artefact Finder client continuity',url=URL,version=VERSION),module='client_continuity',release_status='beta',execution_mode='explicit_opt_in_only',generated_at_utc=generated,source_timezone=parent.get('timezone'),base_engine=parent.get('engine'),sources=parent.get('sources'),target_accounts=sorted(targets),excluded_ips=sorted(excluded),reference_ip=baseline['ip'] if baseline else None,reference_selection='caller_supplied_not_trusted_identity' if chosen else 'largest_account_bundle_then_active_days_then_endpoint_seconds_not_trusted_identity',rules=config,rule_sha256=hashlib.sha256(Path(rules).read_bytes()).hexdigest(),module_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),parent_manifest_sha256=hashlib.sha256(Path(parent_manifest).read_bytes()).hexdigest() if parent_manifest else None,counts=dict(observed_ips=len(profiles),eligible_bundle_ips=len(relevant),handover_reviews=len(evidence),eligible_endpoint_seconds=sum(x['endpoint_seconds'] for x in profiles.values()),nonunique_auth_success_rows_excluded=nonunique,same_second_endpoint_duplicates_ignored=deduplicated,status_counts=dict(Counter(x['status'] for x in evidence))),limitations=['not_person_or_device_identification','not_a_physical_travel_detector','same_user_multiple_devices_and_NAT_VPN_possible','login_overlap_not_session_duration_overlap','account_bundle_and_poll_rhythm_not_unique_fingerprints','no_geolocation_or_network_queries','server_timezone_not_changed_by_travel','missing_and_ambiguous_UTC_excluded','failed_logins_and_mail_actions_require_separate_cross_mailbox_analysis','reference_IP_is_not_automatically_a_company_allowlist','no_automatic_suppression_or_blocking'])
    for name,value in [('manifest.json',manifest),('endpoint-profiles.json',relevant),('handover-evidence.json',evidence)]:
        (out/name).write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    render(out,manifest,relevant,evidence)
    return manifest

def render(out,manifest,profiles,evidence):
    def esc(x):return html.escape(str(x))
    def point(x):return (x['time']+' / '+x['file']+':'+str(x['line'])) if x else 'Nerasta / nepakanka istorijos'
    def table(headers,rows):return '<div class="scroll"><table><tr>'+''.join('<th>'+esc(x)+'</th>' for x in headers)+'</tr>'+''.join('<tr>'+''.join('<td>'+esc(x)+'</td>' for x in row)+'</tr>' for row in rows)+'</table></div>'
    text='<h1>Pasirenkamas kliento tęstinumo modulis</h1><p>Ataskaitos redakcija 0.1 | '+esc(manifest['generated_at_utc'])+' [UTC] | '+esc(manifest['engine']['name'])+' '+VERSION+' | '+URL+'</p>'
    text+='<p>Bazinis variklis: '+esc(manifest.get('base_engine'))+'. Įvykių šaltinio zona: '+esc(manifest.get('source_timezone'))+'. Tai galimo kliento / IP tęstinumo hipotezės, ne patvirtintos kelionės, įrenginio ar asmens tapatybės. Vienas naudotojas gali turėti kelis įrenginius; bendras NAT / VPN gali jungti skirtingus žmones. Modulis įjungiamas tik atskira komanda ir neslopina kitų tyrimo radinių.</p>'
    text+='<p>Atskaitos IP '+esc(manifest['reference_ip'])+' yra palyginimo taškas, ne automatiškai patvirtintas įmonės adresas. Žemiau login laikai, ne nustatytos sesijų trukmės. Geografiniai atstumai ir kelionės greičiai neskaičiuojami; serverio laikas nesikeičia keliaujant klientui.</p>'
    text+='<h2>Dėžučių rinkiniai ir ritmas</h2>'+table(['IP','Dėžutės','Pirmas login / eilutė','Paskutinis login / eilutė','Aktyvių dienų / medianinis tarpas s'],[[p['ip'],'; '.join(sorted(p['accounts'])),point(p['first']),point(p['last']),str(p['active_days'])+' / '+str(p['median_poll_gap_seconds'])] for p in profiles])
    text+='<h2>Ankstesnis IP → kandidatinis IP → vėlesnis login</h2><p>Rinkinio panašumas nėra unikalus įrenginio atspaudas. Suderinamumas su persijungimu nėra tapatybės patvirtinimas. Jei trūksta ankstesnio ar vėlesnio atskaitos login, rezultatas lieka insufficient_history. Jeigu atskaitos IP tebetikrina tą pačią dėžutę kandidatinio IP intervale, žymima overlapping_endpoint_activity, o ne skirtingas žmogus.</p>'
    text+=table(['Dėžutė / kandidatinis IP','Ankstesnis atskaitos login','Pirmas kandidatinis login','Paskutinis kandidatinis login','Vėlesnis atskaitos login','Ataskaitos IP login intervale','Vertinimas'],[[e['account']+' / '+e['candidate_ip'],point(e['reference_last_before']),point(e['candidate_first']),point(e['candidate_last']),point(e['reference_first_after']),e['reference_raw_logins_during'],e['status']] for e in evidence])
    text+='<h2>Tarpiniai IP ir tikslūs įrodymai</h2>'
    for e in evidence:
        if not e['intermediate_endpoint_intervals']:continue
        text+='<h3>'+esc(e['account']+' / '+e['candidate_ip'])+'</h3>'+table(['IP / protokolas','Pirmas login / eilutė','Paskutinis login / eilutė','Raw eilučių'],[[x['ip']+' / '+str(x['protocol']),point(x['first']),point(x['last']),x['raw_rows']] for x in e['intermediate_endpoint_intervals']])
    text+='<p>Intervalai gali persidengti; pirmas ir paskutinis login neįrodo nuolatinio veikimo. Ataskaitoje nekeičiamas įvykių laikas pagal numanomą IP šalį. Patvirtinimui sutikrinti kelionių informaciją, sukonfigūruotas dėžutes ir tikrinimo periodus, VPN bei kitus įrenginius; iš tiekėjo prašyti tikro webmail IP, User-Agent ir sesijų / proceso ryšių. Vienkartinis serverio session ID, PID, TLS ar PLAIN žyma nėra pastovus įrenginio identifikatorius.</p>'
    for name in ('manifest.json','endpoint-profiles.json','handover-evidence.json'):text+='<p><a href="'+name+'">'+name+'</a></p>'
    css='body{font:15px/1.5 Segoe UI,sans-serif;max-width:1500px;margin:30px auto;padding:0 24px}h2{margin-top:36px}table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #ccd3da;padding:8px;vertical-align:top;overflow-wrap:anywhere}th{background:#eaf0f5}.scroll{overflow:auto}'
    (out/'client-continuity.html').write_text('<!doctype html><html lang="lt"><meta charset="utf-8"><title>Kliento tęstinumo hipotezės</title><style>'+css+'</style>'+text+'</html>',encoding='utf-8')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--database',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--parent-manifest',type=Path);p.add_argument('--reference-ip');p.add_argument('--account',action='append',default=[]);p.add_argument('--exclude-ip',action='append',default=[]);p.add_argument('--rules',type=Path,default=Path(__file__).resolve().parents[1]/'relation-rules/client-continuity.yaml');a=p.parse_args()
    print(json.dumps(run(a.database,a.output,a.rules,a.parent_manifest,a.reference_ip,a.account,a.exclude_ip)['counts']))
