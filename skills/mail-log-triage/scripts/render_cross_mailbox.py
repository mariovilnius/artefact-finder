"""Render an escaped, offline review from cross_mailbox.py JSON outputs."""
import argparse,html,json,hashlib
from collections import defaultdict
from datetime import datetime,timezone
from pathlib import Path
from zoneinfo import ZoneInfo

def render(folder,revision='0.1'):
    folder=Path(folder)
    def load(name):return json.loads((folder/name).read_text(encoding='utf-8'))
    manifest=load('manifest.json');shared=load('shared-ips.json');chains=load('failure-success-actions.json');transfers=load('large-transfers-context.json');bursts=load('bulk-actions-context.json')
    security=load('security-message-actions.json') if (folder/'security-message-actions.json').exists() else []
    policy=manifest['rules']
    now=datetime.now(timezone.utc);zone=manifest.get('source_timezone');generation_zone=ZoneInfo(zone) if zone else timezone.utc
    parts=[]
    def h(s):parts.append('<h2>'+html.escape(s)+'</h2>')
    def p(s):parts.append('<p>'+html.escape(str(s))+'</p>')
    def table(headers,rows):
        parts.append('<div class="scroll"><table><thead><tr>'+''.join('<th>'+html.escape(x)+'</th>' for x in headers)+'</tr></thead><tbody>')
        for row in rows:parts.append('<tr>'+''.join('<td>'+html.escape(str(x))+'</td>' for x in row)+'</tr>')
        parts.append('</tbody></table></div>')
    def ref(x):return x['file']+':'+str(x['line'])
    def full(x):return x['time']+' / '+ref(x)
    parts.append('<h1>Visų dėžučių bendri IP ir veiksmų sekos</h1>')
    p('Peržiūros versija '+revision+' | Parengta '+now.astimezone(generation_zone).isoformat(timespec='seconds')+' ['+(zone or 'UTC')+'] | '+manifest['engine']['name']+' '+manifest['engine']['version']+' (vietinė nepaskelbta beta) | '+manifest['engine']['url'])
    p('Bazinis parseris '+str(manifest.get('parent_engine'))+'. Palyginimo modulis atskiras nuo bazinio parsavimo. Šaltinio laiko zona: '+str(zone)+'. Visi įvykiai išlaiko pilną datą, laiką iki sekundžių ir UTC poslinkį; failo eilutės numeruojamos nuo 1. Lentelėse palikti raw autentifikavimo skaičiai, įskaitant dublikatus. Nevienareikšmiai laikai nekoreliuojami. PDF ir ZIP negeneruoti.')
    p('Patvirtintas faktas: loge užfiksuotas IP ir autentifikavimo rezultatas arba konkretus laiško veiksmas. Galima sąsaja: tas pats tinklas / operatorius arba artimas laikas. Tai ne naudotojo, įrenginio ar bendro užpuoliko tapatybė. Vienas naudotojas gali turėti kelis įrenginius ir dinaminius IP; bendrą NAT / VPN gali naudoti keli žmonės. Veiksmo IP neperimamas iš gretimo login.')
    labels=dict(shared_auth_ips='IP, bandę autentifikuotis keliuose paskyrų varduose',shared_success_ips='IP su sėkmėmis keliose dėžutėse, įskaitant IV',failure_success_sequences='Nesėkmė → pirma sėkmė sekos',sequences_with_following_actions='Sekos su laiškų / RETR / del kontekstu per 60 s',large_transfers='RETR ≥50 000 000 baitų',nonunique_auth_time_rows='Nekoreliuotos nevienareikšmio laiko auth eilutės',bulk_action_groups='Didelio laiškų veiksmų grupės')
    labels['sequences_with_following_actions']='Sekos su veiksmų kontekstu per '+str(policy['action_after_success_seconds'])+' s'
    labels['large_transfers']='RETR ≥'+str(policy['large_retr_bytes'])+' baitų'
    labels['security_message_groups']='PIN / saugumo temos laiškų kandidatų'
    labels['security_message_action_rows']='Šių laiškų veiksmų eilučių'
    table(['Rodiklis','Kiekis'],[(labels.get(k,k),v) for k,v in manifest['counts'].items()])
    h('1. Svarbiausi bendri IP tarp sėkmingai tikrintų dėžučių')
    common=[x for x in shared if len(x['success_accounts'])>=2 and not x['known_provider_proxy']]
    p('Be patvirtintų proxy: '+str(len(common))+' bendri sėkmių IP. Atskirai '+str(sum(x['known_provider_proxy'] and len(x['success_accounts'])>=2 for x in shared))+' bendri patvirtintų proxy IP. Bendras IP pats savaime nėra anomalija. Žemiau pirmos 12 grupių pagal sėkmingų paskyrų aprėptį; visos grupės JSON priede.')
    for group in common[:12]:
        h(group['ip']+' — '+str(len(group['success_accounts']))+' dėžutės')
        p('Operatoriaus žyma: '+str(group['operator'] or 'nežinomas')+'; registruotas tinklas '+str(group['registration_network'] or 'nežinomas')+'. Tai ankstesnė RDAP talpykla, ne nauja ar istorinė patikra.')
        table(['Dėžutė','Sėkmių / nesėkmių raw eilutės','Pirma sėkmė / įrodymas','Paskutinė sėkmė / įrodymas','Pirma / paskutinė nesėkmė'],[[a,str(group['accounts'][a]['success'])+' / '+str(group['accounts'][a]['failure']),full(group['accounts'][a]['first_success']),full(group['accounts'][a]['last_success']),(full(group['accounts'][a]['first_failure'])+' → '+full(group['accounts'][a]['last_failure'])) if group['accounts'][a]['first_failure'] else 'Nesėkmių šiame IP nerasta'] for a in group['success_accounts']])
    h('2. Bendrų IP autentifikavimo nesėkmių ir vėlesnių sėkmių laiko sutapimai')
    coincident=defaultdict(list)
    for c in chains:coincident[(c['failure']['ip'],c['failure']['second'])].append(c)
    simultaneous=[v for v in coincident.values() if len({x['failure']['account'] for x in v})>=2]
    for items in simultaneous:
        table(['Dėžutė','IP','Nesėkmės laikas / eilutė','Vėlesnės sėkmės laikas / eilutė'],[[x['failure']['account'],x['failure']['ip'],full(x['failure']),full(x['success'])] for x in items])
    if not simultaneous:p('Tarp atrinktų paskutinė nesėkmė → pirma sėkmė sekų tokių vienos sekundės sutapimų nerasta.')
    p('Lyginamos atrinktų sekų paskutinės nesėkmės, ne visos nesėkmės. Kelių dėžučių sutrikimai iš vieno IP gali reikšti bendrą pašto tikrinimo programą, pakeistus slaptažodžius / nustatymus arba paslaugos problemą. Tai hipotezės, ne patvirtinta priežastis; reikia kliento įrenginių ir IV autentifikavimo audito.')
    h('3. Visos nesėkmė → sėkmė sekos')
    table(['Dėžutė / protokolas','IP','Nesėkmės laikas / įrodymas','Sėkmės laikas / įrodymas','Tarpas s','Vėlesnių veiksmų eilučių'],[[x['success']['account']+' / '+str(x['success']['protocol']),x['success']['ip'],full(x['failure']),full(x['success']),x['gap_seconds'],len(x['following_actions'])] for x in chains])
    p('Sąlygos: tas pats hostas, dėžutė, protokolas ir IP; paskutinė nesėkmė prieš pirmą vėlesnę sėkmę per '+str(policy['failure_success_seconds'])+' s. Šios sekos nepatvirtina slaptažodžio atspėjimo. Toliau pateiktas po sėkmės sekęs 0–'+str(policy['action_after_success_seconds'])+' s tos pačios dėžutės / hosto kontekstas, kurį galėjo sukurti kitas tuo metu prisijungęs klientas.')
    h('4. Sekos su atsisiuntimo ar laiškų veiksmų kontekstu')
    for chain in chains:
        if not chain['following_actions']:continue
        a=chain['failure'];b=chain['success'];h(b['account']+' / '+b['ip'])
        table(['Žingsnis','IP','Laikas / įrodymas'],[['Nesėkmė',a['ip'],full(a)],['Sėkmė',b['ip'],full(b)]])
        table(['Veiksmo laikas','Veiksmo IP','Protokolas / tipas','RETR komandų / baitų; del','Įrodymas','Originali eilutė'],[[x['time'],x['ip'] or 'nežinomas',str(x['protocol'])+' / '+x['kind'],str(x['retr_commands'])+' / '+str(x['retr_bytes'])+'; '+str(x['del_counter']),ref(x),x['raw']] for x in chain['following_actions']])
    p('IV proxy autentifikavimo atveju tikras naršyklės IP nežinomas; mail-copy / expunge įrašai išlieka tyrimo dalimi. Laiško perkėlimas tarp spam, INBOX ir Trash nebūtinai susijęs su PIN. Tikslią paskirtį tikrinti pagal temą ir pilną Message-ID originalioje eilutėje.')
    h('5. Didžiausi RETR: visų dėžučių palyginimas')
    selected=[];seen=set()
    for x in transfers:
        if x['account'] not in seen:selected.append(x);seen.add(x['account'])
    for x in transfers[:5]:
        if x not in selected:selected.append(x)
    important={g['ip'] for g in common if len(g['success_accounts'])>=5};shown=set()
    for x in transfers:
        if len(x['login_candidates'])!=1:continue
        address=x['login_candidates'][0]['ip'];key=(x['account'],address)
        if address in important and key not in shown:
            shown.add(key)
            if x not in selected:selected.append(x)
    selected.sort(key=lambda x:-x['retr_bytes'])
    table(['Dėžutė','Laikas / įrodymas','Patvirtintas perdavimo IP','RETR komandų / baitų','Gretimų login kandidatai, ne perdavimo šaltinis'],[[x['account'],full(x),x['ip'] or 'nežinomas',str(x['retr_commands'])+' / '+str(x['retr_bytes']),'; '.join(c['ip']+' ['+full(c['first'])+' → '+full(c['last'])+']' for c in x['login_candidates']) or 'Nėra nustatytame lange'] for x in selected])
    p('Rodomas didžiausias kiekvienos dėžutės perdavimas ir penki didžiausi bendrame rinkinyje. Papildomai — didžiausias dėžutės / kandidatinio IP atvejis, kai lange matomas vienas IP, turintis sėkmių bent penkiose dėžutėse. Visi '+str(len(transfers))+' įrašai priede. Login kandidatų langas: '+str(policy['transfer_login_before_seconds'])+' s iki logout ir '+str(policy['transfer_login_after_seconds'])+' s po jo. Tai ne sesijos pradžios nustatymas ar IP priskyrimas. RETR skaičiuoja komandas; didelis kiekis gali reikšti naujo įrenginio, profilio ar archyvo persinchronizavimą, ne patvirtintą visos dėžutės išnešimą.')
    h('6. Didelio šalinimo / perkėlimo grupės tarp dėžučių')
    chosen=[];seen=set()
    for x in bursts:
        if x['account'] not in seen:chosen.append(x);seen.add(x['account'])
    for x in bursts[:6]:
        if x not in chosen:chosen.append(x)
    chosen.sort(key=lambda x:-x['distinct_message_keys'])
    table(['Dėžutė','Veiksmas / katalogas','Pradžia / įrodymas','Pabaiga / įrodymas','Skirtingų raktų / raw eilučių','Veiksmo IP','Login IP kandidatai aplink grupę'],[[x['account'],x['operation']+' / '+str(x['box']),full(x['first']),full(x['last']),str(x['distinct_message_keys'])+' / '+str(x['raw_rows']),x['first']['ip'] or 'nežinomas',', '.join(sorted({c['ip'] for c in x['login_candidates'] if c['ip']})) or 'Nėra nustatytame lange'] for x in chosen])
    p('Visos '+str(len(bursts))+' grupės ir kiekviena jų originali eilutė priede. Mažiausiai '+str(policy['bulk_min_message_keys'])+' skirtingų (katalogas, UID, Message-ID) raktų, tarpas iki '+str(policy['bulk_gap_seconds'])+' s. Kandidatiniai login yra ±'+str(policy['action_after_success_seconds'])+' s aplink grupės intervalą ir nepatvirtina veiksmo šaltinio. Delete flag nėra expunge; expunge iš INBOX neįrodo galutinio Trash kopijos pašalinimo. Ši atranka neįrodo visos dėžutės ar katalogo išvalymo. POP3 šalinimas gali atitikti teisėtą saugojimo politiką.')
    h('7. PIN / saugumo laiškų veiksmai tarp dėžučių')
    p('Atranka pagal MIME iškoduotą temą ir YAML šabloną, toliau sekamas pilnas Message-ID tik tos pačios dėžutės / hosto kontekste. Tai laiško paskirties peržiūros kandidatai, ne patvirtintas PIN panaudojimas. Login kandidatų langas ±'+str(policy['action_after_success_seconds'])+' s apie veiksmus; proxy IP nenustato tikro naršyklės naudotojo. Copy į Trash ir expunge iš INBOX nepatvirtina Trash kopijos pašalinimo.')
    for message in security:
        h(message['account']+' / '+message['subject'])
        p('Message-ID: '+message['message_id'])
        table(['Veiksmo laikas / įrodymas','Veiksmo IP','Protokolas / veiksmas','Originali eilutė'],[[full(x),x['ip'] or 'nežinomas',str(x['protocol'])+' / '+x['kind'],x['raw']] for x in message['actions']])
        by_ip=defaultdict(list)
        for candidate in message['login_candidates']:by_ip[candidate['ip']].append(candidate)
        table(['Kandidatinis login IP, ne veiksmo šaltinis','Pirmas gretimas login / įrodymas','Paskutinis gretimas login / įrodymas'],[[address,full(rows[0]),full(rows[-1])] for address,rows in sorted(by_ip.items(),key=lambda x:str(x[0]))])
    p('Kodo išdavimo, patikrinimo, panaudojimo ir savitarnos / administravimo veiksmų šie pašto logai nepatvirtina. Šiems ryšiams tikrinti reikalingas IV savitarnos ir HTTP / Roundcube auditas.')
    h('8. Tikslinimai klientui ir IV')
    p('Identifikuoti bendrų IP pašto tikrinimo paskirtį ir kelis naudojamus įrenginius; sutikrinti lentelėse nurodytas nesėkmes su slaptažodžių ar konfigūracijos pakeitimais. Bendrus kitų operatorių adresus sutikrinti su naudotojų namų / darbo / mobiliu ryšiu ir kelionėmis. Dinaminio IP ar bendro operatoriaus nelaikyti bendra asmens tapatybe.')
    p('IV prašyti pagal kiekvienos lentelės pilnus laikus ir eilutes: originalių autentifikavimo / proceso / sesijos ryšių, tikro webmail kliento IP ir User-Agent bei kontrolės skydelio PIN / administravimo audito. Dideliam RETR būtinas tikslus sesijos / PID ryšys su login; trynimams — mail-log proceso / sesijos identifikatorius ir serverio logavimo formato paaiškinimas. Ataskaitos laiko konteksto nepaversti priežastiniu ryšiu.')
    h('9. Atkuriamumas ir priedai')
    for name in ['manifest.json','shared-ips.json','failure-success-actions.json','failure-success-actions.csv','large-transfers-context.json','bulk-actions-context.json']:
        parts.append('<p><a href="'+name+'">'+name+'</a></p>')
    if (folder/'security-message-actions.json').exists():parts.append('<p><a href="security-message-actions.json">security-message-actions.json</a></p>')
    css='body{font:15px/1.5 Segoe UI,sans-serif;max-width:1500px;margin:32px auto;padding:0 24px;color:#17212b}h2{margin-top:36px}table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #ccd3da;padding:8px;vertical-align:top;overflow-wrap:anywhere}th{background:#eaf0f5}tr:nth-child(even){background:#f8fafb}.scroll{overflow:auto}a{color:#174e78}'
    doc='<!doctype html><html lang="lt"><meta charset="utf-8"><title>Visų dėžučių palyginimas</title><style>'+css+'</style>'+''.join(parts)+'</html>'
    (folder/'Visu-dezuciu-palyginimas.html').write_text(doc,encoding='utf-8')
    metadata=dict(report_revision=revision,generated_at_utc=now.isoformat(timespec='seconds'),generated_at_local=now.astimezone(generation_zone).isoformat(timespec='seconds'),report_timezone=zone or 'UTC',engine=manifest['engine'],parent_engine=manifest.get('parent_engine'))
    metadata['analysis_manifest_sha256']=hashlib.sha256((folder/'manifest.json').read_bytes()).hexdigest()
    metadata['renderer_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (folder/'report-metadata.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2),encoding='utf-8')
    return folder/'Visu-dezuciu-palyginimas.html'

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--revision',default='0.1');a=p.parse_args();print(render(a.folder,a.revision))
