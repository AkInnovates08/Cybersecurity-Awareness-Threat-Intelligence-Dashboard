"""Generate 2,000+ safe synthetic CTI records. No network access is used."""
from pathlib import Path
from datetime import datetime, timedelta
import csv, hashlib, random

random.seed(20261006)
ROOT=Path(__file__).resolve().parent
OUT=ROOT/'threat_intelligence_dataset.csv'
CATEGORIES=[
 ('PHISHING','Synthetic Credential Phishing Campaign'),('MALWARE','Synthetic Malware Observation'),
 ('RANSOMWARE','Synthetic Ransomware Awareness Event'),('CREDENTIAL THREATS','Synthetic Credential Exposure'),
 ('WEB THREATS','Synthetic Web Threat Observation'),('NETWORK THREATS','Synthetic Network Anomaly'),
 ('VULNERABILITY EXPOSURE','Synthetic Vulnerability Exposure'),('SOCIAL ENGINEERING','Synthetic Social Engineering Event'),
 ('DATA EXPOSURE','Synthetic Data Exposure Signal'),('ACCOUNT SECURITY','Synthetic Account Security Event')]
INDICATOR_TYPES=['IP ADDRESS','DOMAIN','URL','FILE HASH','EMAIL/SENDER DOMAIN','CVE ID']
SOURCES=[('Internal SOC','A'),('Security Vendor','A'),('Public Threat Feed','B'),('Research Report','B'),('Community Submission','C'),('Unknown Source','D')]
SEVERITIES=['INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL']
STATUSES=['NEW','UNDER_REVIEW','MONITORING','CLOSED','FALSE_POSITIVE']
REGIONS=['India','US','EU','APAC','Global']
CATEGORY_ATTACK={'PHISHING':('Initial Access','Phishing','T1566'),'CREDENTIAL THREATS':('Credential Access','Valid Accounts','T1078'),'ACCOUNT SECURITY':('Credential Access','Valid Accounts','T1078'),'RANSOMWARE':('Impact','Data Encrypted for Impact','T1486')}

HEADERS=['threat_id','timestamp','threat_name','threat_category','indicator_type','indicator_value','source_name','confidence_score','severity','risk_score','status','first_seen','last_seen','country_or_region_optional','description','mitre_tactic_optional','mitre_technique_optional','cve_id_optional']

def indicator(i, typ):
    if typ=='IP ADDRESS': return f'{random.choice([192,198,203])}.0.2.{(i%250)+1}' if random.choice([192,198,203])==192 else f'{random.choice([198,203])}.51.100.{(i%250)+1}'
    if typ=='DOMAIN': return f'{random.choice(["example.com","example.org","example.net"])}' if i%5 else 'demo.invalid'
    if typ=='URL': return f'https://demo.invalid/security-awareness/{i}'
    if typ=='FILE HASH': return hashlib.sha256(f'synthetic-{i}'.encode()).hexdigest()
    if typ=='EMAIL/SENDER DOMAIN': return f'notice-{i%50}@example.org'
    return f'CVE-2026-{1000+(i%9000):04d}'

rows=[]
base=datetime(2026,1,1)
for i in range(1,2201):
    cat,name=random.choice(CATEGORIES); typ=random.choice(INDICATOR_TYPES)
    if i==1: cat,name,typ='PHISHING','Synthetic Credential Phishing Campaign','DOMAIN'
    if i==2: cat,name,typ='PHISHING','Synthetic Credential Phishing Campaign','IP ADDRESS'
    day=base+timedelta(days=random.randint(0,278),hours=random.randint(0,23),minutes=random.randint(0,59))
    first=day-timedelta(days=random.randint(0,30)); last=day+timedelta(days=random.randint(0,20))
    sev=random.choices(SEVERITIES,weights=[8,22,35,25,10])[0]
    if i==1: sev='HIGH'
    if i==2: sev='HIGH'
    sev_base={'INFORMATIONAL':10,'LOW':30,'MEDIUM':50,'HIGH':70,'CRITICAL':90}[sev]
    confidence=random.randint(35,98)
    if i==1: confidence=85
    if i==2: confidence=85
    risk=max(0,min(100,round(sev_base*0.30+confidence*0.25+random.randint(20,100)*0.15+random.randint(1,10)*1.0+random.randint(50,100)*0.10+random.randint(20,100)*0.10)))
    source,rel=random.choice(SOURCES)
    if i in (1,2): source='Internal SOC'
    attack=CATEGORY_ATTACK.get(cat); tactic,tech,tid=(attack if attack else (None,None,None))
    cve=f'CVE-2026-{1000+(i%9000):04d}' if cat=='VULNERABILITY EXPOSURE' else ''
    if i==1: cve=''
    value=indicator(i,typ)
    if i==1: value='login-check.invalid'
    if i==2: value='198.51.100.25'
    rows.append([f'THR-2026-{i:03d}',day.isoformat(timespec='minutes'),name,cat,typ,value,source,confidence,sev,risk,('MONITORING' if i in (1,2) else random.choice(STATUSES)),first.date().isoformat(),last.date().isoformat(),random.choice(REGIONS),('Indicator appears in multiple synthetic phishing observations. DEMO ONLY.' if i in (1,2) else f'Synthetic defensive observation for {cat.lower()}. DEMO ONLY.'),tactic or '',f'{tech} ({tid})' if tech else '',cve])
with OUT.open('w',newline='',encoding='utf-8') as f:
    w=csv.writer(f); w.writerow(HEADERS); w.writerows(rows)
print(f'Generated {len(rows)} records at {OUT}')
