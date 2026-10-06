import ipaddress,re
from urllib.parse import urlparse
DOMAIN_RE=re.compile(r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,63}|invalid)$')
CVE_RE=re.compile(r'^CVE-\d{4}-\d{4,}$',re.I)
HASH_RE={32:'MD5-format',40:'SHA-1-format',64:'SHA-256-format'}

def validate_indicator(value):
    raw=(value or '').strip(); notes=[]
    if not raw: return {'valid':False,'indicator_type':'UNKNOWN','normalized_value':'','validation_notes':'Empty indicator.'}
    try: ipaddress.ip_address(raw); return {'valid':True,'indicator_type':'IP ADDRESS','normalized_value':raw,'validation_notes':'Syntactically valid IP address; no reputation lookup performed.'}
    except ValueError: pass
    if CVE_RE.fullmatch(raw): return {'valid':True,'indicator_type':'CVE ID','normalized_value':raw.upper(),'validation_notes':'Syntactically valid CVE identifier; validity does not imply severity or exploitation.'}
    if len(raw) in HASH_RE and re.fullmatch(r'[0-9a-fA-F]+',raw): return {'valid':True,'indicator_type':'FILE HASH','normalized_value':raw.lower(),'validation_notes':HASH_RE[len(raw)]+' format.'}
    candidate=raw if '://' in raw else 'https://'+raw
    parsed=urlparse(candidate)
    if parsed.scheme in {'http','https'} and parsed.netloc and (raw.startswith('http://') or raw.startswith('https://')):
        return {'valid':True,'indicator_type':'URL','normalized_value':raw,'validation_notes':'Syntactically valid URL; the application will not visit it.'}
    if DOMAIN_RE.fullmatch(raw.lower()):
        return {'valid':True,'indicator_type':'DOMAIN','normalized_value':raw.lower().rstrip('.'),'validation_notes':'Syntactically valid domain; no DNS/reputation lookup performed.'}
    return {'valid':False,'indicator_type':'UNKNOWN','normalized_value':raw,'validation_notes':'Unsupported or invalid indicator syntax.'}
