from datetime import datetime, timezone
SEV={'INFORMATIONAL':10,'LOW':30,'MEDIUM':50,'HIGH':70,'CRITICAL':90}
SOURCE={'A':100,'B':85,'C':65,'D':40}

def classification(score):
    if score<=20:return 'INFORMATIONAL'
    if score<=40:return 'LOW'
    if score<=60:return 'MEDIUM'
    if score<=80:return 'HIGH'
    return 'CRITICAL'

def calculate_threat_risk(severity,confidence,recency=100,observations=1,source_reliability='B',context=50,related_alerts=0):
    obs=min(100,observations*10); alerts=min(100,related_alerts*20); src=SOURCE.get(source_reliability,40)
    score=SEV.get(severity,10)*.30 + confidence*.25 + recency*.15 + obs*.10 + src*.10 + min(100,(context*.8+alerts*.2))*.10
    score=round(max(0,min(100,score)))
    return {'score':score,'classification':classification(score)}

def calculate_confidence(source_reliability,observations,validation_ok=True,corroborated=False):
    src=SOURCE.get(source_reliability,40); score=src*.45 + min(100,observations*10)*.25 + (20 if validation_ok else 0) + (20 if corroborated else 0)
    return round(max(0,min(100,score)))

def calculate_vulnerability_priority(cvss,asset_criticality,exposure,known_exploitation,business_context):
    score=cvss*10*.30 + asset_criticality*.20 + exposure*.20 + known_exploitation*.20 + business_context*.10
    return round(max(0,min(100,score)))
