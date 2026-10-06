def generate_threat_alert(row,risk_threshold=70,confidence_threshold=60):
    risk=int(row['risk_score']); conf=int(row['confidence_score'])
    reasons=[]
    if risk>=risk_threshold: reasons.append('Risk threshold exceeded')
    if conf>=confidence_threshold and row['severity'] in {'HIGH','CRITICAL'}: reasons.append('High-confidence high-severity intelligence')
    if row.get('observation_count',1)>=10: reasons.append('Repeated observations')
    if not reasons:return None
    sev='CRITICAL' if risk>=81 else 'HIGH' if risk>=61 else 'MEDIUM'
    return {'alert_id':'ALT-'+row['threat_id'],'threat_id':row['threat_id'],'timestamp':row['last_seen'],'alert_type':'THREAT_RISK','severity':sev,'risk_score':risk,'confidence_score':conf,'description':'; '.join(reasons),'status':'NEW'}
