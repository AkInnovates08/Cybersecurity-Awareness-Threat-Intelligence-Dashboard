def correlate_threats(records):
    clusters={}
    for r in records:
        key=(r.get('campaign_id') or r.get('threat_category'), r.get('threat_category'))
        clusters.setdefault(key,[]).append(r)
    return [{'cluster_key':str(k),'observation_count':len(v),'threat_ids':[x.get('threat_id') for x in v]} for k,v in clusters.items() if len(v)>1]

def correlate_alerts(alerts):
    groups={}
    for a in alerts:
        key=(a.get('alert_type'),a.get('severity'),a.get('threat_id'))
        groups.setdefault(key,[]).append(a)
    return [{'alert_group':str(k),'observation_count':len(v),'alert_ids':[x.get('alert_id') for x in v]} for k,v in groups.items()]
