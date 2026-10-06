from backend.services.threat_service import init_db,get_db,fetch_threats
from backend.services.alert_engine import generate_threat_alert
init_db(); conn=get_db()
for row in fetch_threats({'limit':5000}):
    a=generate_threat_alert(row)
    if a: conn.execute('INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?,?,?,?,?)',(a['alert_id'],a['threat_id'],a['timestamp'],a['alert_type'],a['severity'],a['risk_score'],a['confidence_score'],a['description'],a['status']))
conn.commit(); conn.close(); print('Synthetic alerts seeded.')
