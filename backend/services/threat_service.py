import csv, sqlite3
from pathlib import Path
from .risk_engine import calculate_threat_risk, calculate_vulnerability_priority
DB=Path(__file__).resolve().parent.parent/'cybersecurity.db'
CSV_PATH=Path(__file__).resolve().parents[2]/'data'/'threat_intelligence_dataset.csv'
VULN_PATH=Path(__file__).resolve().parents[2]/'data'/'vulnerabilities.csv'

def get_db():
    conn=sqlite3.connect(DB); conn.row_factory=sqlite3.Row; return conn

def init_db():
    conn=get_db(); c=conn.cursor()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS threats(threat_id TEXT PRIMARY KEY,threat_name TEXT,category TEXT,description TEXT,severity TEXT,risk_score INTEGER,confidence_score INTEGER,status TEXT,first_seen TEXT,last_seen TEXT,indicator_type TEXT,indicator_value TEXT,source_name TEXT,source_reliability TEXT,region TEXT,mitre_tactic TEXT,mitre_technique TEXT,cve_id TEXT);
    CREATE TABLE IF NOT EXISTS indicators(indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,threat_id TEXT,indicator_type TEXT,indicator_value TEXT,first_seen TEXT,last_seen TEXT);
    CREATE TABLE IF NOT EXISTS sources(source_id INTEGER PRIMARY KEY AUTOINCREMENT,source_name TEXT UNIQUE,reliability TEXT);
    CREATE TABLE IF NOT EXISTS attack_mappings(mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,threat_id TEXT,tactic TEXT,technique TEXT,technique_id TEXT);
    CREATE TABLE IF NOT EXISTS vulnerabilities(vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT,cve_id TEXT,product_category TEXT,severity TEXT,cvss_score REAL,published_date TEXT,patch_available TEXT,exploitation_status_demo TEXT,description TEXT,priority_score INTEGER);
    CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY,threat_id TEXT,timestamp TEXT,alert_type TEXT,severity TEXT,risk_score INTEGER,confidence_score INTEGER,description TEXT,status TEXT);
    CREATE TABLE IF NOT EXISTS analyst_notes(note_id INTEGER PRIMARY KEY AUTOINCREMENT,threat_id TEXT,note TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS quiz_results(result_id INTEGER PRIMARY KEY AUTOINCREMENT,anonymous_user_id TEXT,overall_score INTEGER,created_at TEXT);
    ''')
    if c.execute('SELECT COUNT(*) FROM threats').fetchone()[0]==0:
        with CSV_PATH.open(encoding='utf-8') as f:
            for r in csv.DictReader(f):
                c.execute('INSERT INTO threats VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(r['threat_id'],r['threat_name'],r['threat_category'],r['description'],r['severity'],int(r['risk_score']),int(r['confidence_score']),r['status'],r['first_seen'],r['last_seen'],r['indicator_type'],r['indicator_value'],r['source_name'],{'Internal SOC':'A','Security Vendor':'A','Public Threat Feed':'B','Research Report':'B','Community Submission':'C','Unknown Source':'D'}[r['source_name']],r['country_or_region_optional'],r['mitre_tactic_optional'],r['mitre_technique_optional'],r['cve_id_optional']))
                c.execute('INSERT INTO indicators(threat_id,indicator_type,indicator_value,first_seen,last_seen) VALUES(?,?,?,?,?)',(r['threat_id'],r['indicator_type'],r['indicator_value'],r['first_seen'],r['last_seen']))
        for name,rel in [('Internal SOC','A'),('Security Vendor','A'),('Public Threat Feed','B'),('Research Report','B'),('Community Submission','C'),('Unknown Source','D')]: c.execute('INSERT OR IGNORE INTO sources(source_name,reliability) VALUES(?,?)',(name,rel))
    if c.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]==0:
        with VULN_PATH.open(encoding='utf-8') as f:
            for r in csv.DictReader(f):
                p=calculate_vulnerability_priority(float(r['cvss_score']),80,70,60,70)
                c.execute('INSERT INTO vulnerabilities(cve_id,product_category,severity,cvss_score,published_date,patch_available,exploitation_status_demo,description,priority_score) VALUES(?,?,?,?,?,?,?,?,?)',(r['cve_id'],r['product_category'],r['severity'],r['cvss_score'],r['published_date'],r['patch_available'],r['exploitation_status_demo'],r['description'],p))
    conn.commit(); conn.close()

def fetch_threats(filters=None):
    conn=get_db(); q='SELECT * FROM threats WHERE 1=1'; params=[]; filters=filters or {}
    for key,col in [('severity','severity'),('category','category'),('indicator_type','indicator_type'),('status','status')]:
        if filters.get(key): q+=f' AND {col}=?'; params.append(filters[key])
    if filters.get('min_risk'):
        q+=' AND risk_score>=?'; params.append(int(filters['min_risk']))
    q+=' ORDER BY last_seen DESC LIMIT ?'; params.append(min(int(filters.get('limit',100)),5000))
    rows=[dict(x) for x in conn.execute(q,params).fetchall()]; conn.close(); return rows

def fetch_threat(tid):
    conn=get_db(); row=conn.execute('SELECT * FROM threats WHERE threat_id=?',(tid,)).fetchone();
    if not row: conn.close(); return None
    d=dict(row); d['related_indicators']=[dict(x) for x in conn.execute('SELECT * FROM indicators WHERE threat_id=?',(tid,)).fetchall()]; d['notes']=[dict(x) for x in conn.execute('SELECT * FROM analyst_notes WHERE threat_id=? ORDER BY created_at DESC',(tid,)).fetchall()]; d['alerts']=[dict(x) for x in conn.execute('SELECT * FROM alerts WHERE threat_id=?',(tid,)).fetchall()]; conn.close(); return d

def dashboard_stats():
    conn=get_db(); c=conn.cursor(); out={
      'total_threats':c.execute('SELECT COUNT(*) FROM threats').fetchone()[0], 'critical':c.execute("SELECT COUNT(*) FROM threats WHERE severity='CRITICAL'").fetchone()[0], 'high':c.execute("SELECT COUNT(*) FROM threats WHERE severity='HIGH'").fetchone()[0], 'active_indicators':c.execute('SELECT COUNT(*) FROM indicators').fetchone()[0], 'open_investigations':c.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('NEW','INVESTIGATING')").fetchone()[0], 'avg_confidence':round(c.execute('SELECT AVG(confidence_score) FROM threats').fetchone()[0] or 0,1), 'vulnerabilities':c.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0],
      'severity':[{ 'label':r[0], 'value':r[1]} for r in c.execute('SELECT severity,COUNT(*) FROM threats GROUP BY severity').fetchall()], 'categories':[{ 'label':r[0], 'value':r[1]} for r in c.execute('SELECT category,COUNT(*) FROM threats GROUP BY category ORDER BY 2 DESC').fetchall()], 'indicator_types':[{ 'label':r[0], 'value':r[1]} for r in c.execute('SELECT indicator_type,COUNT(*) FROM threats GROUP BY indicator_type').fetchall()], 'status':[{ 'label':r[0], 'value':r[1]} for r in c.execute('SELECT status,COUNT(*) FROM threats GROUP BY status').fetchall()], 'risk_bins':[{ 'label':r[0], 'value':r[1]} for r in c.execute("SELECT CASE WHEN risk_score<=20 THEN '0-20' WHEN risk_score<=40 THEN '21-40' WHEN risk_score<=60 THEN '41-60' WHEN risk_score<=80 THEN '61-80' ELSE '81-100' END,COUNT(*) FROM threats GROUP BY 1 ORDER BY 1").fetchall()], 'confidence_bins':[{ 'label':r[0], 'value':r[1]} for r in c.execute("SELECT CASE WHEN confidence_score<=20 THEN '0-20' WHEN confidence_score<=40 THEN '21-40' WHEN confidence_score<=60 THEN '41-60' WHEN confidence_score<=80 THEN '61-80' ELSE '81-100' END,COUNT(*) FROM threats GROUP BY 1 ORDER BY 1").fetchall()], 'tactics':[{ 'label':r[0], 'value':r[1]} for r in c.execute("SELECT COALESCE(mitre_tactic,'Unmapped'),COUNT(*) FROM threats GROUP BY 1 ORDER BY 2 DESC").fetchall()]
    }; conn.close(); return out
