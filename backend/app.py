from flask import Flask, jsonify, request, render_template, abort, session, redirect, url_for
from pathlib import Path
import json, os
from functools import wraps
from dotenv import load_dotenv
from .services.threat_service import init_db,fetch_threats,fetch_threat,dashboard_stats,get_db
from .services.ioc_validator import validate_indicator
from .services.enrichment_engine import enrich_indicator
from .services.alert_engine import generate_threat_alert

load_dotenv(); BASE=Path(__file__).resolve().parent; app=Flask(__name__,template_folder=str(BASE.parent/'frontend/templates'),static_folder=str(BASE.parent/'frontend/static')); app.config['SECRET_KEY']=os.getenv('SECRET_KEY','dev-only-change-me'); init_db()

def json_error(msg,code=400): return jsonify({'error':msg}),code


def analyst_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('analyst_authenticated'):
            if request.path.startswith('/api/'):
                return json_error('Analyst authentication required',401)
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper

@app.get('/login')
def login(): return render_template('login.html')

@app.post('/login')
def login_post():
    data=request.form
    username=os.getenv('ANALYST_USERNAME','analyst')
    password=os.getenv('ANALYST_PASSWORD','change-me')
    if data.get('username')==username and data.get('password')==password:
        session['analyst_authenticated']=True; session['role']='analyst'; return redirect(url_for('threats_page'))
    return render_template('login.html',error='Invalid analyst credentials.'),401

@app.post('/logout')
def logout():
    session.clear(); return redirect(url_for('home'))
@app.get('/')
def home(): return render_template('index.html')
@app.get('/threats')
def threats_page(): return render_template('threats.html')
@app.get('/threats/<tid>')
def threat_page(tid): return render_template('threat_detail.html',threat_id=tid)
@app.get('/awareness')
def awareness_page(): return render_template('awareness.html')
@app.get('/quiz')
def quiz_page(): return render_template('quiz.html')
@app.get('/vulnerabilities')
def vulnerabilities_page(): return render_template('vulnerabilities.html')
@app.get('/alerts')
def alerts_page(): return render_template('alerts.html')
@app.get('/executive')
def executive_page(): return render_template('executive.html')

@app.get('/api/health')
def health(): return jsonify({'status':'ok','service':'cybersecurity-awareness-threat-intelligence-dashboard','data_mode':'SYNTHETIC/DEMO ONLY'})
@app.get('/api/threats')
def api_threats(): return jsonify(fetch_threats(request.args))
@app.get('/api/threats/<tid>')
def api_threat(tid):
    d=fetch_threat(tid)
    return jsonify(d) if d else json_error('Threat not found',404)
@app.post('/api/threats')
def create_threat():
    data=request.get_json(silent=True) or {}
    required=['threat_id','threat_name','category','indicator_type','indicator_value','severity','risk_score','confidence_score','status']
    missing=[x for x in required if x not in data]
    if missing:return json_error('Missing fields: '+', '.join(missing))
    return json_error('Creation endpoint is demonstration-only; use the validated database ingestion workflow.',501)
@app.put('/api/threats/<tid>')
@analyst_required
def update_threat(tid):
    data=request.get_json(silent=True) or {}; allowed={'status','risk_score','confidence_score','severity'}; updates={k:data[k] for k in allowed if k in data}
    if not updates:return json_error('No supported fields supplied')
    conn=get_db();
    if not conn.execute('SELECT 1 FROM threats WHERE threat_id=?',(tid,)).fetchone(): conn.close(); return json_error('Threat not found',404)
    sets=', '.join(k+'=?' for k in updates); conn.execute(f'UPDATE threats SET {sets} WHERE threat_id=?',(*updates.values(),tid)); conn.commit(); conn.close(); return jsonify(fetch_threat(tid))
@app.get('/api/indicators/search')
def indicator_search():
    q=(request.args.get('q') or '').strip();
    if not q:return json_error('q is required')
    validation=validate_indicator(q); enrichment=enrich_indicator(q,[dict(x) for x in get_db().execute('SELECT * FROM threats').fetchall()]);
    return jsonify({'validation':validation,'enrichment':enrichment})
@app.get('/api/dashboard/stats')
def stats(): return jsonify(dashboard_stats())
@app.get('/api/dashboard/trends')
def trends():
    conn=get_db(); rows=[dict(x) for x in conn.execute("SELECT substr(first_seen,1,7) month, COUNT(*) count FROM threats GROUP BY month ORDER BY month").fetchall()]; conn.close(); return jsonify(rows)
@app.get('/api/alerts')
def alerts():
    conn=get_db(); rows=[dict(x) for x in conn.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 200').fetchall()]; conn.close(); return jsonify(rows)
@app.put('/api/alerts/<aid>/status')
@analyst_required
def alert_status(aid):
    data=request.get_json(silent=True) or {}; status=data.get('status'); allowed={'NEW','INVESTIGATING','MONITORING','RESOLVED','FALSE_POSITIVE'}
    if status not in allowed:return json_error('Invalid alert status')
    conn=get_db(); conn.execute('UPDATE alerts SET status=? WHERE alert_id=?',(status,aid)); conn.commit(); row=conn.execute('SELECT * FROM alerts WHERE alert_id=?',(aid,)).fetchone(); conn.close(); return jsonify(dict(row) if row else {})
@app.post('/api/threats/<tid>/notes')
@analyst_required
def note(tid):
    data=request.get_json(silent=True) or {}; text=data.get('note','').strip()
    if not text or len(text)>2000:return json_error('Note must contain 1-2000 characters')
    conn=get_db();
    if not conn.execute('SELECT 1 FROM threats WHERE threat_id=?',(tid,)).fetchone(): conn.close(); return json_error('Threat not found',404)
    conn.execute("INSERT INTO analyst_notes(threat_id,note,created_at) VALUES(?,?,datetime('now'))",(tid,text)); conn.commit(); conn.close(); return jsonify({'status':'saved'})
@app.get('/api/vulnerabilities')
def vulnerabilities():
    conn=get_db(); rows=[dict(x) for x in conn.execute('SELECT * FROM vulnerabilities ORDER BY priority_score DESC').fetchall()]; conn.close(); return jsonify(rows)
@app.get('/api/awareness/modules')
def modules(): return jsonify(json.loads((BASE.parent/'awareness/modules.json').read_text()))
@app.get('/api/quiz')
def quiz(): return jsonify(json.loads((BASE.parent/'awareness/quiz_questions.json').read_text()))
@app.post('/api/quiz/submit')
def quiz_submit():
    data=request.get_json(silent=True) or {}; answers=data.get('answers',{}); questions=json.loads((BASE.parent/'awareness/quiz_questions.json').read_text()); correct=sum(1 for q in questions if str(q['id']) in answers and int(answers[str(q['id'])])==q['correct_index']); score=round(correct/len(questions)*100); conn=get_db(); conn.execute("INSERT INTO quiz_results(anonymous_user_id,overall_score,created_at) VALUES(?,?,datetime('now'))",(data.get('anonymous_user_id'),score)); conn.commit(); conn.close(); return jsonify({'score':score,'correct':correct,'total':len(questions),'message':'Educational awareness score only; not an employee fitness or competency judgment.'})
@app.get('/api/executive')
def executive():
    s=dashboard_stats(); return jsonify({'threat_landscape':s,'priorities':['Review critical/high synthetic threats','Prioritize internet-facing critical assets when using real data','Strengthen phishing and MFA awareness','Review alert correlation to reduce fatigue']})

if __name__=='__main__': app.run(host='127.0.0.1',port=5000,debug=True)
