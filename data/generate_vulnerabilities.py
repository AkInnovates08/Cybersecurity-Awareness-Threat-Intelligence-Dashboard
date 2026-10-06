from pathlib import Path
import csv
OUT=Path(__file__).resolve().parent/'vulnerabilities.csv'
rows=[]
for i in range(1,101):
    score=[3.1,5.6,7.5,8.8,9.8][i%5]
    sev='CRITICAL' if score>=9 else 'HIGH' if score>=7 else 'MEDIUM' if score>=4 else 'LOW'
    rows.append([f'CVE-2026-{5000+i:04d}', ['Web Application','Identity Platform','Endpoint','Database','Cloud Service'][i%5],sev,score,'2026-09-%02d'%(i%28+1),'YES' if i%3 else 'NO','DEMO - no exploitation activity represented','Synthetic vulnerability awareness record'])
with OUT.open('w',newline='',encoding='utf-8') as f:
    w=csv.writer(f); w.writerow(['cve_id','product_category','severity','cvss_score','published_date','patch_available','exploitation_status_demo','description']); w.writerows(rows)
print(f'Generated {len(rows)} vulnerability records.')
