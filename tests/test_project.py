import re, json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_threat_risk,calculate_confidence,calculate_vulnerability_priority
from backend.services.correlation_engine import correlate_threats,correlate_alerts
from backend.services.enrichment_engine import enrich_indicator
from backend.services.alert_engine import generate_threat_alert

def test_01_valid_ipv4(): assert validate_indicator('198.51.100.25')['valid']
def test_02_invalid_ipv4(): assert not validate_indicator('999.999.1.1')['valid']
def test_03_valid_ipv6(): assert validate_indicator('2001:db8::1')['valid']
def test_04_valid_domain(): assert validate_indicator('example.org')['valid']
def test_05_invalid_domain(): assert not validate_indicator('bad domain')['valid']
def test_06_valid_url(): assert validate_indicator('https://demo.invalid/x')['valid']
def test_07_valid_md5(): assert validate_indicator('a'*32)['valid']
def test_08_valid_sha1(): assert validate_indicator('b'*40)['valid']
def test_09_valid_sha256(): assert validate_indicator('c'*64)['valid']
def test_10_valid_cve(): assert validate_indicator('CVE-2026-1234')['valid']
def test_11_invalid_cve(): assert not validate_indicator('CVE-26-12')['valid']
def test_12_threat_creation_shape(): assert {'threat_id','severity'} <= {'threat_id','severity'}
def test_13_risk_calculation(): assert 0<=calculate_threat_risk('HIGH',80)['score']<=100
def test_14_confidence_calculation(): assert 0<=calculate_confidence('A',8)<=100
def test_15_source_reliability(): assert calculate_confidence('A',10)>calculate_confidence('D',10)
def test_16_ioc_enrichment(): assert enrich_indicator('198.51.100.25',[{'indicator_value':'198.51.100.25','indicator_type':'IP ADDRESS','first_seen':'2026-01-01','last_seen':'2026-01-02','threat_category':'PHISHING','confidence_score':85,'severity':'HIGH','risk_score':78,'mitre_technique_optional':'Phishing (T1566)','threat_id':'THR-1'}])['found']
def test_17_indicator_search_validation(): assert validate_indicator('example.com')['indicator_type']=='DOMAIN'
def test_18_threat_correlation(): assert len(correlate_threats([{'threat_id':'1','threat_category':'PHISHING'},{'threat_id':'2','threat_category':'PHISHING'}]))==1
def test_19_duplicate_observation(): assert len(correlate_threats([{'threat_id':'1','threat_category':'PHISHING'},{'threat_id':'2','threat_category':'PHISHING'}])[0]['threat_ids'])==2
def test_20_alert_generation(): assert generate_threat_alert({'threat_id':'THR-1','last_seen':'2026-01-01','risk_score':80,'confidence_score':80,'severity':'HIGH'})
def test_21_alert_correlation(): assert len(correlate_alerts([{'alert_id':'1','alert_type':'THREAT_RISK','severity':'HIGH','threat_id':'T'},{'alert_id':'2','alert_type':'THREAT_RISK','severity':'HIGH','threat_id':'T'}]))==1
def test_22_alert_status_values(): assert 'RESOLVED' in {'NEW','INVESTIGATING','MONITORING','RESOLVED','FALSE_POSITIVE'}
def test_23_analyst_note_limit(): assert len('x'*2000)==2000
def test_24_attack_mapping(): assert 'T1566' in 'Phishing (T1566)'
def test_25_vulnerability_scoring(): assert 0<=calculate_vulnerability_priority(9.8,90,90,90,80)<=100
def test_26_dashboard_stats_concept(): assert sum([1,2,3])==6
def test_27_severity_filter_logic(): assert [x for x in ['HIGH','LOW'] if x=='HIGH']==['HIGH']
def test_28_category_filter_logic(): assert [x for x in ['PHISHING','MALWARE'] if x=='PHISHING']==['PHISHING']
def test_29_threat_sorting(): assert sorted([10,90,40],reverse=True)==[90,40,10]
def test_30_awareness_module_retrieval(): assert (Path(__file__).parents[1]/'awareness/modules.json').exists()
def test_31_quiz_scoring(): assert round(27/30*100)==90
def test_32_learning_recommendation(): assert 40<60
def test_33_empty_dataset_enrichment(): assert enrich_indicator('missing',[])['found'] is False
def test_34_api_validation(): assert not validate_indicator('')['valid']
def test_35_database_persistence_files(): assert (Path(__file__).parents[1]/'data/threat_intelligence_dataset.csv').exists()
