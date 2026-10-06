# Only mappings supported by the synthetic context are included here.
ATTACK_MAP={
 'PHISHING': {'tactic':'Initial Access','technique':'Phishing','technique_id':'T1566'},
 'CREDENTIAL THREATS': {'tactic':'Credential Access','technique':'Valid Accounts','technique_id':'T1078'},
 'ACCOUNT SECURITY': {'tactic':'Credential Access','technique':'Valid Accounts','technique_id':'T1078'},
}
def map_threat(category, description=''):
    return ATTACK_MAP.get(category)
