# Interview Preparation — 10 Questions & Answers

## 1. Explain your project.
I built a defensive Cybersecurity Awareness & Threat Intelligence Dashboard using Python, Flask and SQLite. It generates synthetic threat data, validates IOCs, enriches them from a local database, calculates risk and confidence, correlates related observations, generates alerts, provides conservative ATT&CK mapping, prioritizes vulnerabilities, and teaches users through awareness modules and a quiz. I intentionally designed it so indicators are never contacted or executed.

## 2. What is threat intelligence?
Threat intelligence is analyzed information about threats that supports defensive decisions. In my project, the intelligence is synthetic and structured into indicators, context, severity, confidence, source reliability and relationships.

## 3. What is an IOC?
An IOC is an Indicator of Compromise such as an IP, domain, URL or file hash that may be associated with suspicious activity. An IOC match is not automatically proof of compromise because context and freshness matter.

## 4. Risk vs confidence?
Risk represents how concerning an observation may be. Confidence represents how strong the evidence is. A risk score of 90 with confidence 25 needs validation; a risk score of 70 with confidence 95 is stronger intelligence for prioritization.

## 5. What is threat enrichment?
Enrichment adds context to an indicator, such as first/last seen, category, severity, risk, confidence, related indicators and ATT&CK context. My implementation uses only local synthetic records.

## 6. Why MITRE ATT&CK?
ATT&CK provides a structured knowledge base of adversary behaviors. I use it to describe behavior context, not to claim that a synthetic indicator proves a technique occurred. For example, phishing is T1566 under Initial Access.

## 7. How do you prioritize vulnerabilities?
I combine CVSS with asset criticality, exposure, known exploitation evidence and business context. A critical CVSS score on an isolated test asset may be less urgent than a high score on an exposed critical production asset.

## 8. How does correlation help a SOC?
Correlation reduces duplicate noise and groups observations that share meaningful context. It can turn repeated observations into one analyst-facing alert with an observation count, reducing alert fatigue.

## 9. Describe the SOC workflow.
Threat feed -> IOC detection -> validation -> enrichment -> risk/confidence -> alert -> SOC queue -> analyst triage -> correlation -> investigation -> escalate/monitor/resolve/false positive -> documentation.

## 10. How do you handle false positives?
I treat threat intelligence as evidence rather than unquestionable truth. Shared IPs, changing domains, stale indicators, cloud infrastructure and feed disagreement can produce false positives. Analysts should validate with authorized internal telemetry and context.
