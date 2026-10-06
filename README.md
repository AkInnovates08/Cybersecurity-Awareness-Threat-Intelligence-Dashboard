# Cybersecurity Awareness & Threat Intelligence Dashboard

A defensive cybersecurity platform that combines Cyber Threat Intelligence (CTI), IOC analysis, threat risk scoring, confidence scoring, threat correlation, MITRE ATT&CK mapping, vulnerability awareness, SOC-style investigation workflows, security alerts, and cybersecurity awareness training.

The project is designed as a student-friendly but industry-oriented cybersecurity portfolio project using synthetic and sanitized defensive-security data.

---

## Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Project Objectives](#project-objectives)
- [Key Features](#key-features)
- [Cybersecurity Concepts Covered](#cybersecurity-concepts-covered)
- [Threat Categories](#threat-categories)
- [Indicator Types](#indicator-types)
- [Threat Intelligence Workflow](#threat-intelligence-workflow)
- [Risk and Confidence Scoring](#risk-and-confidence-scoring)
- [Threat Intelligence Lifecycle](#threat-intelligence-lifecycle)
- [MITRE ATT&CK Integration](#mitre-attck-integration)
- [Vulnerability Awareness](#vulnerability-awareness)
- [SOC Investigation Workflow](#soc-investigation-workflow)
- [Security Awareness Center](#security-awareness-center)
- [System Architecture](#system-architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Dataset](#dataset)
- [REST API](#rest-api)
- [Dashboard](#dashboard)
- [Security and Privacy](#security-and-privacy)
- [Testing](#testing)
- [Installation](#installation)
- [Running the Project](#running-the-project)
- [Demo Scenario](#demo-scenario)
- [GitHub Setup](#github-setup)
- [Recommended Git Commits](#recommended-git-commits)
- [Project Report](#project-report)
- [Learning Outcomes](#learning-outcomes)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [Ethical Disclaimer](#ethical-disclaimer)
- [Author](#author)

---

## Overview

The **Cybersecurity Awareness & Threat Intelligence Dashboard** is a defensive cybersecurity application designed to help users understand, analyze, classify, and monitor cybersecurity threat information.

The system combines two major areas of cybersecurity:

### Cyber Threat Intelligence

The platform processes synthetic threat intelligence and indicators such as:

- IP addresses
- Domains
- URLs
- File hashes
- Email/sender domains
- CVE identifiers

It validates indicators, enriches them with local intelligence, calculates risk and confidence scores, correlates related observations, generates alerts, and presents the information through a SOC-style dashboard.

### Cybersecurity Awareness

The platform also provides educational modules covering:

- Phishing
- Password security
- Multi-factor authentication
- Social engineering
- Safe browsing
- Secure Wi-Fi
- Software updates
- Ransomware awareness
- Removable media safety
- Data privacy
- Mobile security
- Remote work security
- Cloud account security
- Incident reporting
- AI-enabled scam awareness

A security-awareness quiz evaluates the user's understanding and provides personalized learning recommendations.

---

## Problem Statement

Cybersecurity teams receive large amounts of security information from different sources.

Simply collecting indicators is not enough.

Security analysts need to determine:

- What was observed?
- What type of indicator is it?
- How reliable is the information?
- How risky is the observation?
- How confident are we in the intelligence?
- Is it related to another observation?
- Does it justify an alert?
- Is there enough evidence for an ATT&CK mapping?
- Does the organization need additional defensive action?

At the same time, users need cybersecurity awareness training to recognize common threats such as phishing, credential theft, social engineering, ransomware, and fraudulent messages.

This project combines technical threat intelligence analysis with human-focused cybersecurity awareness.

---

## Project Objectives

The primary objectives are:

1. Build a defensive Cyber Threat Intelligence dashboard.
2. Generate and analyze safe synthetic threat intelligence data.
3. Validate different types of Indicators of Compromise.
4. Enrich indicators using local intelligence.
5. Calculate threat risk scores.
6. Calculate intelligence confidence scores.
7. Track source reliability.
8. Correlate related threat observations.
9. Generate and correlate security alerts.
10. Provide MITRE ATT&CK contextual mapping where justified.
11. Provide vulnerability awareness and prioritization.
12. Provide SOC-style investigation workflows.
13. Provide an interactive IOC search system.
14. Build a cybersecurity awareness learning center.
15. Provide a security-awareness quiz.
16. Calculate awareness scores.
17. Generate personalized learning recommendations.
18. Provide an executive-level cybersecurity summary.
19. Demonstrate defensive cybersecurity engineering skills.
20. Create a GitHub-ready portfolio project.

---

# Key Features

## Threat Intelligence

- Synthetic threat intelligence dataset
- Threat classification
- Threat severity analysis
- Threat risk scoring
- Confidence scoring
- Source reliability
- Threat enrichment
- Threat correlation
- Threat timeline
- Threat search
- Threat filtering
- Threat sorting

## IOC Analysis

Supported indicators include:

- IPv4
- IPv6
- Domain
- URL
- MD5
- SHA-1
- SHA-256
- Email/sender domain
- CVE ID

The system performs syntactic validation without automatically interacting with external indicators.

---

## Security Alerts

The alert engine can generate alerts based on:

- Risk threshold
- Confidence threshold
- Repeated observations
- High-priority vulnerabilities
- Correlated indicators

Alert statuses include:

- NEW
- INVESTIGATING
- MONITORING
- RESOLVED
- FALSE_POSITIVE

Alert correlation helps reduce unnecessary duplicate alerts.

---

## Vulnerability Awareness

The project provides a vulnerability-awareness module containing:

- CVE identifiers
- Product categories
- Severity
- CVSS score
- Published date
- Patch availability
- Demonstration exploitation status
- Description
- Priority score

The project emphasizes that CVSS alone should not determine remediation priority.

A better prioritization model considers:

```text
CVSS
+
Asset Criticality
+
Exposure
+
Known Exploitation Evidence
+
Business Context
=
Contextual Vulnerability Priority
```

---

## Security Awareness

The Awareness Center contains educational modules covering common cybersecurity risks.

Each module provides:

- What is it?
- Why does it matter?
- Warning signs
- Safe practices
- What to do if something happens

---

# Cybersecurity Concepts Covered

The project demonstrates practical understanding of:

- Cybersecurity Awareness
- Cyber Threat Intelligence
- Indicators of Compromise
- Indicators of Attack
- Threat Feeds
- Threat Enrichment
- Threat Correlation
- Threat Hunting Concepts
- Threat Actors
- Tactics, Techniques and Procedures
- MITRE ATT&CK
- Vulnerability Management
- CVE
- CVSS
- Security Alerts
- SOC Operations
- Incident Response
- Security Analytics
- Risk Assessment
- Confidence Assessment
- False Positives

---

# Threat Categories

The project uses the following threat categories:

| Category | Description |
|---|---|
| Phishing | Deceptive communication designed to trick users |
| Malware | Malicious software-related threat awareness |
| Ransomware | Threats involving disruption, encryption, or extortion |
| Credential Theft | Risks involving stolen authentication information |
| Social Engineering | Manipulation of users to obtain information or access |
| Network Threats | Suspicious network-related activity |
| Web Threats | Web-based security risks |
| Data Exposure | Risks involving exposed or improperly protected data |
| Account Takeover Risk | Risks involving unauthorized account access |
| Vulnerability Exploitation Awareness | Defensive awareness of vulnerability-related risk |

No exploitation instructions or malicious payloads are included.

---

# Indicator Types

The platform supports:

```text
IP ADDRESS
DOMAIN
URL
FILE HASH
EMAIL / SENDER DOMAIN
CVE ID
```

Hash formats supported by the validator include:

```text
MD5
SHA-1
SHA-256
```

---

# Observation, Indicator, Alert, Threat and Incident

The system intentionally distinguishes between different cybersecurity concepts.

### Observation

Something was recorded or detected.

### Indicator

An artifact that may provide useful security context.

Examples:

```text
IP address
Domain
URL
File hash
Email sender
```

### Alert

A security notification generated when predefined conditions are met.

### Threat

A potentially harmful cybersecurity condition supported by available evidence.

### Incident

A confirmed or sufficiently established security event requiring incident response.

An important principle of this project is:

```text
IOC MATCH != CONFIRMED COMPROMISE
```

A suspicious indicator should not automatically be treated as proof of an attack.

---

# Threat Intelligence Workflow

The project follows this defensive workflow:

```text
Synthetic / Defensive Threat Data
              |
              v
       Data Collection
              |
              v
        Normalization
              |
              v
       IOC Validation
              |
              v
      IOC Extraction
              |
              v
    Threat Classification
              |
              v
     Risk + Confidence
              |
              v
    MITRE ATT&CK Mapping
              |
              v
       Threat Database
              |
              v
        Correlation
              |
              v
        Alert Engine
              |
              v
        SOC Dashboard
              |
              v
   Security Awareness Center
              |
              v
        Analyst / User
```

---

# Threat Intelligence Types

## Strategic Threat Intelligence

High-level intelligence used for business and management decisions.

Example:

```text
An organization is facing increased credential-related threats.
```

## Tactical Threat Intelligence

Information about adversary behaviors, techniques, and defensive considerations.

Example:

```text
Increased phishing activity targeting employee credentials.
```

## Operational Threat Intelligence

Information related to ongoing campaigns, incidents, or operational security activity.

Example:

```text
Multiple related synthetic indicators observed within the same campaign.
```

## Technical Threat Intelligence

Technical indicators and artifacts used for defensive analysis.

Examples:

```text
IP addresses
Domains
URLs
Hashes
CVE identifiers
```

This project focuses primarily on:

```text
Technical Intelligence
+
Tactical Intelligence
+
Security Awareness
```

---

# IOC Lifecycle

The project follows an IOC lifecycle:

```text
Observed
   |
   v
Validated
   |
   v
Enriched
   |
   v
Scored
   |
   v
Investigated
   |
   v
Monitored
   |
   v
Expired / Closed
```

An indicator can become stale or lose relevance over time.

---

# Risk and Confidence Scoring

The project separates **risk** from **confidence**.

## Risk Score

Risk represents how concerning the available evidence may be.

The conceptual weighting is:

| Factor | Weight |
|---|---:|
| Severity | 30% |
| Confidence | 25% |
| Recency | 15% |
| Observation Frequency | 10% |
| Source Reliability | 10% |
| Context / Correlation | 10% |

The resulting score is normalized to:

```text
0 - 100
```

### Risk Classification

| Score | Classification |
|---:|---|
| 0-20 | INFORMATIONAL |
| 21-40 | LOW |
| 41-60 | MEDIUM |
| 61-80 | HIGH |
| 81-100 | CRITICAL |

---

## Confidence Score

Confidence represents how trustworthy or well-supported the available intelligence is.

Example:

```text
Risk:       90
Confidence: 25
```

Interpretation:

```text
Potentially serious, but evidence quality is weak.
```

Another example:

```text
Risk:       70
Confidence: 95
```

Interpretation:

```text
High-confidence intelligence with meaningful risk.
```

Therefore:

```text
Risk != Confidence
```

A high-risk indicator is not automatically confirmed.

---

# Source Reliability

Synthetic intelligence sources include:

- Internal SOC
- Security Vendor
- Public Threat Feed
- Research Report
- Community Submission
- Unknown Source

Reliability levels:

| Level | Meaning |
|---|---|
| A | Highly Reliable |
| B | Usually Reliable |
| C | Fairly Reliable |
| D | Reliability Unknown |

Source reliability and confidence are related, but they are not the same concept.

---

# IOC Validation

The project provides a `validate_indicator()` function.

It validates the syntax of:

```text
IPv4
IPv6
Domain
URL
MD5
SHA-1
SHA-256
CVE
```

Example output:

```json
{
  "valid": true,
  "indicator_type": "IP",
  "normalized_value": "198.51.100.25",
  "validation_notes": "Valid IPv4 address"
}
```

Important:

```text
Validation means:
"Is this syntactically valid?"

It does NOT mean:
"Is this malicious?"
```

---

# Threat Enrichment

The `enrich_indicator()` service enriches indicators using local synthetic intelligence.

Enrichment can include:

- Indicator type
- First seen
- Last seen
- Associated categories
- Confidence
- Severity
- Risk score
- Related alerts
- Related indicators
- ATT&CK mapping
- Analyst notes

The application does not require an external API to operate.

---

# Threat Correlation

The `correlate_threats()` engine groups related observations.

Records can be correlated using:

- Campaign ID
- Observation window
- Threat category
- Analyst correlation
- Related indicators

Example:

```text
Domain
   |
   +---- Related IP
   |
   +---- Related File Hash
   |
   +---- Related Alert
```

The resulting group can be displayed as:

```text
RELATED THREAT CLUSTER
```

Correlation provides evidence of a relationship.

It does not automatically prove attribution.

---

# Threat Timeline

Each threat can be represented using a timeline:

```text
First Seen
    |
    v
New Observations
    |
    v
Risk Increase / Decrease
    |
    v
Investigation
    |
    v
Monitoring
    |
    v
Closed
```

---

# MITRE ATT&CK Integration

MITRE ATT&CK is used to provide contextual information about adversary behavior.

The project distinguishes:

### Tactic

Why an adversary performs an action.

### Technique

How an objective may be achieved.

### Sub-technique

A more specific implementation of a technique.

The dashboard can display:

- Top ATT&CK tactics
- Top techniques
- Threats by tactic
- Technique frequency
- Associated synthetic records

Mappings are only used where the synthetic threat context provides sufficient justification.

The system does not treat an IOC as automatic proof that an ATT&CK technique occurred.

---

# Vulnerability Awareness

The vulnerability module explains:

- CVE
- CVSS
- Vulnerabilities
- Patching
- Exploitation concepts
- Zero-day concepts

The project uses synthetic vulnerability data for the local demonstration.

Vulnerability prioritization considers:

```text
CVSS
Asset Criticality
Exposure
Known Exploitation Evidence
Business Context
```

This provides a more realistic defensive prioritization approach than relying only on CVSS.

---

# Alert Engine

The alert engine can generate alerts based on:

```text
Risk Threshold
Confidence Threshold
Repeated Observations
High-Priority Vulnerability
Correlated Indicators
```

Each alert contains:

```text
alert_id
threat_id
timestamp
alert_type
severity
risk_score
confidence_score
description
status
```

---

# Alert Correlation

Alert correlation helps reduce alert fatigue.

Example:

```text
Same indicator observed 100 times
within a short observation window
```

Instead of generating:

```text
100 separate alerts
```

The system can create:

```text
1 correlated alert

Observation Count = 100
```

This demonstrates the concept of reducing duplicate analyst workload.

---

# SOC Investigation Workflow

The project models a simplified Tier 1 SOC workflow:

```text
Threat Feed
    |
    v
IOC Detected
    |
    v
Validation
    |
    v
Enrichment
    |
    v
Risk + Confidence
    |
    v
Alert
    |
    v
SOC Queue
    |
    v
Analyst Triage
    |
    v
Correlation
    |
    v
Investigation
    |
    +----> Escalate
    |
    +----> Monitor
    |
    +----> Resolve
    |
    +----> False Positive
    |
    v
Documentation
```

---

# Security Awareness Center

The Awareness Center contains 15 learning modules:

1. Phishing Awareness
2. Password Security
3. MFA
4. Social Engineering
5. Safe Browsing
6. Secure Wi-Fi
7. Software Updates
8. Ransomware Awareness
9. USB / Removable Media Safety
10. Data Privacy
11. Mobile Security
12. Remote Work Security
13. Cloud Account Security
14. Incident Reporting
15. AI-Enabled Scam Awareness

---

# Phishing Awareness

The phishing module teaches users to recognize warning signs such as:

- Suspicious sender
- Urgency
- Credential requests
- Unexpected attachments
- Suspicious links
- Payment requests
- Impersonation
- Unexpected QR codes

The project uses safe educational examples.

It does not create real phishing pages, credential harvesting systems, or phishing kits.

---

# Password and MFA Awareness

The project teaches:

- Unique passwords
- Long passwords/passphrases
- Password managers
- Password reuse risks
- MFA
- Phishing-resistant authentication concepts
- Passkeys / WebAuthn awareness

The basic security principle is:

```text
Strong Password
+
MFA
=
Stronger Account Protection
```

---

# Ransomware Awareness

The ransomware module focuses on defensive awareness.

Potential impacts include:

- File encryption
- Service disruption
- Data theft/extortion risk
- Operational downtime

Defensive practices include:

- Backups
- Patching
- Least privilege
- Email security
- Endpoint protection
- Network segmentation
- MFA
- Monitoring
- Incident response preparation

No ransomware code or destructive functionality is included.

---

# Security Awareness Quiz

The project contains 30 cybersecurity-awareness questions covering:

- Phishing
- Passwords
- MFA
- Social Engineering
- Safe Browsing
- Ransomware
- Privacy
- Wi-Fi
- Mobile Security
- Incident Reporting

The quiz calculates a score from:

```text
0 - 100
```

### Awareness Classification

| Score | Result |
|---:|---|
| 0-40 | Needs Improvement |
| 41-60 | Basic Awareness |
| 61-80 | Good Awareness |
| 81-100 | Strong Awareness |

The awareness score is educational.

It is not an employee fitness, employment, or competency judgment.

---

# Personalized Learning Recommendations

The project provides personalized recommendations based on quiz performance.

Example:

```text
Phishing: 40%

Recommendation:
Complete Phishing Awareness Module.
```

Another example:

```text
Password Security: 90%

Recommendation:
No immediate module required.
```

The recommendation engine is implemented through:

```text
generate_learning_recommendations()
```

---

# Executive Cybersecurity Summary

The executive view provides a simplified management-level overview.

It includes:

- Threat landscape summary
- Critical/high threat count
- Top threat categories
- Vulnerability categories
- Awareness score trend
- Top awareness weaknesses
- Defensive priorities

The executive view intentionally avoids unnecessary technical detail.

---

# System Architecture

```text
                Synthetic / Public
                Defensive Data
                       |
                       v
               Data Ingestion Layer
                       |
                       v
                  Normalization
                       |
                       v
              IOC Validation
                       |
                       v
               Threat Enrichment
                       |
                       v
             Risk + Confidence Engine
                       |
                       v
               Correlation Engine
                       |
          +------------+-------------+
          |            |             |
          v            v             v
      Threat DB    Alert Engine   ATT&CK
          |            |          Mapping
          +------------+-------------+
                       |
                       v
                 SOC Dashboard
                       |
                       v
                    Analyst


          Security Awareness Layer
                       |
                       v
                Learning Modules
                       |
                       v
                  Quiz Engine
                       |
                       v
                Awareness Score
                       |
                       v
             Recommendations
```

---

# Technology Stack

## Backend

- Python
- Flask
- SQLite
- Pandas

## Frontend

- HTML5
- CSS3
- JavaScript

## Data

- CSV
- JSON
- SQLite

## Security Analytics

- IOC validation
- Threat scoring
- Confidence scoring
- Correlation
- Alert generation
- Vulnerability prioritization

## Testing

- pytest

---

# Project Structure

```text
Cybersecurity-Awareness-Threat-Intelligence-Dashboard/
│
├── backend/
│   ├── app.py
│   ├── db.py
│   │
│   ├── routes/
│   │   ├── threats.py
│   │   ├── indicators.py
│   │   ├── alerts.py
│   │   ├── vulnerabilities.py
│   │   ├── awareness.py
│   │   └── dashboard.py
│   │
│   ├── models/
│   │   ├── threat.py
│   │   ├── indicator.py
│   │   ├── alert.py
│   │   └── vulnerability.py
│   │
│   ├── services/
│   │   ├── threat_service.py
│   │   ├── ioc_validator.py
│   │   ├── enrichment_engine.py
│   │   ├── risk_engine.py
│   │   ├── correlation_engine.py
│   │   ├── alert_engine.py
│   │   └── attack_mapper.py
│   │
│   └── utils/
│       ├── auth.py
│       └── seed_alerts.py
│
├── frontend/
│   ├── index.html
│   ├── threat-dashboard.html
│   ├── threat-details.html
│   ├── awareness.html
│   ├── quiz.html
│   ├── vulnerabilities.html
│   ├── alerts.html
│   ├── executive.html
│   ├── login.html
│   │
│   ├── css/
│   │   └── style.css
│   │
│   └── js/
│       ├── dashboard.js
│       ├── threats.js
│       ├── awareness.js
│       └── quiz.js
│
├── awareness/
│   ├── modules.json
│   └── quiz_questions.json
│
├── data/
│   ├── generate_threat_data.py
│   ├── generate_vulnerabilities.py
│   ├── threat_intelligence_dataset.csv
│   └── vulnerabilities.csv
│
├── database/
│   └── cybersecurity.db
│
├── tests/
│   ├── test_ioc_validator.py
│   ├── test_risk_engine.py
│   ├── test_confidence.py
│   ├── test_enrichment.py
│   ├── test_correlation.py
│   ├── test_alerts.py
│   ├── test_vulnerabilities.py
│   ├── test_awareness.py
│   └── ...
│
├── docs/
│   ├── architecture.md
│   ├── github_strategy.md
│   ├── interview_questions.md
│   ├── project_report.md
│   └── screenshot_checklist.md
│
├── reports/
│
├── screenshots/
│
├── README.md
├── requirements.txt
├── .env.example
└── .gitignore
```

---

# Dataset

The project includes a synthetic threat intelligence dataset containing more than 2,000 records.

The generated dataset contains fields such as:

```text
threat_id
timestamp
threat_name
threat_category
indicator_type
indicator_value
source_name
confidence_score
severity
risk_score
status
first_seen
last_seen
country_or_region
description
mitre_tactic
mitre_technique
cve_id
```

The project uses safe reserved/example infrastructure.

### Example IP ranges

```text
192.0.2.0/24
198.51.100.0/24
203.0.113.0/24
```

### Example domains

```text
example.com
example.org
example.net
*.invalid
```

### Synthetic URLs

URLs are fictional and intended only for local demonstration.

### Synthetic hashes

File hashes are randomly generated SHA-256-style demonstration values.

All generated intelligence should be treated as:

```text
SYNTHETIC / DEMO ONLY
```

---

# REST API

The backend exposes REST endpoints for the main application functionality.

## Threats

```http
GET /api/threats
```

Retrieve threat records.

```http
GET /api/threats/{id}
```

Retrieve a specific threat.

```http
POST /api/threats
```

Create a threat record.

```http
PUT /api/threats/{id}
```

Update a threat.

---

## IOC Search

```http
GET /api/indicators/search
```

Search the local synthetic database for an indicator.

Example:

```text
198.51.100.25
```

The application performs a database lookup only.

It does not connect to the IP address.

---

## Dashboard

```http
GET /api/dashboard/stats
```

Retrieve dashboard statistics.

```http
GET /api/dashboard/trends
```

Retrieve threat trend data.

---

## Alerts

```http
GET /api/alerts
```

Retrieve alerts.

```http
PUT /api/alerts/{id}/status
```

Update alert status.

---

## Analyst Notes

```http
POST /api/threats/{id}/notes
```

Add analyst notes to a threat investigation.

---

## Vulnerabilities

```http
GET /api/vulnerabilities
```

Retrieve vulnerability records.

---

## Awareness

```http
GET /api/awareness/modules
```

Retrieve awareness modules.

```http
GET /api/quiz
```

Retrieve quiz questions.

```http
POST /api/quiz/submit
```

Submit quiz results.

---

# Dashboard

The main dashboard provides SOC-style metrics such as:

- Total Threat Records
- Critical Threats
- High Threats
- Active Indicators
- Open Investigations
- Average Confidence
- Vulnerabilities Tracked

Charts include:

1. Threats Over Time
2. Threats by Severity
3. Threats by Category
4. IOC Type Distribution
5. Top ATT&CK Tactics
6. Risk Score Distribution
7. Confidence Distribution
8. Vulnerabilities by Severity
9. Top Threat Categories
10. Threat Status Distribution

---

# Threat Investigation View

Selecting a threat provides:

- Threat ID
- Threat name
- Category
- Description
- Indicator type
- Indicator value
- Severity
- Risk score
- Confidence score
- Source
- Source reliability
- First seen
- Last seen
- Related indicators
- Related alerts
- ATT&CK mapping
- CVE association
- Analyst notes
- Status
- Recommended defensive actions

---

# Security and Privacy

The project follows a defensive-only approach.

The application does not:

- Execute malware
- Execute files based on hashes
- Visit suspicious URLs
- Contact suspicious IP addresses
- Scan external systems
- Exploit vulnerabilities
- Create phishing pages
- Harvest credentials
- Deploy malicious payloads

Indicators are treated as data.

---

## Security Controls

The project demonstrates:

- Input validation
- Threat-description sanitization
- XSS awareness
- Environment variables
- Authentication for analyst functionality
- Role-based access concepts
- Analyst-note protection
- API validation
- Rate-limiting considerations
- HTTPS considerations
- Administrative audit concepts
- Minimal personal-data collection

Threat intelligence can itself be sensitive and therefore should be protected using appropriate access controls.

---

# False Positives and Intelligence Limitations

Threat intelligence is not perfect.

An IP address may be shared by many users.

A domain may change ownership.

Cloud infrastructure may host both legitimate and malicious services.

Indicators can become stale.

Different intelligence sources may disagree.

Confidence levels can vary.

Correlation does not prove attribution.

Therefore:

```text
Threat Intelligence
        +
Context
        +
Analyst Validation
        =
Better Defensive Decisions
```

The dashboard is designed to support analysts rather than replace analyst judgment.

---

# Testing

The project contains automated tests covering:

- IPv4 validation
- Invalid IPv4
- IPv6 validation
- Domain validation
- Invalid domain
- URL validation
- MD5 validation
- SHA-1 validation
- SHA-256 validation
- CVE validation
- Invalid CVE
- Threat creation
- Risk calculation
- Confidence calculation
- Source reliability
- IOC enrichment
- Indicator search
- Threat correlation
- Duplicate observations
- Alert generation
- Alert correlation
- Alert status update
- Analyst notes
- ATT&CK mapping
- Vulnerability scoring
- Dashboard statistics
- Severity filtering
- Category filtering
- Threat sorting
- Awareness module retrieval
- Quiz scoring
- Learning recommendations
- Empty dataset handling
- API validation
- Database persistence

Run tests with:

```bash
pytest -q
```

Expected result:

```text
38 passed
```

---

# Installation

## 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/Cybersecurity-Awareness-Threat-Intelligence-Dashboard.git
```

```bash
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard
```

---

## 2. Create a Virtual Environment

### Windows

```powershell
py -m venv .venv
```

Activate:

```powershell
.\.venv\Scripts\Activate.ps1
```

### Linux/macOS

```bash
python3 -m venv .venv
```

Activate:

```bash
source .venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Configure Environment Variables

Copy:

```text
.env.example
```

to:

```text
.env
```

Example:

```env
APP_NAME=Cybersecurity Awareness & Threat Intelligence Dashboard
SECRET_KEY=change-this-development-secret
DATABASE_URL=sqlite:///database/cybersecurity.db
DEBUG=True
```

Never commit real secrets to GitHub.

---

# Generate Synthetic Threat Data

Run:

```bash
python data/generate_threat_data.py
```

This generates:

```text
data/threat_intelligence_dataset.csv
```

with more than 2,000 synthetic records.

---

# Generate Vulnerability Data

Run:

```bash
python data/generate_vulnerabilities.py
```

This generates:

```text
data/vulnerabilities.csv
```

---

# Initialize / Seed the Database

Run:

```bash
python -m backend.utils.seed_alerts
```

The application creates or updates the local SQLite database.

---

# Start the Backend

Run:

```bash
python -m backend.app
```

The application will be available at:

```text
http://127.0.0.1:5000
```

Open the URL in your browser.

---

# Example IOC Search

Use a synthetic indicator such as:

```text
198.51.100.25
```

The dashboard can display:

```text
Indicator Type:
IP

Known in Demo Dataset:
YES

Risk:
78/100

Severity:
HIGH

Confidence:
85%

Category:
PHISHING

Status:
MONITORING
```

This is local synthetic data.

The application does not contact the IP address.

---

# Safe Demonstration Scenario

The project includes the following fictional scenario:

```text
Threat ID:
THR-2026-001

Threat Name:
Synthetic Credential Phishing Campaign

Category:
PHISHING

Indicator Type:
DOMAIN

Indicator:
login-check.invalid

Severity:
HIGH

Risk:
78/100

Confidence:
85/100

Status:
MONITORING

Related Indicator:
198.51.100.25
```

Analyst note:

```text
Indicator appears in multiple synthetic phishing observations.
```

Recommended defensive actions:

```text
Review related internal logs
Check for authorized sightings
Review email-security telemetry
Increase phishing awareness
Monitor related indicators
```

Do not visit the demonstration domain.

---

---

# Git Commands

Initialize the repository:

```bash
git init
```

Set the main branch:

```bash
git branch -M main
```

Add files:

```bash
git add .
```

Create the first commit:

```bash
git commit -m "Initialize cybersecurity threat intelligence dashboard"
```

Add your GitHub repository:

```bash
git remote add origin https://github.com/YOUR_USERNAME/Cybersecurity-Awareness-Threat-Intelligence-Dashboard.git
```

Push:

```bash
git push -u origin main
```

---



# Learning Outcomes

By completing this project, the developer demonstrates practical exposure to:

### Cybersecurity

- Defensive security
- Threat analysis
- Security awareness
- Vulnerability awareness
- Incident response concepts

### Cyber Threat Intelligence

- IOC analysis
- Threat enrichment
- Threat classification
- Risk scoring
- Confidence scoring
- Source reliability
- Threat correlation
- Threat lifecycle management

### SOC Operations

- Alert generation
- Alert correlation
- Analyst triage
- Threat investigation
- Analyst notes
- Threat prioritization
- False-positive handling

### Security Engineering

- REST API development
- Database design
- Input validation
- Authentication
- Security-aware application design
- Automated testing

### Python Development

- Flask
- Pandas
- SQLite
- JSON/CSV processing
- Modular application architecture
- Unit testing

---

# Industry Relevance

The concepts demonstrated by this project are relevant to:

- Security Operations Centers
- Banks
- Cloud companies
- IT enterprises
- Government organizations
- E-commerce companies
- Healthcare organizations
- Universities
- Managed Security Service Providers
- Cybersecurity consulting organizations

The project demonstrates concepts applicable to roles such as:

- SOC Analyst
- Cybersecurity Analyst
- Threat Intelligence Analyst
- Incident Response Analyst
- Security Engineer
- Vulnerability Analyst
- Security Awareness Specialist
- Threat Hunter

---


# Technical Skills Demonstrated

```text
Python
Flask
SQLite
Pandas
REST APIs
HTML
CSS
JavaScript
Cyber Threat Intelligence
IOC Analysis
Threat Enrichment
Risk Scoring
Confidence Scoring
Threat Correlation
Security Alerts
MITRE ATT&CK
Vulnerability Management
SOC Workflows
Incident Response Concepts
Security Awareness
Automated Testing
Git
GitHub
```

---

# Ethical Disclaimer

This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, security awareness, and security analytics.

It does not:

- Execute malicious payloads
- Deploy malware
- Create phishing kits
- Harvest credentials
- Exploit vulnerabilities
- Scan unauthorized systems
- Contact suspicious infrastructure automatically
- Attack external systems
- Provide harmful payloads

All demonstration indicators are synthetic, fictional, sanitized, or intended for defensive educational use.

Threat intelligence is treated as analytical evidence rather than unquestionable truth.


---

# Project Repository

Repository:

```text
Cybersecurity-Awareness-Threat-Intelligence-Dashboard
```

Project focus:

```text
Cybersecurity
Cyber Threat Intelligence
SOC
IOC Analysis
MITRE ATT&CK
Vulnerability Management
Risk Scoring
Threat Correlation
Security Awareness
Python
Security Analytics
Incident Response Concepts
```

---

# Final Project Summary

This project demonstrates how cybersecurity threat information can be transformed into useful defensive intelligence:

```text
Raw Threat Data
      |
      v
Validation
      |
      v
Normalization
      |
      v
Enrichment
      |
      v
Risk + Confidence
      |
      v
Correlation
      |
      v
Alert Generation
      |
      v
SOC Investigation
      |
      v
Defensive Decision
```

At the same time, the awareness component transforms cybersecurity knowledge into practical user education:

```text
Awareness Content
      |
      v
Learning Modules
      |
      v
Security Quiz
      |
      v
Awareness Score
      |
      v
Weakness Identification
      |
      v
Personalized Recommendations
```

The overall objective is to demonstrate a complete defensive cybersecurity workflow while keeping the project safe, reproducible, understandable, and suitable for academic, GitHub, portfolio, and placement purposes.