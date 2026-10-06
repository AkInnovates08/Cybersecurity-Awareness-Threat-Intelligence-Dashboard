# Project Report — Cybersecurity Awareness & Threat Intelligence Dashboard

## Abstract
This project presents a defensive cybersecurity dashboard that combines synthetic cyber threat intelligence with cybersecurity awareness training. It validates indicators, enriches them from a local database, separates risk from confidence, correlates observations, generates alerts, provides conservative MITRE ATT&CK context, prioritizes vulnerabilities, and teaches users through awareness modules and a quiz.

## Introduction
Cybersecurity teams need both technical intelligence and informed users. The system demonstrates how a student can connect SOC-style analysis with practical awareness without interacting with malicious infrastructure.

## Problem Statement
Threat intelligence without context can create false positives and alert fatigue. Awareness without technical telemetry can lack operational relevance. This project joins both perspectives in a safe local environment.

## Objectives
Generate synthetic data; validate IOCs; enrich and score threats; correlate evidence; create alerts; visualize trends; explain vulnerabilities; provide awareness learning; test the system; document it for GitHub and placement use.

## IOC and IOA Concepts
An IOC is an artifact that may be associated with malicious activity, such as an IP, domain, URL, hash, or sender domain. An IOA is a behavior/action pattern that can indicate adversary activity. This project focuses on IOCs and high-level behavioral context.

## Threat Intelligence Lifecycle
Observed -> Validated -> Enriched -> Scored -> Investigated -> Monitored -> Expired/Closed.

## Proposed System
Synthetic data enters a normalization layer, passes IOC validation, classification, scoring and optional ATT&CK mapping, then reaches the threat database, correlation engine and SOC dashboard. A parallel awareness module provides learning and assessment.

## Risk vs Confidence
Risk asks how concerning an event may be. Confidence asks how trustworthy the available evidence is. A high-risk, low-confidence observation requires validation rather than automatic confirmation.

## False Positives and Limitations
IP addresses can be shared. Domains can change ownership. Cloud infrastructure can host benign and malicious services. Feeds can disagree. Indicators become stale. Correlation does not prove attribution. Analysts remain responsible for interpretation.

## Security
The project never visits indicators, executes files, scans systems, or sends suspicious network traffic. User-facing values are escaped before rendering. API input is validated. Secrets belong in environment variables.

## Results
The demo contains 2,200 synthetic threat records, 100 synthetic vulnerability records, 15 awareness modules, 30 quiz questions, REST endpoints, a SOC dashboard, threat detail views, alert management and 35 automated tests.

## Future Scope
Authorized STIX/TAXII, SIEM/SOAR, CVE/KEV and approved telemetry integrations; improved deduplication, confidence scoring, threat clustering, ATT&CK Navigator support, RBAC, Docker and CI/CD.

## Conclusion
The project demonstrates a complete defensive workflow from synthetic threat observation to analyst-facing decision support and human security awareness. Its most important lesson is that an indicator, score or alert is evidence for investigation—not automatic proof of compromise.
