# Criminal IP Integration for Palo Alto XSOAR

## About
Criminal IP delivers cyber threat intelligence powered by AI and OSINT, enabling precise threat analysis and deep investigations into IPs, domains, and URLs with reputation data, threat scoring, along with real-time detection of malicious indicators such as C2, IOCs, and other critical threats. Built on this intelligence, Criminal IP Attack Surface Management discovers and monitors exposed assets, identifying risks across the attack surface with real-time enrichment and risk prioritisation.

The integration between Criminal IP and Palo Alto XSOAR enables users to assess the malicious nature of IPs and domains through dedicated Commands and Playbooks. For domains, the system delivers comprehensive reports directly to users via email.

Additionally, Criminal IP's **Micro-ASM** playbook provides rapid and robust Attack Surface Management capabilities, allowing users to receive detailed reports about their digital assets via email.

## Requirements
To use this integration, a Criminal IP API key is required.  
Users can obtain an API key by registering at [Criminal IP](https://www.criminalip.io/).

## What does this pack do?

### IP Analysis
- Evaluates IPs based on Criminal IP's intelligence to determine whether they are malicious or safe.
- Supports automated maliciousness checks using Criminal IP's IP Score and Real IP detection.

### Domain Analysis
- Conducts various scan types (**Quick, Lite, Full**) on domains to assess their security status.
- Full Scan results can be used to generate summary email reports with suspicious findings.

### Attack Surface Management
- Examines the user's domain assets to detect anomalies (e.g., CVEs, expiring certificates, malicious connections).
- If issues are detected, the system delivers a detailed asset report to the user.
- Can be configured as a scheduled job for continuous monitoring.

### Playbooks Included
- **Criminal IP Micro ASM**:  
  Takes a list of domains, executes a full scan for each, runs Micro ASM checks, and delivers results via email.  
- **Criminal IP Run Micro ASM**:  
  Sub-playbook that handles scanning and Micro ASM checks for a single domain, with polling for scan completion.

## Resources
For more information, visit:
- [Criminal IP Official Website](https://www.criminalip.io/)  
- [Criminal IP Blog](https://blog.criminalip.io/)  
