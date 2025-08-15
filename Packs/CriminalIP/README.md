# Criminal IP Integration for Palo Alto Xsoar

## About
Criminal IP delivers cyber threat intelligence powered by AI and OSINT, enabling precise threat analysis and deep investigations into IPs, domains, and URLs with reputation data, threat scoring, along with real-time detection of malicious indicators such as C2, IOCs, and other critical threats. Built on this intelligence, Criminal IP Attack Surface Management discovers and monitors exposed assets, identifying risks across the attack surface with real-time enrichment and risk prioritisation.

The integration between Criminal IP and Palo Alto Xsoar enables users to assess the malicious nature of IPs and domains through dedicated Commands and Playbooks. For domains, the system delivers comprehensive reports directly to users via email.

Additionally, Criminal IP's Micro-ASM playbook provides rapid and robust Attack Surface Management capabilities, allowing users to receive detailed reports about their digital assets via email.

## Requirements
To use this integration, a Criminal IP API key is required.
Users can obtain an API key by registering at [Criminal IP](https://www.criminalip.io/).

## What does this pack do?

### IP Analysis
- Evaluates IPs based on Criminal IP's intelligence to determine whether they are malicious or safe.

### Domain Analysis
- Conducts various scan types (Quick, Lite, Full) on domains to assess their security status.
- When a Full Scan identifies a malicious domain, the system automatically sends a comprehensive report to the user.

### Attack Surface Management
- Thoroughly examines the user's domain assets to detect any security anomalies.
- If issues are detected, the system delivers a detailed asset report to the user.
- This functionality can be configured as a scheduled job for continuous monitoring.

## Resources
For more information, visit:
- [Criminal IP Official Website](https://www.criminalip.io/)
- [Criminal IP Blog](https://blog.criminalip.io/)