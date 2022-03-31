See high risk vulnerabilities in your application before they go into production.

ShiftLeft CORE provides static application security testing (SAST) that can be integrated into your CI/CD for automated scans. Each test is completed in minutes and, depending on the complexity of your application, can be run at each pull request. Known open source vulnerabilities are automatically checked against data flow analysis to tell whether an attacker can “reach” them from the attack surface of the application.

A single scan combines:

- Static analysis for risk in custom code.
- Software composition analysis for known issues in open source libraries.
- Secrets detection.

High-risk issues are listed with their corresponding OWASP Top Ten and attacker-reachable CVE categories.

With ShiftLeft CORE and Cortex XSOAR, Application Security engineers can run playbooks in order to:

- Gather application threat intelligence to help prioritize bug fixes
- Identify and create incidents to rotate secrets discovered in code.
- Proactively monitor applications for critical attacker-reachable vulnerabilities that enter production.

## Prerequisite

To use this extension, ensure CORE subscription is enabled for your ShiftLeft account.

## What does this pack do?

- Integrates ShiftLeft CORE and adds commands to retrieve the findings and secrets for your apps.
