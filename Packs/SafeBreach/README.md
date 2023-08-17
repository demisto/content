SafeBreach has an extensive Hacker’s Playbook of breach and attack simulations that enables you to test your security controls against known attacks with the latest indicators of compromise (IOCs) and behavioral indicators of compromise (BIOCs).   IOCs that are proven capable - through simulation results - of breaching your enterprise are fetched from SafeBreach into Cortex XSOAR playbooks to fully automate updates to your endpoint and network security controls.

The integration with Cortex XSOAR enables a fully automated, closed-loop process to ensure your security defenses will prevent the latest indicators from breaching your defenses.
Enable the "SafeBreach - Breach and Attack Simulation platform" integration with Cortex XSOAR and benefit from **closed-loop automated security control remediation of IOCs:**

- Discover security gaps through continuous breach & attack simulation
- Automatically remediate and validate missed IOCs
- Maximize the effectiveness and value of your existing security controls

**What does this pack do?**

- Integrates with SafeBreach Insights, fetching multiple indicators that were not blocked in your environment (files, domains, urls, commands, ports, protocols, etc.)
- Processes non-behavioral indicators, automatically remediating and validating them by rerunning related simulations
- Extends the existing XSOAR indicator types with additional custom SafeBreach indicator types

**How to enable it?**

1. Enable and configure SafeBreach v2 integration
2. Create a Feed triggered job that will be triggered for SafeBreach indicators
3. Assign the playbook for the job - "SafeBreach - Process Non-Behavioral Insights Feed"