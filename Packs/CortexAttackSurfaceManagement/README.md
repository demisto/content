The **Cortex Attack Surface Management** pack supported by Cortex Xpanse Expander and the ASM module for Cortex XSIAM.

Cortex Xpanse Expander and the ASM module for Cortex XSIAM are both best in class External Attack Surface Management solutions that strive to proactively reduce the frequency and severity of security incidents caused by internet-exposed risks. These solutions deliver comprehensive attack surface visibility by combining thorough, ML enhanced asset attribution with continuous attack surface assessment. Discovered risks are prioritized using contextual information and exploitability data and findings are actioned on through curated automated playbooks to investigate, remediate, and summarize every new alert.

## What does this pack do?
This pack contains all of the integrations, automations, and playbooks necessary to fully automate the investigation, remediation, verification, and reporting on ASM risks within Cortex Xpanse Expander and XSIAM.

- Enriches services, assets, and alerts based on out of the box integrations with sources like CMDBs, Cloud Service Providers, VM solutions, and more.
- Uses ML assisted analysis to identify critical context useful for analyst decision making.
- Keeps human analysts in the loop to direct the desired remediation action depending on the type of risk and discovered context.
- Includes automated notification and ticket creation workflows for delegating remediation tasks to the appropriate service owners.
- Includes full automated remediation options for automatically removing risky services from the public Internet.
- Supports validation rescanning to ensure that remediation efforts have been applied successfully.
- Includes pdf reporting capabilities for preserving and communicating the investigation summary.

### Playbooks
1. Cortex ASM - ASM Alert
2. Cortex ASM - Detect Service
3. Cortex ASM - Enrichment

### Cortex ASM - ASM Alert
Playbook that enriches asset information for ASM alerts and provides means of remediation.
<place_holder: Add absolute link after PR>

#### Cortex ASM - Detect Service
Playbook that looks at what ASM sub-type the alert is and direct to different pre/post mitigation scans (such as NMAP).
<place_holder: Add absolute link after PR>

#### Cortex ASM - Enrichment
Playbook that is used as a container folder for all enrichments of ASM alerts.
<place_holder: Add absolute link after PR>

### Automation Scripts
This content pack includes the following scripts: 
1. GetRemediationGuidance
2. GenerateASMReport

#### GetRemediationGuidance
This automation helps determine remediation guidance based on a list of Xpanse issueTypeId to remediationGuidance pairings.
<place_holder: Add absolute link after PR>

#### GenerateASMReport
This automation helps generate an ASM alert summary report with important information found via the playbook run.
<place_holder: Add absolute link after PR>