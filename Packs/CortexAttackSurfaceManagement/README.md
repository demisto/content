The **Cortex Attack Surface Management** pack is supported by Cortex Xpanse Expander and the ASM module for Cortex XSIAM.

Cortex Xpanse Expander and the ASM module for Cortex XSIAM are both best in class External Attack Surface Management solutions that strive to proactively reduce the frequency and severity of security incidents caused by internet-exposed risks. These solutions deliver comprehensive attack surface visibility by combining thorough, ML enhanced asset attribution with continuous attack surface assessment. Discovered risks are prioritized using contextual information and exploitability data, and findings are actioned on through curated automated playbooks to investigate, remediate, and summarize every new alert.

## What does this pack do?

This pack contains all of the integrations, automations, and playbooks necessary to fully automate the investigation, remediation, verification, and reporting on ASM risks within Cortex Xpanse Expander and XSIAM.

- Enriches services, assets, and alerts based on out-of-the-box integrations with sources like CMDBs, Cloud Service Providers, VM solutions, and more.
- Uses ML assisted analysis to identify critical context useful for analyst decision making.
- Keeps human analysts in the loop to direct the desired remediation action depending on the type of risk and discovered context.
- Includes automated notification and ticket creation workflows for delegating remediation tasks to the appropriate service owners.
- Includes full automated remediation options for automatically removing risky services from the public internet.
- Supports validation re-scanning to ensure that remediation efforts have been applied successfully.
- Includes PDF reporting capabilities for preserving and communicating the investigation summary.

### Automated Remediation requirements

Automated remediation is only possible when the right conditions are met.  These are the current requirements:

- One of the following attack surface rule IDs:
  - Insecure OpenSSH
  - RDP Server
  - Telnet Server
  - Unencrypted FTP Server
  - OpenSSH
  - SSH Server
  - SNMP Server
- Asset is a cloud compute instance:
  - AWS EC2 Instance
  - GCP Compute Engine (VM)
  - Azure Compute Instance
- Service owner information found through one of the following:
  - AWS IAM
  - ServiceNow CMDB
  - Tenable.io Assets
  - GCP IAM
  - Azure IAM
- Indicators of a non-production host:
  - "dev" or related words found in environment-related tags associated with the asset (case insensitive)
  - Has an active "DevelopmentEnvironment" classification from processing of public data

### Playbooks

- [Cortex ASM - ASM Alert](#cortex-asm---asm-alert)
- [Cortex ASM - Detect Service](#cortex-asm---detect-service)
- [Cortex ASM - Enrichment](#cortex-asm---enrichment)
- [Cortex ASM - AWS Enrichment](#cortex-asm---aws-enrichment)
- [Cortex ASM - ServiceNow CMDB Enrichment](#cortex-asm---servicenow-cmdb-enrichment)
- [Cortex ASM - Tenable.io Enrichment](#cortex-asm---tenableio-enrichment)
- [Cortex ASM - Remediation Guidance](#cortex-asm---remediation-guidance)
- [Cortex ASM - Remediation](#cortex-asm---remediation)
- [Cortex ASM - Azure Enrichment](#cortex-asm---azure-enrichment)
- [Cortex ASM - GCP Enrichment](#cortex-asm---gcp-enrichment)
- [Cortex ASM - SNMP Check](#cortex-asm---snmp-check)
- [Cortex ASM - Decision](#cortex-asm---decision)
- [Cortex ASM - Remediation Path Rules](#cortex-asm---remediation-path-rules)

### Cortex ASM - ASM Alert

Playbook that enriches asset information for ASM alerts and provides means of remediation.
![Cortex ASM - ASM Alert](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_ASM_Alert.png)

#### Cortex ASM - Detect Service

Playbook that looks at what ASM sub-type the alert is and directs it to different pre/post mitigation scans (such as NMAP, SNMP).
![Cortex ASM - Detect Service](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Detect_Service.png)

#### Cortex ASM - Enrichment

Playbook that is used as a container folder for all enrichments of ASM alerts.
![Cortex ASM - Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Enrichment.png)

#### Cortex ASM - AWS Enrichment

Playbook that given the IP address enriches AWS information relevant to ASM alerts.
![Cortex ASM - AWS Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_AWS_Enrichment.png)

#### Cortex ASM - ServiceNow CMDB Enrichment

Playbook that given the IP address enriches ServiceNow CMDB information relevant to ASM alerts.
![Cortex ASM - ServiceNow CMDB Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_ServiceNow_CMDB_Enrichment.png)

#### Cortex ASM - Tenable.io Enrichment

Playbook that given the IP address enriches Tenable.io information relevant to ASM alerts.
![Cortex ASM - Tenable.io Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Tenable.io_Enrichment.png)

#### Cortex ASM - Remediation Guidance

Playbook that pulls remediation guidance off of a list based on ASM RuleID to be used in service owner notifications (email or ticketing system).
![Cortex ASM - Remediation Guidance](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Remediation_Guidance.png)

#### Cortex ASM - Remediation

Playbook that is used as a container folder for all remediation of ASM alerts.	
![Cortex ASM - Remediation](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Remediation.png)

#### Cortex ASM - Azure Enrichment

Playbook that given the IP address enriches Azure information relevant to ASM alerts.	
![Cortex ASM - Azure Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Azure_Enrichment.png)

#### Cortex ASM - GCP Enrichment

Playbook that given the IP address enriches GCP information relevant to ASM alerts.	
![Cortex ASM - GCP Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_GCP_Enrichment.png)

#### Cortex ASM - SNMP Check

Playbook that given the IP address checks if SNMP is enabled or not and returns versions running.
![Cortex ASM - SNMP Check](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_SNMP_Check.png)

#### Cortex ASM - Decision
Playbook that returns "RemediationAction" options based on meeting "Automated Remediation Requirements" as well as whether ServiceNowV2 integration is set up.
![Cortex ASM - Decision](https://raw.githubusercontent.com/demisto/content/7b2f8db22f0be0cc55f8f0663894f459c3b3801e/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Decision.png)

#### Cortex ASM - Remediation Path Rules
Playbook that returns "RemediationAction" options based on the return from the Remediation Path Rules API, or defaults to data collection task options from the "Cortex ADM - Decision" sub-playbook.
![Cortex ASM - Remediation Path Rules](https://raw.githubusercontent.com/demisto/content/7b2f8db22f0be0cc55f8f0663894f459c3b3801e/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Remediation_Path_Rules.png)

### Automation Scripts

This content pack includes the [generateASMReport](#generateasmreport) script: 


#### GenerateASMReport

This automation helps generate an ASM alert summary report with important information found via the playbook run.
![GenerateASMReport](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/GenerateASMReport.png)

#### SnmpDetection

This automation checks if SNMP is enabled or not and gets the running version on the remote server.
![SnmpDetection](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/GenerateASMReport.png)

#### InferWhetherServiceIsDev

This automation identifies whether the service is a "development" server. Development servers have no external users and run no production workflows. These servers might be named "dev", but they might also be named "qa", "pre-production", "user acceptance testing", or use other non-production terms. This automation uses both public data visible to anyone (`active_classifications` as derived by Xpanse ASM) as well as checking internal data for AI-learned indicators of development systems (`asm_tags` as derived from integrations with non-public systems).
![InferWhetherServiceIsDev](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/InferWhetherServiceIsDev.png)

#### RemediationPathRuleEvaluation
This automation attempts to find a matching remediation path rule based on criteria.  If multiple rules match, it will return the most recently created rule.  This assumes that the rules passed in are filtered to correlate with the alert's attack surface rule (Xpanse only).
![RemediationPathRuleEvaluation](https://raw.githubusercontent.com/demisto/content/7b2f8db22f0be0cc55f8f0663894f459c3b3801e/Packs/CortexAttackSurfaceManagement/doc_files/RemediationPathRuleEvaluation.png)
