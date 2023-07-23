The **Cortex Attack Surface Management** pack is supported by Cortex Xpanse Expander and the (Attack Surface Management) ASM module for Cortex XSIAM.

[Cortex Xpanse](https://www.paloaltonetworks.com/cortex/cortex-xpanse) Expander and the Attack Surface Management (ASM) module for [Cortex XSIAM](https://www.paloaltonetworks.com/cortex/cortex-xsiam) are both best in class External Attack Surface Management solutions that strive to proactively reduce the frequency and severity of security incidents caused by internet-exposed risks. These solutions deliver comprehensive attack surface visibility by combining thorough, ML-enhanced asset attribution with continuous attack surface assessment. Any discovered risks are prioritized using contextual information and exploitability data, and findings are actioned through curated, automated playbooks to investigate, remediate, and summarize every new alert.

## What does this pack do?

This pack contains all of the integrations, automations, and playbooks necessary to fully automate the investigation, remediation, verification, and reporting on ASM risks within Cortex Xpanse Expander and Cortex XSIAM. Currently our pack:

- Enriches services, assets, and alerts based on out-of-the-box integrations with sources like CMDBs, Cloud Service Providers, VM solutions, and more.
- Uses ML assisted analysis to identify critical context useful for analyst decision making.
- Keeps human analysts in the loop to direct the desired remediation action depending on the type of risk and discovered context.
- Includes automated notification and ticket creation workflows for delegating remediation tasks to the appropriate service owners.
- Includes full automated remediation options for automatically removing risky services from the public internet.
- Sends out a notification to identified service owners via email about the remediation action taken.
- Supports validation re-scanning to ensure that remediation efforts have been applied successfully.
- Includes PDF reporting capabilities for preserving and communicating the investigation summary.

## How to use it?

The Active Response playbook contains a set of sub-playbooks, which support many different remediation paths that can be taken depending on the types of configured integrations, the type of alert, and input provided by the analyst.

For setting up the Active Response module for Xpanse, [a guide on how to configure the Active Response module can we found here.](https://docs-cortex.paloaltonetworks.com/r/Cortex-XPANSE/Cortex-Xpanse-Expander-User-Guide/Set-Up-Active-Response)

Aditionally, [a list of integrations used for the Active Response playbook can be found here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XPANSE/Cortex-Xpanse-Expander-User-Guide/Automated-Remediation-Capabilities-Matrix?section=UUID-0a5dcbc2-d5ab-fa4e-5efc-599daac8b39b_table-idm4546555537995233526554598204). These are needed for different enrichment and remediation possibilities.

### Demo Video

[![Active Response in Cortex Xpanse](https://i.ytimg.com/vi/aIP1CCn9ST8/hq720.jpg)](https://www.youtube.com/watch?v=rryAQ23uuqw "Active Response in Cortex Xpanse")

### Automated Remediation Requirements

Automated remediation is only possible when the right conditions are met.  These are the current requirements:

- One of the following attack surface rule IDs:
  - Insecure OpenSSH
  - OpenSSH
  - SSH Server
  - SNMP Server
  - RDP Server
  - Telnet Server
  - Unencrypted FTP Server
  - Mysql Server
  - Mongo Server
  - Postgres Server
  - Elasticsearch Server
  - Unclaimed S3 Bucket*
- Asset is a cloud compute instance:
  - AWS EC2 Instance
  - Azure Compute Instance
  - GCP Compute Engine (VM)
- Service owner information found through one of the following:
  - AWS IAM
  - Azure IAM
  - GCP IAM
  - Prisma Cloud
  - Rapid7 InsightVM (Nexpose)
  - Splunk
  - ServiceNow CMDB
  - Tenable.io Assets
  - Qualys
- Indicators of a non-production host:
  - "dev" or related words found in environment-related tags associated with the asset (case insensitive)
  - Has an active "DevelopmentEnvironment" classification from processing of public data

\* The `Unclaimed S3 Bucket` attack surface rule ID only requires `AWS-S3` integration to be enabled.

## What is included in this pack?

The main active response playbook is the `Cortex ASM - ASM Alert` playbook. This playbook contains a set of sub-playbooks and automation scripts, which support many different remediation paths that can be taken depending on the types of configured integrations, the type of alert, and input provided by the analyst. After the final stage, the alert is resolved.

- Playbooks
  - [Cortex ASM - ASM Alert](#cortex-asm---asm-alert)
  - [Cortex ASM - AWS Enrichment](#cortex-asm---aws-enrichment)
  - [Cortex ASM - Azure Enrichment](#cortex-asm---azure-enrichment)
  - [Cortex ASM - Decision](#cortex-asm---decision)
  - [Cortex ASM - Detect Service](#cortex-asm---detect-service)
  - [Cortex ASM - Email Notification](#cortex-asm---email-notification)
  - [Cortex ASM - Enrichment](#cortex-asm---enrichment)
  - [Cortex ASM - GCP Enrichment](#cortex-asm---gcp-enrichment)
  - [Cortex ASM - Jira Notification](#cortex-asm---jira-notification)
  - [Cortex ASM - Prisma Cloud Enrichment](#cortex-asm---prisma-cloud-enrichment)
  - [Cortex ASM - Qualys Enrichment](#cortex-asm---qualys-enrichment)
  - [Cortex ASM - Rapid7 Enrichment](#cortex-asm---rapid7-enrichment)
  - [Cortex ASM - Remediation Confirmation Scan](#cortex-asm---remediation-confirmation-scan)
  - [Cortex ASM - Remediation Guidance](#cortex-asm---remediation-guidance)
  - [Cortex ASM - Remediation Objectives](#cortex-asm---remediation-objectives)
  - [Cortex ASM - Remediation Path Rules](#cortex-asm---remediation-path-rules)
  - [Cortex ASM - Remediation](#cortex-asm---remediation)
  - [Cortex ASM - Service Ownership](#cortex-asm---service-ownership)
  - [Cortex ASM - ServiceNow CMDB Enrichment](#cortex-asm---servicenow-cmdb-enrichment)
  - [Cortex ASM - ServiceNow Notification](#cortex-asm---servicenow-notification)
  - [Cortex ASM - Splunk Enrichment](#cortex-asm---splunk-enrichment)
  - [Cortex ASM - Tenable.io Enrichment](#cortex-asm---tenableio-enrichment)
- Automation Scripts
  - [GenerateASMReport](#generateasmreport)
  - [GetProjectOwners](#getprojectowners)
  - [RankServiceOwners](#rankserviceowners)
  - [RemediationPathRuleEvaluation](#remediationpathruleevaluation)

### Playbooks

#### Cortex ASM - ASM Alert

A playbook that enriches asset information for ASM alerts and provides the means for remediation.

![Cortex ASM - ASM Alert](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_ASM_Alert.png)

#### Cortex ASM - AWS Enrichment

A playbook that given the IP address enriches AWS information relevant to ASM alerts.

![Cortex ASM - AWS Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_AWS_Enrichment.png)

#### Cortex ASM - Azure Enrichment

A playbook that given the IP address enriches Azure information relevant to ASM alerts.

![Cortex ASM - Azure Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Azure_Enrichment.png)

#### Cortex ASM - Decision

A playbook that returns "RemediationAction" options based on meeting "Automated Remediation Requirements" as well as whether ServiceNowV2 integration is set up.

![Cortex ASM - Decision](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Decision.png)

#### Cortex ASM - Detect Service

A playbook that utilizes the Remediation Confirmation Scan service to check for mitigated vulnerabilities.

![Cortex ASM - Detect Service](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Detect_Service.png)

#### Cortex ASM - Email Notification

A playbook that is used to send email notifications to service owners to notify them of their internet exposures.

![Cortex ASM - Email Notification](https://raw.githubusercontent.com/demisto/content/94341532ed2e30cb0c5fb3235ef10b4411c8337c/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Email_Notification.png)

#### Cortex ASM - Enrichment

A playbook that is used as a container folder for all enrichments of ASM alerts.

![Cortex ASM - Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Enrichment.png)

#### Cortex ASM - GCP Enrichment

A playbook that given the IP address enriches GCP information relevant to ASM alerts.

![Cortex ASM - GCP Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_GCP_Enrichment.png)

#### Cortex ASM - Jira Notification

A playbook that is used to create Jira tickets directed toward service owners to notify them of their internet exposures.

![Cortex ASM - Jira Notification](https://raw.githubusercontent.com/demisto/content/94341532ed2e30cb0c5fb3235ef10b4411c8337c/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Jira_Notification.png)

#### Cortex ASM - Prisma Cloud Enrichment

Playbook that given the IP address enriches Prisma Cloud information relevant to ASM alerts.

![Cortex ASM - Prisma Cloud Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Prisma_Cloud_Enrichment.png)

#### Cortex ASM - Qualys Enrichment

Playbook that given the IP address enriches Qualys information relevant to ASM alerts.

![Cortex ASM - Qualys Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Qualys_Enrichment.png)

#### Cortex ASM - Rapid7 Enrichment

A playbook that given the IP address enriches Rapid7 information relevant to ASM alerts.

![Cortex ASM - Rapid7 Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Rapid7_Enrichment.png)

#### Cortex ASM - Remediation Confirmation Scan

A playbook that creates an ASM Remediation Confirmation Scan using an existing service ID, if the scan does not already exist;. It then polls for results of a scan.

![Cortex ASM - Remediation Confirmation Scan](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Remediation_Confirmation_Scan.png)

#### Cortex ASM - Remediation Guidance

A playbook that pulls remediation guidance off of a list based on ASM RuleID to be used in service owner notifications (email or ticketing system).

![Cortex ASM - Remediation Guidance](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Remediation_Guidance.png)

#### Cortex ASM - Remediation Objectives

A playbook that populates the remediation objectives field that is used to display the remediation actions to the end user.

![Cortex ASM - Remediation Objectives](https://raw.githubusercontent.com/demisto/content/5f71853b59431ca60b1b783867b89f819accfefd/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Remediation_Objectives.png)

#### Cortex ASM - Remediation Path Rules

A playbook that returns "RemediationAction" options based on the return from the Remediation Path Rules API, or defaults to data collection task options from the "Cortex ADM - Decision" sub-playbook.

![Cortex ASM - Remediation Path Rules](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Remediation_Path_Rules.png)

#### Cortex ASM - Remediation

A playbook that is used as a container folder for all remediation of ASM alerts.

![Cortex ASM - Remediation](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Remediation.png)

#### Cortex ASM - Service Ownership

Playbook that identifies and recommends the most likely owners of a given service.

![Cortex ASM - Remediation](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Service_Ownership.png)

#### Cortex ASM - ServiceNow CMDB Enrichment

A playbook that given the IP address enriches ServiceNow CMDB information relevant to ASM alerts.

![Cortex ASM - ServiceNow CMDB Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_ServiceNow_CMDB_Enrichment.png)

#### Cortex ASM - ServiceNow Notification

A playbook that is used to create ServiceNow tickets directed toward service owners to notify them of their internet exposures.

![Cortex ASM - ServiceNow Notification](https://raw.githubusercontent.com/demisto/content/94341532ed2e30cb0c5fb3235ef10b4411c8337c/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_ServiceNow_Notification.png)

#### Cortex ASM - Splunk Enrichment

A playbook that given the IP address enriches Splunk information relevant to ASM alerts.

![Cortex ASM - Splunk Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Splunk_Enrichment.png)

#### Cortex ASM - Tenable.io Enrichment

A playbook that given the IP address enriches Tenable.io information relevant to ASM alerts.

![Cortex ASM - Tenable.io Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Tenable.io_Enrichment.png)

### Automation Scripts

#### GenerateASMReport

An automation used to generate an ASM alert summary report with important information found via the playbook run.

![GenerateASMReport](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/GenerateASMReport.png)

#### InferWhetherServiceIsDev

An automation that identifies whether the service is a "development" server. Development servers have no external users and run no production workflows. These servers might be named "dev", but they might also be named "qa", "pre-production", "user acceptance testing", or use other non-production terms. This automation uses both public data visible to anyone (`active_classifications` as derived by Xpanse ASM) as well as checking internal data for AI-learned indicators of development systems (`asm_tags` as derived from integrations with non-public systems).

![InferWhetherServiceIsDev](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/InferWhetherServiceIsDev.png)

#### RankServiceOwners

An automation that recommends the most likely service owners from those surfaced by Cortex ASM Enrichment and updates content.

#### GetProjectOwners

This automation parses a GCP service account email for the project ID, then looks up the project owners and adds them to a list of potential service owners for ranking.

#### RemediationPathRuleEvaluation

An automation that is used to find a matching remediation path rule based on criteria.  If multiple rules match, it will return the most recently created rule.  This assumes that the rules passed in are filtered to correlate with the alert's attack surface rule (Xpanse only).

![RemediationPathRuleEvaluation](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/RemediationPathRuleEvaluation.png)
