### Overview 

RiskSense provides vulnerability management, assessment, and response to changes in the environment while prioritizing risk across vulnerabilities, configurations, and controls. 

Our objective is to integrate with Cortex XSOAR and address use-cases such as:

**Aggregation** - make RiskSense a source for data ingestion especially as a threat intelligence source in context of a customer’s infrastructure.

**Enrichment** - be able to enrich security and threat centric data for an incident or during data collection and processing.

**Orchestration and Automation** - provide functions and capabilities to allow for RiskSense data to be used in creating playbooks for vulnerability management either as a standalone data source or in conjunction with other software and solutions.

### Use-Cases

#### Automated Vulnerability Enrichment and Context Addition
With the Cortex XSOAR-RiskSense integration, security orchestration playbooks can benefit from ingesting and enriching host vulnerability information along with other custom fields such as a host risk score and vulnerability risk rating to help security operations prioritize and remediate vulnerabilities. RiskSense integration can provide all necessary data to security analyst to help make their decision based on actual risk.

#### Information Enrichment for Incidents and Threats
Security analysts can benefit by using RiskSense commands to debug and respond to incidents and threats. For example, analysts can look up host details for the host that shows up in a alert and quickly gauge the risk that host presents based on its risk score and vulnerabilities that exist on the host.


### RiskSense Commands on Cortex XSOAR

|   Command     | Description|
| ---    | ---  |
| risksense-get-hosts                  | Get all hosts info from RiskSense  |
| risksense-get-apps                   | Get information about an application|
|risksense-get-host-detail             | Get host information in detail for a particular host with finding distribution count and RS3 info |
|risksense-get-app-detail              | Get application information in detail for a particular application with finding distribution count |
|risksense-get-host-finding-detail     | Get host finding information with detail projection for particular host finding ID|
|risksense-get-open-host-finding       | Get basic information of open host finding based on various filter like hostname, <br /> criticality, severity etc. Return total number                                          of open findings on a particular host broken down as CHMLI|
|risksense-get-closed-host-finding     | Get basic information of close host finding based on various filter like hostname, <br /> criticality, severity etc. Return total number of closed findings on a particular host broken down as CHMLI |
|risksense-get-unique-cves             | Returns all CVE exposure on a host based on its findings |


