This is a sub-playbook reruns a list of SafeBreach insights based on Insight Id and waits until they complete. Used in main SafeBreach playbooks, such as "SafeBreach - Handle Insight Incident" and "SafeBreach - Process Non-Behavioral Insights Feed".

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling
* SafeBreach - Rerun Single Insight

### Integrations
This playbook does not use any integrations.

### Scripts
* Sleep
* Print

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| InsightIds | SafeBreach Insight Ids to rerun | SafeBreach.Insight.Id | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SafeBreach.Insight.Name | Insight name representing the action required to be taken | String |
| SafeBreach.Insight.Id | Insight unique id | Number |
| SafeBreach.Insight.DataType | Insight data type. Options: Hash, Domain, URI, Command, Port, Protocol | Array |
| SafeBreach.Insight.Category | Security control category name | String |
| SafeBreach.Insight.LatestSimulation | Time of the latest simulation from the insight | String |
| SafeBreach.Insight.SimulationsCount | Number of the related simulations | Number |
| SafeBreach.Insight.RiskImpact | Risk impact of the insight on the environment total risk score | Number |
| SafeBreach.Insight.AffectedTargetsCount | Number of the affected targets | Number |
| SafeBreach.Insight.SeverityScore | Insight severity numeric value | Number |
| SafeBreach.Insight.Severity | Insight severity mapped to low/medium/high | String |
| SafeBreach.Insight.RemediationDataCount | Number of the remediation data points | Number |
| SafeBreach.Insight.RemediationDataType | Type of the remediation data | String |
| SafeBreach.Insight.ThreatGroups | Array of APT names that are mapped to the insight | Array |
| SafeBreach.Insight.NetworkDirection | Communication direction of Insight, relative to the target \(inbound/outbound\) | String |
| SafeBreach.Insight.AttacksCount | List of all insight related SafeBreach attack ids | Array |

## Playbook Image
---
![SafeBreach - Rerun Insights](https://github.com/demisto/content/raw/6af01e00312a5558e9e2fecdb22534e98414bc9c/Packs/SafeBreach/doc_imgs/SafeBreach_Rerun_Insights.png)