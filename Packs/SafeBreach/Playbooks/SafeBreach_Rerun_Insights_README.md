This playbook reruns a SafeBreach insight based on Insight Id and waits until it completes.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* SafeBreach Rerun Insights with Sleep in Between
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
* Sleep

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
| SafeBreach.Insight.Name | Insight name representing the action required to be taken | unknown |
| SafeBreach.Insight.Id | Insight unique id | unknown |
| SafeBreach.Insight.DataType | Insight data type. Options: Hash, Domain, URI, Command, Port, Protocol | unknown |
| SafeBreach.Insight.Category | Security control category name | unknown |
| SafeBreach.Insight.LatestSimulation | Time of the latest simulation from the insight | unknown |
| SafeBreach.Insight.SimulationsCount | Number of the related simulations | unknown |
| SafeBreach.Insight.RiskImpact | Risk impact of the insight on the environment total risk score | unknown |
| SafeBreach.Insight.AffectedTargetsCount | Number of the affected targets | unknown |
| SafeBreach.Insight.SeverityScore | Insight severity numeric value | unknown |
| SafeBreach.Insight.Severity | Insight severity mapped to low/medium/high | unknown |
| SafeBreach.Insight.RemediationDataCount | Number of the remediation data points | unknown |
| SafeBreach.Insight.RemediationDataType | Type of the remediation data | unknown |
| SafeBreach.Insight.ThreatGroups | Array of APT names that are mapped to the insight | unknown |
| SafeBreach.Insight.NetworkDirection | Communication direction of Insight, relative to the target \(inbound/outbound\) | unknown |
| SafeBreach.Insight.AttacksCount | List of all insight related SafeBreach attack ids | unknown |

## Playbook Image
---
![SafeBreach - Rerun Insights](Insert the link to your image here)