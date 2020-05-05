This playbook reruns a SafeBreach insight based on id and waits until it completes. Returns the updated insight object after post rerun.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* SafeBreach v2

### Scripts
* Sleep

### Commands
* safebreach-get-insights
* safebreach-rerun-insight

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| InsightId | SafeBreach Insight Id to rerun | Insight.Id | SafeBreach | Optional |

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

<!-- Playbook PNG image comes here -->