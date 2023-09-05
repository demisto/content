Deprecated. No available replacement.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* SafeBreach - Rerun Single Insight
* GenericPolling

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
