Gets more information when running on a QRadar offense.

* Get all correlations relevant to the offense
* Get all logs relevant to the correlations. This is not done by default. To put this in place set `GetCorrelationLogs` to "True".

Inputs:
* GetCorrelationLogs (default: False)
* MaxLogsCount (default: 20)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* QRadarGetCorrelationLogs
* QRadarGetOffenseCorrelations

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| GetCorrelationLogs | Get all of the offense's correlations logs when set to "True". | False | - | Optional |
| MaxLogsCount | THe maximum number of log entires to query from QRadar. The default is 20. | 20 | - | Optional |
| ID | The QRadar offense ID.  | labels.id | incident | Required |
| StartTime | The QRadar offense start time. | labels.start_time | incident | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| QRadar.Correlation.StartTime | The correlation start time. | unknown |
| QRadar.Correlation.CategoryID | The correlation category ID.  | unknown |
| QRadar.Correlation.QID | The correlation QID identifier. | unknown |
| QRadar.Correlation.CREName | The correlation name. | unknown |
| QRadar.Correlation.CREDescription | The correlation description. | unknown |
| QRadar.Correlation | The QRadar offense correlations. | unknown |
| QRadar.Correlation.SourceIP | The correlation source IP address. | unknown |
| QRadar | The QRadar context output. | unknown |
| QRadar.Correlation.DestinationIP | The correlation destination IP address. | unknown |
| QRadar.Correlation.Category | The correlation high level category. | unknown |
| QRadar.Correlation.Username | The correlation username. | unknown |
| QRadar.Log | The QRadar offense correlation logs. | unknown |
| QRadar.Log.QID | The log's correlation ID. | unknown |
| QRadar.Log.SourceIP | The log's source IP address. | unknown |
| QRadar.Log.DestinationPort | The log's destination port. | unknown |
| QRadar.Log.SourcePort | The log's source port. | unknown |
| QRadar.Log.DestinationIP | The log's destination IP address. | unknown |
| QRadar.Log.Category | The log's category. | unknown |
| QRadar.Log.IdentityIP | The log's identity IP address. | unknown |
| QRadar.Log.Username | The log's username. | unknown |
| QRadar.Log.StartTime | The log's start time. | unknown |
| QRadar.Log.Magnitude | The log's magnitude. | unknown |
| QRadar.Log.ProtocolName | The log's protocol name. | unknown |

## Playbook Image
---
![QRadar_Get_offense_correlations](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/QRadar_Get_offense_correlations.png)
