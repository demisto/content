Run on a QRadar offense to get more information:

* Get all correlations relevant to the offense
* Get all logs relevant to the correlations (not done by default - set "GetCorrelationLogs" to "True")

Inputs:
* GetCorrelationLogs (default: False)
* MaxLogsCount (default: 20)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* QRadarCorrelationLog
* QRadarFullSearch

### Integrations
This playbook does not use any integrations.

### Scripts
* ChangeContext
* Set

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| GetCorrelationLogs | When set to &quot;True&quot;, retrieves all of the offense&\#x27;s correlations logs | True |  | Optional |
| MaxLogsCount | Maximum number of log entires to query from QRadar \(default: 20\) | 20 |  | Optional |
| ID | The QRadar offense ID  | labels.id | incident | Required |
| StartTime | The QRadar offense start time | labels.start_time | incident | Required |
| GetOnlyCREEvents | If value &quot;OnlyCRE&quot; get only events made by CRE.
Values can be &quot;OnlyCRE&quot;, &quot;OnlyNotCRE&quot;, &quot;All&quot;. | All |  | Optional |
| MaxCorrelationCount | Maximum number of correlations to query from QRadar \(default: 100\) | 100 |  | Optional |
| Fields | A comma\-separated list of extra fields to get from each event. |  |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| QRadar.Correlation.StartTime | The correlation start time | unknown |
| QRadar.Correlation.CategoryID | The correlation category id  | unknown |
| QRadar.Correlation.QID | The correlation QID identifier | unknown |
| QRadar.Correlation.CREName | The correlation name | unknown |
| QRadar.Correlation.CREDescription | The correlation description | unknown |
| QRadar.Correlation | The QRadar offense correlations | unknown |
| QRadar.Correlation.SourceIP | The correlation source IP | unknown |
| QRadar | QRadar context output | unknown |
| QRadar.Correlation.DestinationIP | The correlation destination IP | unknown |
| QRadar.Correlation.Category | The correlation high level category | unknown |
| QRadar.Correlation.Username | The correlation username | unknown |
| QRadar.Log | The QRadar offense correlation logs | unknown |
| QRadar.Log.QID | The log&\#x27;s correlation ID | unknown |
| QRadar.Log.SourceIP | The log&\#x27;s source IP | unknown |
| QRadar.Log.DestinationPort | The log&\#x27;s destination port | unknown |
| QRadar.Log.SourcePort | The log&\#x27;s source port | unknown |
| QRadar.Log.DestinationIP | The log&\#x27;s destination IP | unknown |
| QRadar.Log.Category | The log&\#x27;s category | unknown |
| QRadar.Log.IdentityIP | The log&\#x27;s identity IP | unknown |
| QRadar.Log.Username | The log&\#x27;s username | unknown |
| QRadar.Log.StartTime | The log&\#x27;s start time | unknown |
| QRadar.Log.Magnitude | The log&\#x27;s magnitude | unknown |
| QRadar.Log.ProtocolName | The log&\#x27;s protocol name | unknown |

![](https://user-images.githubusercontent.com/50324325/81265692-33d91380-904c-11ea-9937-4839f6df52b1.png)
