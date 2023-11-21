Enables changing context in two ways. The first is to capitalize the first letter of each key in following level of the context key entered. The second is to change context keys to new values. 

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* QRadar - Get Offense Logs
* QRadar - Get offense correlations v2
* QRadarCorrelationLog
* SafeBreach - Compare and Validate Insight Indicators

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| input | The context to change \(i.e., $\{Context.Key\}\). |
| inplace | If "True" replaces the existing key. The default is "True". |
| replace_dict | A list of key-values to replace key for value in the following format: \{"old_key1":"new_key1", "old_key2":"new_key2"\} |
| capitalize | If "True" capitalizes the first letter of the context key. |
| output_key | The context path in which to output the results. Should be in the format of Context.Key. |

## Outputs

---
There are no outputs for this script.
