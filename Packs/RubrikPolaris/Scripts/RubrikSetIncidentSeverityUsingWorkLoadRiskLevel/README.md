Script used to set the XSOAR incident severity using the workload data provided from the argument.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.5.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| risk_levels | Specify the risk level values. Supports comma separated values.<br/><br/>Supported values are: High, Medium, Low, No Risk. |
| anomaly_severities | Specify the anomaly severity values. Supports comma separated values.<br/><br/>Supported values are: Critical, Warning, Informational. |
| threat_hunt_malicious | Specify the malicious threat hunt values. Supports comma separated values.<br/><br/>Supported values are: Matches Found, No Matches Found. |
| threat_monitoring_malicious | Specify the malicious threat monitoring values. Supports comma separated values.<br/><br/>Supported values are: Matches Found, No Matches Found. |
| increase_severity_by | Specify the level in number by which to increase the XSOAR incident severity. Only applicable if match found for the malicious threat hunt or for the malicious threat monitoring of workload.<br/><br/>Note: The value can range from 1 to 4.<br/><br/>Example: If the current XSOAR incident severity is 1 \(Low\) and the script is set to increase the severity by 2, the XSOAR incident severity will be set to 3 \(high\). |

## Outputs

---
There are no outputs for this script.