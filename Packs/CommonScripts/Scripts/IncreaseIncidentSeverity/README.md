Increases the incident severity in the following manner:
If no argument is specified - increases the current incident severity by 1, or by 0.5 if the current severity is 0.5 (informational).
If an argument is specified - the incident severity will not be increased above the severity that was specified.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |

## Used In
---
This script is used in the following playbooks and scripts.
* LSASS Credential Dumpin
* PAN-OS to Cortex Data Lake Monitoring - Cron Job
* Powershell Payload Response

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| severity | The highest incident severity to increase the incident to. If no severity is specified, the severity will be increased by 1 unless it's already at 4. In the case that the severity is 0.5 \(informational\) - the seveirty will be increased by 0.5 \(to low\). |

## Outputs
---
There are no outputs for this script.
