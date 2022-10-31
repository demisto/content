Generate an ASM Alert Summary report.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| alert_name | Name of the Alert that triggered this playbook |
| alert_details | Details of the Alert that triggered this playbook |
| asmserviceowner | Potential service owners gathered through playbook. |
| asmremediation | Collect information on remediation action\(s\). |
| asmservicedetection | Pre/Post remediation scan to check if service is still detectable. |
| asmsystemids | Related system identifiers. |
| asmcloud | Information on cloud assets. |
| asmnotification | Information on notification\(s\) sent via the ASM playbook. |
| asmdatacollection | Collect information on data collection tasks. |
| asmtags | Tags from objects that can be used to determine other information \(if server is Dev for example\). |
| asmprivateip | Private IP addresses found. |
| asmrelated | Related or duplicate objects \(more of a nice to have because not sure how to track this\) |

## Outputs
---
There are no outputs for this script.
