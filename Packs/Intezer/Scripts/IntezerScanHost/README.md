Scans the Intezer host.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Intezer - scan host

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| host | Computer name. |
| os | OS |
| intezer_api_key | Intezer API key. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Intezer.Analysis.ID | Endpoint analysis ID.  | string |
