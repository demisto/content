Parse STIX files to Cortex XSOAR indicators by clicking the **Upload STIX File** button. This script is used for the button only. 
This script does not support indicators relationships creation.
In order to create indicators from STIX files using an automation, use **CreateIndicatorsFromSTIX**. This automation supports indicators relationships creation. 


## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | stix, ioc |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
|-------------------| --- |
| iocXml            | IOC XML or JSON in STIX format. |
| entry_id          | IOC file entry ID. |

## Outputs
---
There are no outputs for this script.
