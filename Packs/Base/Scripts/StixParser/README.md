Parse Stix files to Demisto indicators using `Upload STIX File` button. This script is used for the button only. 
This script is not supporting indicators relationships creation.
In order to create indicators from STIX files using automation, please use `CreateIndicatorsFromSTIX`, this automation supports indicators relationships creation. 


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
| iocXml            | ioc xml or json in stix format. |
| entry_id          | ioc file entry id. |

## Outputs
---
There are no outputs for this script.
