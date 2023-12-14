Creates indicators from the submitted STIX file. Supports STIX 1.0 and STIX 2.x. This automation creates indicators and adds an indicator's relationships if available.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | stix, ioc |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* StixParser

## Used In

---
This script is used in the following playbooks and scripts.

* SolarStorm and SUNBURST Hunting and Response Playbook
* CreateIndicatorFromSTIXTest
* SolarStorm and SUNBURST Hunting and Response Playbook

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| entry_id | The entry ID of the STIX file. |
| add_context | Adds Indicators to context. |
| tags | Adds tags to Indicators. Comma separated. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| StixIndicators.type | Type of the Indicator | Unknown |
| StixIndicators.value | Value of the Indicator | Unknown |
| StixIndicators.tags | Tags of the Indicator | Unknown |
