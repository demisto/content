Creates indicators from the submitted STIX file. Supports STIX 1.0 and STIX 2.x.
Wrapper for the **StixParser** automation. This automation creates indicators and adds an indicator's relationships if available.

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
| --- | --- |
| entry_id | The entry ID of the STIX file. |
| add_context | Adds indicators to context. |
| tags | A comma-separated list of tags to add to indicators.  |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| StixIndicators.type | Type of the indicator. | String |
| StixIndicators.value | Value of the indicator. | String |
| StixIndicators.tags | Tags of the indicator. | Unknown |
