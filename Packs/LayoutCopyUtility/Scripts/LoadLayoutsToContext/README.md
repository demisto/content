Loads certain layout details to the context

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Add Layouts To Context

## Inputs
---
There are no inputs for this script.

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| XSOAR.Layouts | Layout Objects | unknown |
| XSOAR.Layouts.id | Id of the layout | string |
| XSOAR.Layouts.name | Name of the layout | string |
| XSOAR.Layouts.type | Type of the layout \(In the API it is called 'Group'\) | string |
| XSOAR.Layouts.tabs | Tabs of the layout | string |
| XSOAR.Layouts.tabs.id | Tab id | string |
| XSOAR.Layouts.tabs.name | Tab name | string |
| XSOAR.Layouts.tabs.sections | Tab Sections | Unknown |
| XSOAR.Layouts.tabs.sections.name | Section Name | Unknown |
