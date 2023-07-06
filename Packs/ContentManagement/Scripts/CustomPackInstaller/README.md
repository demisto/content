Custom Packs Installer for the Content Management pack.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | configuration, Content Management |
| Cortex XSOAR Version | 6.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Configuration Setup

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| pack_id | The ID of the pack to install. |
| skip_verify | if true will skip pack signature validation, Available from 6.5.0 server version. |
| skip_validation | if true will skip all pack validations, use this flag just to migrate from custom content entities to custom content packs, Available from 6.6.0 server version. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ConfigurationSetup.CustomPacks.installationstatus | The installtion status of the required pack. | Unknown |
