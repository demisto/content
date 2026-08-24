For each NRD, calls DarkmonLevenshtein against the brands list and emits Typosquats with distance <= max_distance.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | darkmon |
| Cortex XSOAR Version | 6.5.0 |

## Dependencies

---
This script uses the following commands and scripts.

* DarkmonLevenshtein

## Used In

---
This script is used in the following playbooks and scripts.

* Darkmon - Brand-Targeted NRD Watch

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| items | Items to process. |
| id_field | Field name to use as the dedup key. |
| seen_list | Name of the XSOAR List storing already-seen IDs. |
| domain_filter_list | Optional - list of customer domains to filter username matches. |
| domain_match_field | Field on each item to match against domain_filter_list. |
| allowlist | Optional list of usernames/DNs that must NEVER be actioned. |
| allowlist_match_field | Field to match against the allowlist. |
| incident_type | Incident type for newly created incidents. |
| severity | Severity \(1=Low, 2=Medium, 3=High, 4=Critical\). |
| name_template | Incident name template \(supports $\{field\} interpolation\). |
| field_map | Comma-separated 'fieldCli=sourcePath' pairs. |
| emails | Email addresses to fan out per VIP fetch. |
| domains |  |
| brands_list |  |
| max_distance |  |
| min_cvss |  |
| tech_stack_list |  |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| NewAccounts |  | unknown |
| CreatedIncidents |  | unknown |
| Count |  | number |
| Typosquats |  | unknown |
| FilteredCVEs |  | unknown |
| VIPCreated |  | number |
