Filters CVEs by CVSS minimum and intersection with a tech-stack tag list.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | darkmon |
| Cortex XSOAR Version | 6.5.0 |

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
| domains | Optional list of customer domains to filter domain-based matches. |
| brands_list | Name of the XSOAR List containing brand names for NRD brand-watch matching. |
| max_distance | Maximum Levenshtein distance allowed when matching NRD domains against brand names. |
| min_cvss | Minimum CVSS score threshold; CVEs below this value are excluded. |
| tech_stack_list | Name of the XSOAR List containing tech-stack tags used to filter CVEs by relevance. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| NewAccounts | Newly discovered account records that have not been previously actioned. | unknown |
| CreatedIncidents | Incidents created during this execution run. | unknown |
| Count | Total count of new items processed. | number |
| Typosquats | NRD domains identified as potential typosquats of monitored brand names. | unknown |
| FilteredCVEs | CVEs that passed the CVSS and tech-stack filters. | unknown |
| VIPCreated | Number of VIP-related incidents created during this execution. | number |
