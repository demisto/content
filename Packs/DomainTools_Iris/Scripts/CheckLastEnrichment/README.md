Check if DomainTools Data is in Need of Enrichment

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | DomainTools, Condition |
| Cortex XSOAR Version | 6.9.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| last_enrichment | Date domain was last enriched '%Y-%m-%d' |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| yes | Refresh Enrichment Data | String |
| no | Don't Refresh Enrichment Data | String |
