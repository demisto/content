Builds the `setIncident` `addLabels` JSON string from a ***netskopev2-url-lookup*** result, joining nested `categories`/`url_lists` name arrays into flat comma-joined label values.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Netskope |

## Dependencies

---
This script uses the following commands and scripts.

* netskopev2-url-lookup

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| lookup_result | The Netskope.URLLookup context output (a list, or a single-element dict if XSOAR unwraps it) - bind this directly to ${Netskope.URLLookup}. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| NetskopeURLLookupLabels.labels_json | JSON string ready to pass as setIncident's addLabels argument. | String |
| NetskopeURLLookupLabels.summary | Human-readable summary of what was recorded. | String |
