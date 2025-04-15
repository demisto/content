Search war room entries for text results.  Results are placed in the search results buffer where they can be added to the LLM's conversation context

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| ids | CSV list of incident IDs to fetch war room entries |
| tags | war room entry tags to include |
| categories | war room entry categories to include |
| maxcontensize | filter out large entries when the content size exceeds this value. This minimizes data added to the LLM's conversation context where they may be a size limit depending on the LLM model being used |

## Outputs

---
There are no outputs for this script.
