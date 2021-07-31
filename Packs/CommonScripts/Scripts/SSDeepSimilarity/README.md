This script finds similar files that can be related to each other by fuzzy hash (SSDeep) .

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| ssdeep_hash | The SSDeep hash to check for similarity against. |
| ssdeep_hashes_to_compare | A list of SSDeep hashes to check for similarity to the ssdeep_hash input. |
| output_key | The context key to which the list of SSDeep hashes will be outputted. |

## Outputs
---
There are no outputs for this script.
