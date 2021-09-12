This script finds similar files that can be related to each other by fuzzy hash (SSDeep).

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
| output_key | The context key to which the list of SSDeep hashes will be outputted.<br/>In case used, the default outputs will not contain the results.<br/>In order to get results, replace the SSDeepSimilarity in default outputs with the output_key provided. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SSDeepSimilarity.compared_hashes.similarityValue | The difference calculation score between the ssdeep_hash and the compared hash. | number |
| SSDeepSimilarity.compared_hashes.hash | The hash compared to the ssdeep_hash. | string |

Please note the outputs are changed to use output_key instead of 'SSDeepSimilarity' if provided. 
