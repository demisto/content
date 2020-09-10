Calculates the entropy for the given data.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | entropy |
| Demisto Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| data | The data for which to calculate entropy. |
| minimum_entropy | The minimum entropy value. Default is 0. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EntropyResult.checked_value | The given value \(data\). | String |
| EntropyResult.entropy | The entropy score. | Number |


## Script Example
```!CalculateEntropy data=abcd```

## Context Example
```
{
    "EntropyResult": {
        "checked_value": "abcd",
        "entropy": 2
    }
}
```

## Human Readable Output
### Entropy results
|Checked Value|Entropy|
|---|---|
| abcd | 2.0 |

