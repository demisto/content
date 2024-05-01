Use this script to display meta events inside the layout.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | dynamic-section |

## Inputs

---
There are no inputs for this script.

## Outputs

---
There are no outputs for this script.


## Script Examples

### Example command

```!SetRSANetWitnessAlertsMD```

### Context Example

```json
 {
    "Metas Events": [
        {
            "meta1": "value meta 1",
            "meta2": "value meta 2",
            "meta3": "value meta 3",
            "id": "dummy_id",
            "riskScore": "50",
            "source": "NetWitness Investigate",
            "title": "sk_test300",
            "type": "Log",
        }
    ]
}
```

### Human Readable Output

    |meta1|meta2|meta3|
    |---|---|---|
    | value meta 1 | value meta 2 | value meta 3 |