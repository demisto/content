This automation takes several incident fields from the RSA NetWitness incident context and displays them as markdown in the layout.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | dynamic-section |
| Cortex XSOAR Version | 6.2.0 |

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
    "RSA Alerts": [
        {
            "created": "2023-07-03T11:04:16.408Z",
            "detail": null,
            "events": [],
            "id": "dummy_id",
            "riskScore": "50",
            "source": "NetWitness Investigate",
            "title": "sk_test300",
            "type": "Log",
        },
        {
            "created": "2023-07-03T11:04:24.256Z",
            "detail": null,
            "id": "dummy_id",
            "riskScore": "50",
            "source": "NetWitness Investigate",
            "title": "sk_test300",
            "type": "Log",
        },
    ]
}
```

### Human Readable Output

### RSA Alerts\n"

    |created|detail|events|id|riskScore|source|title|type|
    |---|---|---|---|---|---|---|---|
    | 2023-07-03T11:04:16.408Z |  |  | dummy_id | 50 | NetWitness Investigate | sk_test300 | Log |
    | 2023-07-03T11:04:24.256Z |  |  | dummy_id | 50 | NetWitness Investigate | sk_test300 | Log |
