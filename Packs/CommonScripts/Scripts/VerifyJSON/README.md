Verifies if the supplied JSON string is valid and optionally verifies against a provided schema. The script utilizes Powershell's Test-JSON cmdlet.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | powershell |
| Tags | JSON, Utility |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| json | JSON string to verfiy. |
| schema | Optional schema against which to validate the JSON input. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| VerifyJSON.Result | Whether the passed JSON was verified. | boolean |


## Script Example
```!VerifyJSON json={"alert_id":"695b3238-05d6-4934-86f5-9fff3201aeb0"}```

## Context Example
```
{
    "VerifyJSON": {
        "Result": true
    }
}
```

## Human Readable Output
Verify JSON completed successfully
