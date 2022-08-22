Hello Ahikam Script
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | helloAhikam |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| name | Hello command \- prints hello to anyone. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HelloAhikam.hello | Should be Hello \*\*something\*\* here. | String |


## Script Example
```!HelloAhikamScript name=DBot```

## Context Example
```
{
    "HelloAhikam": {
        "hello": "Hello DBot"
    }
}
```

## Human Readable Output
## Hello DBot
