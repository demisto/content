Hello World Script
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | helloworld |
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
| HelloWorld.hello | Should be Hello \*\*something\*\* here. | String |


## Script Example
```!HelloWorldScript name=DBot```

## Context Example
```
{
    "HelloWorld": {
        "hello": "Hello DBot"
    }
}
```

## Human Readable Output
## Hello DBot
