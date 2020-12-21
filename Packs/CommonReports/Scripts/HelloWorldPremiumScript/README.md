Hello World Premium Script
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | helloworldpremium |
| Demisto Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| name | Hello command \- prints hello to anyone. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HelloWorldPremium.hello | Should be Hello \*\*something\*\* here. | String |


## Script Example
```!HelloWorldPremiumScript name=DBot```

## Context Example
```
{
    "HelloWorldPremium": {
        "hello": "Hello DBot"
    }
}
```

## Human Readable Output
## Hello DBot