Verifies that a given object includes all the given fields.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| fields_to_search | Fields to search if they exist in map. |
| object | Map in which to search fields. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| FieldsExists | If true, all the given fields exist in the object. | boolean |

## Script Example
```!VerifyObjectFieldsList fields_to_search=name,type object=${Indicators}```

## Context Example
```json
{
    "CheckIfFieldsExists": {
        "FieldsExists": true
    }
}
```

## Human Readable Output

>### Results
> Fields name, type are in given context.

