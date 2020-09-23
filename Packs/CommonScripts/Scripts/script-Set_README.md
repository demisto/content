Set a value in context under the key you entered.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| key | The key to set. Can be a full path such as "Key.ID". If using append=true can also use a DT selector such as "Data\(val.ID == obj.ID\)". |
| value | The value to set to the key. Can be an array. |
| append | If false then then the context key will be overwritten. If set to true then the script will append to existing context key. |
| stringify | Whether the argument should be saved as a string. |

## Outputs
---
There are no outputs for this script.


## Script Example
```!Set key="Data(val.ID == obj.ID)" value=`{"ID": "test_id", "Value": "test_val2"}` append="true"```

## Context Example
```json
{
    "Data": {
        "ID": "test_id",
        "Value": "test_val2"
    }
}
```

## Human Readable Output
Key Data(val.ID == obj.ID) set
