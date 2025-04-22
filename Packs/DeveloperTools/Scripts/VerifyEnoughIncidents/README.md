Check whether a given query returns enough incidents.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| query | Query used to check whether there are sufficient incidents in Cortex XSOAR. |
| size | The amount of incidents in which to check. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IncidentsCheck.Size | The number of incidents in Cortex XSOAR that is expected to match the query. | number |
| IncidentsCheck.ConditionMet | Whether there are sufficient incidents in Cortex XSOAR that match the query. | boolean |
| IncidentsCheck.Query | The incidents query which was used to check if the condition was met. | boolean |


## Script Example
```!VerifyEnoughIncidents query="sourceInstance:Some_Integration_instance_1" size="1"```

## Context Example
```json
{
    "IncidentsCheck": {
        "ConditionMet": true,
        "Query": "sourceInstance:Some_Integration_instance_1",
        "Size": 1
    }
}
```

## Human Readable Output

>### Results
>|ConditionMet|Query|Size|
>|---|---|---|
>| true | sourceInstance:Some_Integration_instance_1 | 1 |

