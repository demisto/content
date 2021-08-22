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
| query | Query used to check if there're are enough incidents in XSOAR. |
| size | Target amount of incidents to check for. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IncidentsCheck.Size | Number of incidents in XSOAR that're expected to match the query. | number |
| IncidentsCheck.ConditionMet | Are there enough incidents in XSOAR that match the query. | boolean |
| IncidentsCheck.Query | Incidents query used to check if the condition is met. | boolean |


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

