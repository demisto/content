Given an integration name, returns the instance name.

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
| integration_name | Integration name for which to check its instance name. |
| return_all_instances | Whether to return a full list of instance names related to the given integation name. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Instances.integrationName | Requested integration name. | String |
| Instances.instanceName | Instance name for given integration. | String |


## Script Example
```!GetInstanceName integration_name="HelloWorld Feed"```

## Context Example
```json
{
    "Instances": {
        "instanceName": "HelloWorld Feed_instance_1",
        "integrationName": "HelloWorld Feed"
    }
}
```

## Human Readable Output

>### Results
>|instanceName|integrationName|
>|---|---|
>| HelloWorld Feed_instance_1 | HelloWorld Feed |

