Transform an indicator in Cortex into a CrowdStrike Falcon IOC.
The output (found at the TransformIndicatorToCSFalconIOC.JsonOutput context path) is a JSON, which represents the indicators in CrowdStrike Falcon format.
This JSON can be used as the input for the *cs-falcon-batch-upload-custom-ioc* command. (Available from Cortex XSOAR 6.0.0).

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
| query | The indicators query. Using `GetIndicatorsByQuery` automation. <br/>Example: `type:IP and lastSeen:>="2022-02-16T16:20:00 +0200"`. |
| action | The action that will be taken if the indicator will be discovered in the organization. |
| limit | The maximum number of indicators to fetch. |
| offset | The results offset page. Only change when the number of the results exceed the limit. |
| host_groups | List of host group IDs that the indicator applies to. <br/>Can be retrieved by running the cs-falcon-list-host-groups command.<br/>Either applied_globally or host_groups must be provided. |
| platforms | The platforms that the indicator applies to. |
| applied_globally | Whether the indicator is applied globally. <br/>Either applied_globally or host_groups must be provided. Default set to True. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TransformIndicatorToCSFalconIOC | Json output of the indicators. Should be the input for the \*cs-falcon-batch-upload-custom-ioc\*. | String |
| TransformIndicatorToCSFalconIOC.Indicators.value | The value of the Indicator. | String |
| TransformIndicatorToCSFalconIOC.Indicators.expiration | The date on which the indicator will become inactive. | String |
| TransformIndicatorToCSFalconIOC.Indicators.description | Descriptive label for the indicator. | String |
| TransformIndicatorToCSFalconIOC.Indicators.tags | List of tags of the indicator. | Unknown |
| TransformIndicatorToCSFalconIOC.Indicators.source | The source where this indicator originated. | String |
| TransformIndicatorToCSFalconIOC.Indicators.id | The ID of the indicator. | String |
| TransformIndicatorToCSFalconIOC.Indicators.type | Type of the indicator. Possible values are: md5, sha256, ipv4, ipv6 and domain. | String |
| TransformIndicatorToCSFalconIOC.Indicators.severity | The severity of the indicator. possible values are: Informational, Low, Medium, High and Critical. | String |
| TransformIndicatorToCSFalconIOC.Indicators.action | The action that will be taken if the indicator will be discovered in the organization. | String |
| TransformIndicatorToCSFalconIOC.Indicators.applied_globally | Whether the indicator is applied globally. | Boolean |
| TransformIndicatorToCSFalconIOC.Indicators.platforms | The platforms that the indicator applies to. | Unknown |
| TransformIndicatorToCSFalconIOC.Indicators.host_groups | List of host group IDs that the indicator applies to. | Unknown |



## Script Examples
### Example command
```!TransformIndicatorToCSFalconIOC query="type:IP" action=no_action platforms=linux```
### Context Example
```json
{
    "TransformIndicatorToCSFalconIOC": {
        "Indicators": [
            {
                "Severity": "Informational",
                "Tags": [
                    "test"
                ],
                "action": "no_action",
                "applied_globally": true,
                "expiration": "2022-02-16T13:02:26Z",
                "platforms": [
                    "linux"
                ],
                "source": "Cortex",
                "type": "ipv4",
                "value": "9.6.3.5"
            },
            {
                "Severity": "Informational",
                "action": "no_action",
                "applied_globally": true,
                "expiration": "2022-02-22T13:36:02.776329896Z",
                "platforms": [
                    "linux"
                ],
                "source": "Cortex",
                "type": "ipv4",
                "value": "4.6.8.7"
            },
            {
                "Severity": "Informational",
                "action": "no_action",
                "applied_globally": true,
                "expiration": "2022-02-22T13:41:02.960974457Z",
                "platforms": [
                    "linux"
                ],
                "source": "Cortex",
                "type": "ipv4",
                "value": "4.7.8.7"
            },
            {
                "Severity": "Informational",
                "action": "no_action",
                "applied_globally": true,
                "expiration": "2022-02-22T13:41:02.960919913Z",
                "platforms": [
                    "linux"
                ],
                "source": "Cortex",
                "type": "ipv4",
                "value": "9.1.4.8"
            },
            {
                "Severity": "Informational",
                "action": "no_action",
                "applied_globally": true,
                "expiration": "2022-02-22T13:36:02.776389915Z",
                "platforms": [
                    "linux"
                ],
                "source": "Cortex",
                "type": "ipv4",
                "value": "2.1.4.8"
            },
            {
                "Severity": "Informational",
                "action": "no_action",
                "applied_globally": true,
                "expiration": "2022-02-16T13:02:46Z",
                "platforms": [
                    "linux"
                ],
                "source": "Cortex",
                "type": "ipv4",
                "value": "4.5.8.9"
            }
        ],
        "JsonOutput": "[{\"expiration\": \"2022-02-16T13:02:26Z\", \"type\": \"ipv4\", \"Severity\": \"Informational\", \"Tags\": [\"test\"], \"value\": \"9.6.3.5\", \"action\": \"no_action\", \"source\": \"Cortex\", \"platforms\": [\"linux\"], \"applied_globally\": true}, {\"expiration\": \"2022-02-22T13:36:02.776329896Z\", \"type\": \"ipv4\", \"Severity\": \"Informational\", \"value\": \"4.6.8.7\", \"action\": \"no_action\", \"source\": \"Cortex\", \"platforms\": [\"linux\"], \"applied_globally\": true}, {\"expiration\": \"2022-02-22T13:41:02.960974457Z\", \"type\": \"ipv4\", \"Severity\": \"Informational\", \"value\": \"4.7.8.7\", \"action\": \"no_action\", \"source\": \"Cortex\", \"platforms\": [\"linux\"], \"applied_globally\": true}, {\"expiration\": \"2022-02-22T13:41:02.960919913Z\", \"type\": \"ipv4\", \"Severity\": \"Informational\", \"value\": \"9.1.4.8\", \"action\": \"no_action\", \"source\": \"Cortex\", \"platforms\": [\"linux\"], \"applied_globally\": true}, {\"expiration\": \"2022-02-22T13:36:02.776389915Z\", \"type\": \"ipv4\", \"Severity\": \"Informational\", \"value\": \"2.1.4.8\", \"action\": \"no_action\", \"source\": \"Cortex\", \"platforms\": [\"linux\"], \"applied_globally\": true}, {\"expiration\": \"2022-02-16T13:02:46Z\", \"type\": \"ipv4\", \"Severity\": \"Informational\", \"value\": \"4.5.8.9\", \"action\": \"no_action\", \"source\": \"Cortex\", \"platforms\": [\"linux\"], \"applied_globally\": true}]"
    }
}
```

### Human Readable Output

>### TransformIndicatorToCSFalconIOC is done:
>|value|expiration|Severity|Tags|type|
>|---|---|---|---|---|
>| 9.6.3.5 | 2022-02-16T13:02:26Z | Informational | test | ipv4 |
>| 4.6.8.7 | 2022-02-22T13:36:02.776329896Z | Informational |  | ipv4 |
>| 4.7.8.7 | 2022-02-22T13:41:02.960974457Z | Informational |  | ipv4 |
>| 9.1.4.8 | 2022-02-22T13:41:02.960919913Z | Informational |  | ipv4 |
>| 2.1.4.8 | 2022-02-22T13:36:02.776389915Z | Informational |  | ipv4 |
>| 4.5.8.9 | 2022-02-16T13:02:46Z | Informational |  | ipv4 |

