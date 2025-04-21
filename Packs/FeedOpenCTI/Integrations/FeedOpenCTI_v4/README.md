Ingest indicators from the OpenCTI feed. Compatible with OpenCTI 5.12.17 and above.
## Configure OpenCTI Feed 4.X in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL |  | True |
| API Key (leave empty. Fill in the API key in the password field.) |  | False |
| Indicator types to fetch | The indicator types to fetch. Out-of-the-box indicator types supported in XSOAR are: Account, Domain, Email, File, Host, IP, IPv6, Registry Key, and URL. Other types will not cause automatic indicator creation in XSOAR. | True |
| Max indicators per fetch |  | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will get this reputation. If none of the options is chosen, the indicator reputation will be set according to the indicator data. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. If none of the options is chosen, the TLP color will be set according to the indicator data. | False |
| Feed Fetch Interval |  | False |
| Tags | CSV values are supported. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Score minimum value | Score minimum value to filter by. Values range is 1-100.  | False |
| Score maximum value | Score maximum value to filter by. Values range is 1-100.  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### opencti-reset-fetch-indicators
***
WARNING: This command will reset your fetch history.


#### Base Command

`opencti-reset-fetch-indicators`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!opencti-reset-fetch-indicators```

#### Human Readable Output

>Fetch history deleted successfully

### opencti-get-indicators
***
Gets indicators from the feed.


#### Base Command

`opencti-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return per fetch. Default value is 50. Maximum value is 500. | Optional | 
| indicator_types | The indicator types to fetch. Out-of-the-box indicator types supported in XSOAR are: Account, Domain, Email, File, Host, IP, IPv6, Registry Key, and URL. Other types will not cause automatic indicator creation in XSOAR. Possible values are: ALL, Account, Domain, Email, File, Host, IP, IPv6, Registry Key, URL. Default is ALL. | Optional | 
| last_run_id | The last ID from the previous call, from which to begin pagination for this call. You can find this value at the OpenCTI.IndicatorsList.LastRunID context path. | Optional | 
| score_start | Score minimum value to filter by. Values range is 1-100. | Optional | 
| score_end | Score naximum value to filter by. Values range is 1-100. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!opencti-get-indicators limit=2 indicator_types="IP"```

#### Context Example
```json
{
    "OpenCTI": {
        "Indicators": {
            "IndicatorsList": [
                {
                    "createdBy": "1e12fe87-db3e-4838-8391-6910547bf60d",
                    "description": "test_desc",
                    "externalReferences": [],
                    "id": "700c8187-2dce-4aeb-bf3a-0864cb7b02c7",
                    "labels": [
                        "dev1"
                    ],
                    "marking": [
                        "TLP:AMBER"
                    ],
                    "score": 70,
                    "type": "IP",
                    "value": "1.2.3.4"
                },
                {
                    "createdBy": "1e12fe87-db3e-4838-8391-6910547bf60d",
                    "description": "test fetch one",
                    "externalReferences": [],
                    "id": "33bd535b-fa1c-41e2-a6f9-80d82dd29a9b",
                    "labels": [
                        "dev1",
                        "test-label-1"
                    ],
                    "marking": [],
                    "score": 100,
                    "type": "IP",
                    "value": "1.1.1.1"
                }
            ],
            "lastRunID": "YXJyYXljb25uZWN0aW9uOjI="
        }
    }
}
```

#### Human Readable Output

>### Indicators
>|type|value|id|
>|---|---|---|
>| IP | 1.2.3.4 | 700c8187-2dce-4aeb-bf3a-0864cb7b02c7 |
>| IP | 1.1.1.1 | 33bd535b-fa1c-41e2-a6f9-80d82dd29a9b |
