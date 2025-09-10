This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Citrix Daas Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Client Id |  | True |
| Client Secret |  | True |
| Customer ID |  | True |
| Cloud Instance (Site) ID |  | True |
| Max events per fetch | The maximum amount of events to retrieve. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### citrix-daas-get-events

***
Returns operation events extracted from Citrix.

#### Base Command

`citrix-daas-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display the events. Possible values are: true, false. Default is false. | Required | 
| limit | The maximum number of operations to return. Default is 100. | Optional | 
| search_date_option | Specific time filters for searching operations. Possible values are: LastMinute, Last5Minutes, Last30Minutes, LastHour, Last12Hours, Last24Hours, Today, Yesterday, Last7Days, Last28Days, LastMonth, LastThreeMonths, LastSixMonths. Default is LastMinute. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!citrix-daas-get-events limit=2```

#### Context Example

```json
{
    "CitrixDaas": {
        "Event": [
            {
                "Id": "0",
                "Text": "string",
                "User": "string",
                "UserIdentity": "string",
                "Source": "string",
                "AdminMachineIP": "string",
                "EndTime": "2024-01-02T13:22:36.848+00:00",
                "FormattedEndTime": "2024-01-02T13:22:36Z",
                "StartTime": "2024-01-02T13:22:36.614+00:00",
                "FormattedStartTime": "2025-09-03T13:22:36Z",
                "IsSuccessful": true,
                "TargetTypes": [
                    "string"
                ],
                "OperationType": "Unknown",
                "Labels": [
                    "string"
                ],
                "Metadata": [
                    {
                        "Name": "Name",
                        "Value": "Value"
                    }
                ],
                "Parameters": [
                    {
                        "Name": "Name",
                        "Value": "Value"
                    }
                ],
                "source_log_type": "configlog",
                "_time": "2025-09-03T13:22:36Z"
            },
            {
                "Id": "1",
                "Text": "string",
                "User": "string",
                "UserIdentity": "string",
                "Source": "string",
                "AdminMachineIP": "string",
                "EndTime": "2024-01-02T13:22:36.848+00:00",
                "FormattedEndTime": "2024-01-02T13:22:36Z",
                "StartTime": "2024-01-02T13:22:36.614+00:00",
                "FormattedStartTime": "2025-09-03T13:22:36Z",
                "IsSuccessful": true,
                "TargetTypes": [
                    "string"
                ],
                "OperationType": "Unknown",
                "Labels": [
                    "string"
                ],
                "Metadata": [
                    {
                        "Name": "Name",
                        "Value": "Value"
                    }
                ],
                "Parameters": [
                    {
                        "Name": "Name",
                        "Value": "Value"
                    }
                ],
                "source_log_type": "configlog",
                "_time": "2025-09-03T13:22:36Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Events List

> |AdminMachineIP|EndTime|FormattedEndTime|FormattedStartTime|Id|IsSuccessful|Labels|Metadata|OperationType|Parameters|Source|StartTime|TargetTypes|Text|User|UserIdentity|_time|source_log_type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| string | 2024-01-02T13:22:36.848+00:00 | 2024-01-02T13:22:36Z | 2025-09-03T13:22:36Z | 0 | true | string | {'Name': 'Name', 'Value': 'Value'} | Unknown | {'Name': 'Name', 'Value': 'Value'} | string | 2024-01-02T13:22:36.614+00:00 | string | string | string | string | 2025-09-03T13:22:36Z | configlog |
>| string | 2024-01-02T13:22:36.848+00:00 | 2024-01-02T13:22:36Z | 2025-09-03T13:22:36Z | 1 | true | string | {'Name': 'Name', 'Value': 'Value'} | Unknown | {'Name': 'Name', 'Value': 'Value'} | string | 2024-01-02T13:22:36.614+00:00 | string | string | string | string | 2025-09-03T13:22:36Z | configlog |
