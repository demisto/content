Citrix Cloud Event Collector integration
This integration was integrated and tested with version xx of CitrixCloudEventCollector.

## Configure Citrix Cloud Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Client Id |  | True |
| Client Secret |  | True |
| Customer ID |  | True |
| Max events per fetch | The maximum amount of events to retrieve. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### citrix-cloud-get-events

***
Returns operation events extracted from Citrix.

#### Base Command

`citrix-cloud-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display the events. Possible values are: true, false. Default is false. | Required | 
| limit | The maximum number of operations to return. Default is 100. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!citrix-cloud-get-events limit=2```

#### Context Example

```json
{
    "CitrixCloud": {
        "Event": [
            {
                "RecordId": "1",
                "UtcTimestamp": "2020-07-20T14:26:59.6103585Z",
                "CustomerId": "hulk",
                "EventType": "delegatedadministration:administrator/create",
                "TargetId": "6233644161364977157",
                "TargetDisplayName": "[testcduser1@gmail.com](mailto:testcduser1@gmail.com)",
                "TargetEmail": "[testcduser1@gmail.com](mailto:testcduser1@gmail.com)",
                "TargetUserId": "a90b4449675f4fcf97e1663623334d74",
                "TargetType": "administrator",
                "BeforeChanges": null,
                "AfterChanges": {
                    "CustomerId": "hulk",
                    "Principal": "[testcduser1@gmail.com](mailto:testcduser1@gmail.com)",
                    "UserId": "6233644161364977157",
                    "AccessType": "Full",
                    "CreatedDate": "07/20/2020 14:26:53",
                    "UpdatedDate": "07/20/2020 14:26:53",
                    "DisplayName": "Rafa Doe",
                    "Pending": "False"
                },
                "AgentId": "delegatedadministration",
                "ServiceProfileName": null,
                "ActorId": null,
                "ActorDisplayName": "CwcSystem",
                "ActorType": "system",
                "Message": {
                    "en-US": "Created new administrator user."
                },
                "source_log_type": "systemlog",
                "_time": "2020-07-20T14:26:53Z",
                "_ENTRY_STATUS": "new"
            },
            {
                "RecordId": "2",
                "UtcTimestamp": "2020-07-20T14:26:59.6103585Z",
                "CustomerId": "hulk",
                "EventType": "delegatedadministration:administrator/create",
                "TargetId": "6233644161364977157",
                "TargetDisplayName": "[testcduser1@gmail.com](mailto:testcduser1@gmail.com)",
                "TargetEmail": "[testcduser1@gmail.com](mailto:testcduser1@gmail.com)",
                "TargetUserId": "a90b4449675f4fcf97e1663623334d74",
                "TargetType": "administrator",
                "BeforeChanges": null,
                "AfterChanges": {
                    "CustomerId": "hulk",
                    "Principal": "[testcduser1@gmail.com](mailto:testcduser1@gmail.com)",
                    "UserId": "6233644161364977157",
                    "AccessType": "Full",
                    "CreatedDate": "07/20/2020 14:26:53",
                    "UpdatedDate": "07/20/2020 14:26:53",
                    "DisplayName": "Rafa Doe",
                    "Pending": "False"
                },
                "AgentId": "delegatedadministration",
                "ServiceProfileName": null,
                "ActorId": null,
                "ActorDisplayName": "CwcSystem",
                "ActorType": "system",
                "Message": {
                    "en-US": "Created new administrator user."
                },
                "source_log_type": "systemlog",
                "_time": "2020-07-20T14:26:53Z",
                "_ENTRY_STATUS": "new"
            }
        ]
    }
}
```

#### Human Readable Output

>### Events List

>| ActorDisplayName        |ActorId|ActorType|AfterChanges|AgentId|BeforeChanges|CustomerId|EventType|Message|RecordId|ServiceProfileName|TargetDisplayName|TargetEmail|TargetId|TargetType|TargetUserId|UtcTimestamp|_ENTRY_STATUS|_time|source_log_type|
>|-------------------------|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| CwcSystem               |  | system | CustomerId: hulk<br>Principal: [testcduser1@gmail.com](mailto:testcduser1@gmail.com)<br>UserId: 6233644161364977157<br>AccessType: Full<br>CreatedDate: 07/20/2020 14:26:53<br>UpdatedDate: 07/20/2020 14:26:53<br>DisplayName: Rafa Doe<br>Pending: False | delegatedadministration |  | hulk | delegatedadministration:administrator/create | en-US: Created new administrator user '6233644161364977157'. | 1 |  | [testcduser1@gmail.com](mailto:testcduser1@gmail.com) | [testcduser1@gmail.com](mailto:testcduser1@gmail.com) | 6233644161364977157 | administrator | a90b4449675f4fcf97e1663623334d74 | 2020-07-20T14:26:59.6103585Z | new | 2020-07-20T14:26:53Z | systemlog |
>| CwcSystem |  | system | CustomerId: hulk<br>Principal: [testcduser1@gmail.com](mailto:testcduser1@gmail.com)<br>UserId: 6233644161364977157<br>AccessType: Full<br>CreatedDate: 07/20/2020 14:26:53<br>UpdatedDate: 07/20/2020 14:26:53<br>DisplayName: Rafa Doe<br>Pending: False | delegatedadministration |  | hulk | delegatedadministration:administrator/create | en-US: Created new administrator user '6233644161364977157'. | 2 |  | [testcduser1@gmail.com](mailto:testcduser1@gmail.com) | [testcduser1@gmail.com](mailto:testcduser1@gmail.com) | 6233644161364977157 | administrator | a90b4449675f4fcf97e1663623334d74 | 2020-07-20T14:26:59.6103585Z | new | 2020-07-20T14:26:53Z | systemlog |
