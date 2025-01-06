This is the Zero Networks event collector integration for Cortex XSIAM.

## Configure Zero Networks Segment Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Key | The API key to use for connection. | True |
| Fetch network events |  | False |
| Network Activity Filters | Use filters to reduce the amount of events. | False |
| Maximum audit events to fetch | Maximum number of audit events per fetch. The default value is 10000. | False |
| Maximum network activities events to fetch | Maximum number of network activities events per fetch. The default value is 2000. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### zero-networks-segment-get-events

***
Gets events from Zero Networks Segment.

#### Base Command

`zero-networks-segment-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Warning: Using this argument may lead to duplicate events. Possible values are: true, false. Default is false. | Required |
| from_date | Date from which to get events. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!zero-networks-segment-get-events from_date="2024-08-29T12:00:15.000Z"```

#### Human Readable Output

### Audit Events

| timestamp | auditType | destinationEntitiesList | details | enforcementSource | isoTimestamp |
|--------|---------------|---------------------------------|---------------------|----------------------|
| 1724928222479 | 1 | {"id": "fake_id"} | {"rule":"fake_rule", "id":"fake_id"} | 1 | 2024-08-29T10:43:42.479Z |

### Network Activities Events

| timestamp | protocol | state | trafficType | dst | src |
|-------------|---------------------|------------|----------------------|---------|---------|
| 1724924207581 | 6 | 2 | 1 | {"assetId":"fake_dst", "ip":"1.2.3.4"} | {"assetId":"fake_src", "ip":"1.1.1.1"} |