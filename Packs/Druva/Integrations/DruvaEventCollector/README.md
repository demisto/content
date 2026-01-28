This is the Druva event collector integration for Cortex XSIAM.

## Configure Druva Event Collector in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Client ID | True |
| Secret Key | True |
| Trust any certificate (not secure) |  |
| Use system proxy settings |  |
| The maximum number of events per fetch per type |  |
| Events to fetch |  |

### Additional Information

- **The maximum number of events per fetch**: The default value is 10,000. The API only returns up to 500 events at a time without limiting capabilities, so it is best to enter this parameter in multiples of 500.
- **Resetting event fetching**: Note that resetting the event fetching (clearing the integration context) will cause duplicate events to be fetched, as the integration will restart the fetch process from the beginning.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### druva-get-events

***
Gets events from Druva API in one batch (max 500). If tracker is given, only its successive events will be fetched.

#### Base Command

`druva-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to true in order to create Cortex XSIAM events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required |
| tracker | A string received in a previous run, marking the point in time from which we want to fetch. For InSync events, this is a tracker. For Cybersecurity events, this is a pageToken. | Optional |
| event_types | The types of events to fetch. Possible values are: InSync events, Cybersecurity events. Default is InSync events. | Optional |

#### Context Output

There is no context output for this command.
