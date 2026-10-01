Dummy event collector (managed-content pack, MANAGED variant) that generates fake events for Cortex XSIAM. No external API is called.

Events are sent to the `dummy_collector_raw` dataset (vendor `dummy`, product `collector`). Each event contains the fields `id`, `collector_source`, `integration_id`, `pack_name`, `event_type`, `severity`, `user`, `source_ip`, `message`, and `created_time`.

## Configure Dummy Managed Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Max number of events per fetch | The number of fake events to generate in each fetch. Default is 5. | False |

Set the events fetch interval to 1 minute to receive a new batch of events every minute.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dummy-managed-get-events

***
Generates dummy events. Used for development and debugging.

#### Base Command

`dummy-managed-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Optional |
| limit | Maximum number of events to generate. Default is 5. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!dummy-managed-get-events limit=1 should_push_events=false```

#### Human Readable Output

>### Dummy Events (managed)
>
>|collector_source|created_time|event_type|id|integration_id|message|pack_name|severity|source_ip|user|
>|---|---|---|---|---|---|---|---|---|---|
>| managed | 2026-09-30T10:00:00Z | login | 1 | DummyManagedEventCollector | [managed] Dummy event #1 | DummyCollectorManaged | low | 10.1.2.3 | user1@dummy.local |
