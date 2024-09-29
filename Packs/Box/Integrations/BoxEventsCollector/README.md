# Box Event Collector

Collect events from Box's logs.

## Permissions

The command is using the [events endpoint](https://developer.box.com/reference/get-events/) with enterprise login.
The user making the API call will need to have admin privileges, and the application will need to have the scope manage enterprise properties checked.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Box Event Collector in Cortex

To acquire the "Credential JSON", you need to get a JWT token and an app from Box.
You can use the guide from [Box V2](https://xsoar.pan.dev/docs/reference/integrations/box-v2#configure-the-box-application-to-interface-with-xsoar) to get those credentials.


| **Parameter** | **Required** |
| --- | --- |
| Verify SSL Certificate | False |
| Credentials JSON | True |
| Fetch Events | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
| The maximum amount of events to fetch at once. 500 is maximum | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### box-get-events

***
Get events.

#### Base Command

`box-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum events to fetch. Default is 10. | Optional |
| created_after | Fetch events from this time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). Default is 3 days. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!box-get-events limit=1 created_after="30 days"```

#### Context Example

```json
{
    "BoxEvents": {
        "action_by": null,
        "additional_details": null,
        "created_at": "2022-04-10T05:39:15-07:00",
        "created_by": {
            "id": "00000000000",
            "login": "johndoe@example.com",
            "name": "John Doe",
            "type": "user"
        },
        "event_id": "event_id",
        "event_type": "ADD_LOGIN_ACTIVITY_DEVICE",
        "ip_address": "ip_address",
        "session_id": null,
        "source": {
            "id": "00000000000",
            "login": "johndoe@example.com",
            "name": "John Doe",
            "type": "user"
        },
        "type": "event"
    }
}
```

#### Human Readable Output

>### Results

>|action_by|additional_details|created_at|created_by|event_id|event_type|ip_address|session_id|source|type|
>|---|---|---|---|---|---|---|---|---|---|
>|  |  | 2022-04-10T05:39:15-07:00 | type: user<br/>id: 0000000000<br/>name: John Doe<br/>login: johndoe@example.com | event_id | ADD_LOGIN_ACTIVITY_DEVICE | ip_address |  | type: user<br/>id: 0000000000<br/>name: John Doe<br/>login: johndoe@example.com | event |