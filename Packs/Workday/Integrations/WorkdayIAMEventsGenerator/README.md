IAM mock Workday full reports and events.

This integration is for testing propose only.
To use this integration for testing, take the server with the listening port that has been configured in the integration settings,
and configure the **Workday_IAM** instance with this url and invoke the *fetch_incidents*.

For more information about how to configure the long running integration go to [Long Running HTTP Integrations](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke).


This integration uses mock reports (simulates the real reports that are coming from Workday).
You can use the **generate-event** command to get all kinds of reports (hire, update, terminate and rehire)

## Configure Workday_IAM_Event_Generator on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Workday_IAM_Event_Generator.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | longRunning | Long running instance | False |
    | longRunningPort | Port mapping \(Port mapping (port or host port:docker port)) | False |
    | incidentType | Incident type | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### generate-event
***
Generate workday event.


#### Base Command

`generate-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_type | The event type. Possible values are: hire, update, terminate, rehire. | Required | 
| user_email | The user email for the event. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!generate-event event_type=hire ```

#### Human Readable Output
There is no Human Readable output for this command.


### initialize-context
***
Reset the integration context to fetch the first run reports.


#### Base Command

`initialize-context`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!initialize-context ```

#### Human Readable Output
The integration context has been initialized.

