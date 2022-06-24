Call a Twilio Flow to start an Emergency Call
This integration was integrated and tested with version xx of Twilio Emergency Calls Flow

## Configure Twilio Emergency Calls Flow on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Twilio Emergency Calls Flow.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://studio.twilio.com/v2/Flows/) | False |
    | Account SID | True |
    | Auth token | True |
    | Call Flow ID | True |
    | Default sending number (e.g. +123456789101) | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### emergency-call
***
Starts an emergency call for the specified destination number


#### Base Command

`emergency-call`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | Phone number of Call receiver (e.g. +123456789101). | Required | 
| incident_id | Incident to inform the called number about. | Required | 
| assignee | The Cortex XSOAR to assign the incident to. | Required | 
| from | Phone number of Call starter (e.g. +123456789101). | Optional | 
| ttsMessage | The text message to be used in TTS. Default is Questa è una chiamata generata dal SOC BNL, riguarda l'incident {0},  premi un numero qualsiasi per prendere in carico la chiamata, altrimenti premi cancelletto. | Optional | 
| ttsMessageArgs | Args to format the ttsMessage with. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


