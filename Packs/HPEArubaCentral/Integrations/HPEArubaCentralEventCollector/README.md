This is the Aruba Central event collector integration for Cortex XSIAM.

## Configure HPE Aruba Central Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**.
2. Search for HPE Aruba Central Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | Domain URL for API gateway access | True |
    | Client ID || True |
    | Client Secret || True |
    | Customer ID || True |
    | Username || True |
    | Password || True |
    | Fetch networking events | Whether to fetch networking events or only audit | False |
    | The maximum number of audit events per fetch (Max. allowed - 1,000) | Default - 100 | False |
    | The maximum number of networking events per fetch (Max. allowed - 5,000) | Default - 1000 | False |
    | Trust any certificate (not secure) || False |
    | Use system proxy settings || False |

4. Click **Test** to validate the URL, credentials and connection.

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aruba-central-get-events

***
Gets events from Aruba Central.

#### Base Command

`aruba-central-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. | Required | 
| from_date | Date from which to get events. Default is 3 hours prior | Optional | 

#### Context Output

There is no context output for this command.
