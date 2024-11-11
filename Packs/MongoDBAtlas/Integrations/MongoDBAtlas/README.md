MongoDBAtlas is integration that supports fetching and managing alerts and events within XSIAM.
This integration was integrated and tested with version 2.0 of MongoDB Atlas.

## Configure MongoDBAtlas on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MongoDBAtlas.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | The endpoint URL. | True |
    | Public Key | The Public Key to use for connection. | True |
    | Private Key | The Private Key to use for connection. | True |
    | Group ID | The Project ID from MongoDB Atlas account. | True |
    | Maximum number of events per fetch | Defines the maximum number of alerts or events fetched per type in each fetch cycle. Default value: 2500. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### mongo-db-atlas-get-events

***
Retrieves a list of events from the MongoDB Atlas instance.

#### Base Command

`mongo-db-atlas-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of events to return. | Required | 

#### Context Output

There is no context output for this command.
