MongoDBAtlas is an integration that supports fetching and managing alerts and events within Cortex XSIAM.

This integration was integrated and tested with version 2.0 of MongoDB Atlas.

## Configure MongoDBAtlas on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**.
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

4. Click **Test** to validate the URLs, keys, and connection.


## Additional Information
Groups and projects are synonymous terms. Your group ID is the same as your project ID. For existing groups, your group/project ID remains the same. The resource and corresponding endpoints use the term groups.

### Authentication and authorization:
#### Grant Programmatic Access to a Project
Use the following procedures to grant programmatic access to a project. 
To learn more, see [Manage Programmatic Access to a Project](https://www.mongodb.com/docs/atlas/configure-api-access-project/#std-label-atlas-admin-api-access-project).


## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
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
| limit | Maximum number of events to return. Value range: 1-2500.| Required | 

#### Context Output

| **Path**     | **Type** | **Description** |
|--------------|------| --- |
| MongoDBAtlas | List | The list of the events and the alerts. | 