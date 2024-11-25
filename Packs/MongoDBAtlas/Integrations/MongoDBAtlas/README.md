MongoDB Atlas is an integration that supports fetching and managing alerts and events within Cortex XSIAM.

This integration was integrated and tested with version 2.0 of MongoDB Atlas.

## Configure MongoDB Atlas on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for MongoDB Atlas.
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

### To create an API key for a project using the MongoDB Atlas UI:

1. Log in to MongoDB Atlas.
2. Click **Access Manager** in the navigation bar, then click your project.
3. Navigate to **Applications**.
4. Click **Create Application** and then click **API Key**.
5. Enter a **Description** and set **Project Permissions**. For reading alerts and events, you can set the Project Permissions to "Read Only".
6. Copy and save the **Public Key**. The public key acts as the username when making API requests.
7. Copy and save the **Private Key**. The private key acts as the password when making API requests.

    **WARNING**: Save the Private Key securely! The Private Key is only displayed once on this page. Click **Copy** to copy it to your clipboard. Save and secure both the Public and Private Keys.
8. Add an API Access List Entry by clicking **Add Access List Entry**.
9. Enter an IP address from which MongoDB Atlas should accept API requests for this API Key. You can also click **Use Current IP Address** if the host you are using to access MongoDB Atlas will also make API requests using this API Key.
10. Click **Save**.
11. Click **Done**.

### IMPORTANT

You need to allow access from Cortex XSIAM to MongoDB via the UI by adding a Cortex XSIAM IP address:
https://cloud.mongodb.com/v2/<customer_organization_id>#/security/network/accessList 


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