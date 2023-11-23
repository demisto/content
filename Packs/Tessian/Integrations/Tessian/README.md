Tessian is an email security platform that allows organizations to protect their users from inbound phishing threats, outbound data loss (both malicious and accidental) and account takeovers.

## Configure Tessian on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Tessian.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Portal URL | The URL that you use to access the Tessian Portal. Please include the extension, e.g. "example.tessian-platform.com" or "example.tessian-app.com" | True |
    | API Key | The API Key to use to connect to the Tessian API. This can be found under "Security Integrations" in your Tessian Portal \(/0/admin/integrations/api/tokens\) | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tessian-get-events

***
This command allows you to pull Tessian event data into your XSOAR instance.

#### Base Command

`tessian-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events you would like Tessian to return per call. The maximum value is 100. | Optional | 
| after_checkpoint | If provided, this parameter must be set to the checkpoint returned by a previous request to this endpoint. When provided, events from the previous request will not be included in the response from this request. If the new checkpoint returned by this request is used in yet another call to this endpoint events from both previous requests will not be included in the response (and so on). By making a number of consecutive requests to this endpoint where the checkpoint from the previous request is provided, clients can get all events from the Tessian platform, even when there are many more than can be returned in a single request. This process is often referred to as pagination. If an event is updated, it will no longer be excluded from subsequent requests. | Optional | 
| created_after | Only include events that were created after this time. For example, 2020-02-02T19:00:00Z. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tessian.EventsOutput.checkpoint | String | This value can be provided to a subsequent request via the after_checkpoint query parameter to ensure that events from this request are not returned in future responses. This allows clients to paginate through results. | 
| Tessian.EventsOutput.additional_results | Boolean | True if there may be more events that can be immediately retrieved. | 
| Tessian.EventsOutput.results | Unknown | The events returned by this request. | 

#### Command Example

`!tessian-get-evegit pnts limit=100 after_checkpoint="example-value" created_after="2020-02-02T19:00:00Z"`


### tessian-release-from-quarantine

***
This command allows you to release a quarantined email from Tessian.

#### Base Command

`tessian-release-from-quarantine`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The ID of the event you would like to release from quarantine. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tessian.ReleaseFromQuarantineOutput.number_of_actions_attempted | String | The number of users that release from quarantine actions were attempted for. | 
| Tessian.ReleaseFromQuarantineOutput.number_of_actions_succeeded | String | The number of users that the release from quarantine action was successful for. | 
| Tessian.ReleaseFromQuarantineOutput.results | Unknown | The results of the release action. This is an array of objects mapping the email address of users to the result of the release action. | 
| Tessian.ReleaseFromQuarantineOutput.event_id | String | The event ID that was submitted for release. | 

#### Command Example

`!tessian-release-from-quarantine event_id="id-from-tessian-get-events"
`

### tessian-delete-from-quarantine

***
This command allows you to delete a quarantined email from Tessian.

#### Base Command

`tessian-delete-from-quarantine`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The ID of the event you would like to delete from quarantine. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tessian.DeleteFromQuarantineOutput.number_of_actions_attempted | String | The number of users that delete from quarantine actions were attempted for. | 
| Tessian.DeleteFromQuarantineOutput.number_of_actions_succeeded | String | The number of users that the delete from quarantine action was successful for. | 
| Tessian.DeleteFromQuarantineOutput.results | Unknown | The results of the delete action. This is an array of objects mapping the email address of users to the result of the delete action. | 
| Tessian.DeleteFromQuarantineOutput.event_id | String | The event ID that was submitted for deletion. | 

#### Command Example

`!tessian-delete-from-quarantine event_id="id-from-tessian-get-events"`
