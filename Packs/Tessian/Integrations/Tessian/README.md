Tessian is an email security platform that allows organizations to protect their users from inbound phishing threats, outbound data loss (both malicious and accidental) and account takeovers.
This integration was integrated and tested with version xx of Tessian.

## Configure Tessian on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Tessian.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Portal URL | The URL that you use to access the Tessian Portal. Please include the extension, e.g. "example.tessian-platform.com" or "example.tessian-app.com" | True |
    | API Key | The API Key to use to connect to the Tessian API. This can be found under "Security Integrations" in your Tessian Portal \(/0/admin/integrations/api/tokens\) | True |
    | Password |  | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### get_events

***
This command allows you to pull Tessian event data into your XSOAR instance.

#### Base Command

`get_events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events you would like Tessian to return per call. | Optional | 
| after_checkpoint | If provided, this parameter must be set to the checkpoint returned by a previous request to this endpoint. When provided, events from the previous request will not be included in the response from this request. If the new checkpoint returned by this request is used in yet another call to this endpoint events from both previous requests will not be included in the response (and so on). By making a number of consecutive requests to this endpoint where the checkpoint from the previous request is provided, clients can get all events from the Tessian platform, even when there are many more than can be returned in a single request. This process is often referred to as pagination. If an event is updated, it will no longer be excluded from subsequent requests. | Optional | 
| created_after | Only include events that were created after this time. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tessian.EventsOutput.checkpoint | String | This value can be provided to a subsequent request via the after_checkpoint query parameter to ensure that events from this request are not returned in future responses. This allows clients to paginate through results. | 
| Tessian.EventsOutput.additional_results | Boolean | True if there may be more events that can be immediately retrieved. | 
