Use the CrowdStrike API integration to interact with CrowdStrike APIs that do not have dedicated integrations in Cortex XSOAR, for example, CrowdStrike FalconX, etc.

---

Note: In this documentation, we will use the [Incident and detection monitoring APIs](https://falcon.crowdstrike.com/support/documentation/86/detections-monitoring-apis) as an example.

## Authorization
To use the CrowdStrike API integration, you need the ID and secret of an API client that has right scopes granted to it.

For details, refer to the [CrowdStrike OAuth2-Based APIs documentation](https://falcon.crowdstrike.com/support/documentation/46/crowdstrike-oauth2-based-apis).

**Note**: The integration stores in cache the API access token based on the permissions it is first run with, so if the permissions are modified, it is recommended to create a new instance of the integration.

## Configure CrowdStrike API on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CrowdStrike API.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Required** |
| --- | --- |
| Cloud Base URL | True |
| Client ID | True |
| Client Secret | False |
| Trust any certificate \(not secure\) | False |
| Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute the command from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cs-api-request
***
Run a CrowdStrike API query.


#### Base Command

`cs-api-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | The endpoint to refer to in CrowdStrike API.| Required |
| http_method | The HTTP method used for the request to CrowdStrike API. Possible values are: "GET", "POST", "DELETE", "PUT", or "PATCH". Default is "GET". | Optional |
| request_body | The request body (required for POST queries) in JSON format. | Optional |
| query_parameters | The URL query parameters in JSON format, e.g., {"limit":1}. | Optional |
| populate_context | If "true", will populate the API response to the context data. Default is "true". | Optional | 


#### Context Output

The context data output depends on the resource executed.
The *populate_context* argument sets whether to output to the context data, under the path **CrowdStrike.{ENDPOINT}**.
For resources which return a large response, we recommend narrowing the results by using the *query_parameters* argument or outputting to the context data using [Extend Context](https://xsoar.pan.dev/docs/playbooks/playbooks-extend-context).


## Usage
Let's say we want to [find behaviors](https://assets.falcon.crowdstrike.com/support/api/swagger.html#/incidents/QueryBehaviors).

We can see that:
 - The HTTP method is ***GET***
 - The endpoint is ***/incidents/queries/behaviors/v1***
 
So in order to find behaviors using the integration, we would run the command: `!cs-api-request endpoint=/incidents/queries/behaviors/v1 http_method=GET`
