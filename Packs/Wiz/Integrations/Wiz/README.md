Agentless, context-aware and full-stack security and compliance for AWS, Azure and GCP.
This integration was integrated and tested with Wiz

## Configure Wiz on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Wiz. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | name | Integration Name. Default: `Wiz_instance_1` | True |
    | said | Service Account ID | True |
    | sasecret | Service Account Secret | True |
    | api_endpoint | API Endpoint. Default: `https://api.us1.app.wiz.io/graphql` <br /> To find your API endpoint URL: <br />1. Log in to Wiz, then open your <a href="https://app.wiz.io/user/profile">user profile</a> <br />2. Copy the **API Endpoint URL** to use here. | True
    | first_fetch | First fetch timestamp \(`<number>` `<time unit>`, e.g., 12 hours, 7 days\) | False |
    | streaming_type | Issue Streaming type.<br />Either `Wiz` (to push live Issues) or `XSOAR` (to constantly pull Issues)| False |
    | max_fetch | Max Issues to fetch | False |
    | proxy | Use system proxy settings | False |

3. Click **Test** to validate the API Endpoint, Service Account and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook or War Room.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### wiz-get-issues
***
Get the issues on cloud resources

<h4> Base Command </h4>

`wiz-get-issues`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_type | The type of Issue to get. | Optional | 
| resource_id | Get Issues of a specific resource_id.<br />Expected input: `providerId` | Optional | 
| severity | Get Issues of a specific severuty.<br />Expected input: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFORMATIONAL`.<br />The chosen severity and above will be fetched  | Optional | 
*Either `issue_type` or `resource_id` are required.*

<h4> Context Output </h4>

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Issues | String | All Issues | 


#### Command Example
```
!wiz-get-issues issue_type="VIRTUAL_MACHINE"
!wiz-get-issues resource_id="arn:aws:ec2:us-east-2:123456789098:instance/i-0g03j4h5gd123d456"
!wiz-get-issues resource_id="arn:aws:ec2:us-east-2:123456789098:instance/i-0g03j4h5gd123d456" severity=HIGH
```

### wiz-get-resource
***
Get Details of a resource.

<h4> Base Command </h4>

`wiz-get-resource`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | Resource provider id | Required | 


<h4> Context Output </h4>

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Resource | String | Resource details | 


#### Command Example
```
!wiz-get-resource resource_id="arn:aws:ec2:us-east-2:123456789098:instance/i-0g03j4h5gd123d456"
```