PhishUp prevents phishing attacks, protects your staff and your brand with AI

## Configure PhishUp on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for PhishUp.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API KEY |  | True |
    | Incident type |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | PhishUp Playbook Actions | If there is any Phishing activity in mail, what should PhishUp do? | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.


### url
***
Get Url Reputation

#### Base Command

`phishup-investigate-url`
#### Input

| **Argument Name** | **Description**                       | **Required** | **Usage** |
| --- |---------------------------------------| --- | --- |
| Url | Single URL for sending to PhishUp Api | Required | Send single URL string


#### Context Output

| **Path**       | **Type** | **Description**                   | **Results** |
|----------------| --- |-----------------------------------| --- |
| PhishUp.Result | String | PhishUp Url Investigating Result  | response types "Clean", "Phish", "Error"
| PhishUp.Score  | String | Phishup Engine Result Class Score | Number


PhishUp.Result contains raw result. 
PhishUp.Score is score for predicted class.


#### Command Examples
`!phishup-investigate-url Url="https://www.paloaltonetworks.com/cortex/xsoar"`

##### Raw Response
`
{'IncomingUrl': 'https://www.paloaltonetworks.com/cortex/xsoar', 'Url': 'www.paloaltonetworks.com', 'IsRouted': False, 'PhishUpStatus': 'Clean', 'PhishUpScore': '1.00'}
`

### phishup-get-chosen-action
***
Get chosen PhishUp Playbook action option from instance


#### Base Command

`!phishup-get-chosen-action`
#### Input
There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description**                                                              |
| --- | --- |------------------------------------------------------------------------------|
| PhishUp.Action | String | Chosen PhishUp Playbook action like deleting mail or maving mail to spam box | 


#### Command Example

`!phishup-get-chosen-action`

#### Human Readable Output

Chosen Action: Move to SPAM