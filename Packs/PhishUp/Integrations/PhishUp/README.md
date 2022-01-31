PhishUp prevents phishing attacks, protects your staff and your brand with AI

If you don't have [PhishUp](https://phishup.co) Api Key please create account on PhishUp and get an Api Key. 
Also you can visit and test [PhishUp Web Demo](https://phishup.co).

If you have any question feel free to concat us: [info@phishup.com](info@phishup.co)

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
### phishup-investigate-url
***
Single url investigation


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Url | Single URL for phishup investigation. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PhishUp.Result | String | response types "Clean", "Phish", "Error" | 
| PhishUp.Score | Number | Phishup Engine Url Score | 


#### Base Command

`phishup-get-chosen-action`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PhishUp.Action | String | Chosen action from PhishUp instance | 
