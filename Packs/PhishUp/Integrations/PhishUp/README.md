### PhishUp prevents phishing attacks, protects your staff and your brand with AI

If you don't have [PhishUp](https://phishup.co) Api Key please create an account on PhishUp and get a free Api Key. 
Also you can visit and test [PhishUp Web Demo](https://phishup.co).

If you have any question feel free to concat us: [info@phishup.com](mailto:info@phishup.co)

## Configure PhishUp in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API KEY |  | True |
| Incident type |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| PhishUp Playbook Actions | If there is any Phishing activity in mail, what should PhishUp do? | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### url
***
PhishUp Url investigation

#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Url | URL for phishup investigation. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PhishUp.Url | String | Incoming Url |
| PhishUp.Result | String | response types "Clean", "Phish" | 
| PhishUp.Score | Number | Phishup Engine Url Score | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| URL.Data | String | The URL | 


#### Base Command

`phishup-get-chosen-action`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PhishUp.Action | String | Chosen action from PhishUp instance | 


#### Base Command

`phishup-evaluate-response`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PhishUp.Evaluation | String | Evaluating PhishUp Results and Return Phish If There is an Phish Website | 