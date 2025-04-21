Cyren Inbox Security is an innovative solution that safeguards Office 365 mailboxes in your organization against evasive phishing, business email compromise (BEC), and fraud. This integration imports incidents from Cyren Inbox Security into XSOAR, and includes a playbook for incident resolution.
This integration was integrated and tested with version 1.0 of Cyren Inbox Security

## Configure Cyren Inbox Security in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The endpoint  provided by your Cyren Representative. \(use "sample" to test\) | True |
| Client ID | The client iD provided by your Cyren Representative. \(use "sample" to test\) | True |
| Client Secret | The client secret provided by your Cyren Representative. \(use "sample" to test\) | True |
| First fetch time | 1 day, 2 days, etc... | False |
| Maximum number of incidents per fetch |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cyren-resolve-and-remediate
***
resolve a case and remediate incidents


#### Base Command

`cyren-resolve-and-remediate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | case ID. | Required | 
| resolution | resolution. Possible values are: phishing, malware, clean, other. | Optional | 
| resolution_reason | the reason of the resolution. Possible values are: Identified phishing URL, Identified suspicious sender, Other, Scam, Spam. | Optional | 
| resolution_reason_text | free text for resolution reason. | Optional | 
| actions | remediation actions to perform. Possible values are: MOVE_TO_SPAM, MOVE_TO_DELETED, ADD_BANNER, SOFT_DELETE, MOVE_TO_INBOX, REMOVE_BANNER. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyren.data.status | string | status of actions performed | 


#### Command Example
```!cyren-resolve-and-remediate resolution=phishing resolution_reason="Identified suspicious sender" case_id="62877980-6ac7-4944-b3fa-62ddf628a0fe" resolution_reason_text="I think it is phishing" actions=ADD_BANNER,MOVE_TO_DELETED```

#### Context Example
```json
{
    "Cyren": {
        "data": {
            "status": "ok"
        }
    }
}
```

#### Human Readable Output

>### cyren-resolve-and-remediate results
>|status|
>|---|
>| ok |
>
>*** end of results ***

### cyren-reset-sample-fetch
***
resets integration to fetch a sample incident


#### Base Command

`cyren-reset-sample-fetch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
```!cyren-reset-sample-fetch```

#### Human Readable Output

>A sample incident will be created on the next execution of system *fetch-incidents* command