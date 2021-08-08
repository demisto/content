Cyren Inbox Security is an innovative solution that safeguards Office 365 mailboxes in your organization against evasive phishing, business email compromise (BEC), and fraud. This integration imports incidents from Cyren Inbox Security into XSOAR, and includes a playbook for incident resolution.
This integration was integrated and tested with version 1.0 of Cyren Inbox Security
## Configure Cyren Inbox Security on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cyren Inbox Security.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | The endpoint  provided by your Cyren Representative. \(use "sample" to test\) | True |
    | Client ID | The client iD provided by your Cyren Representative. \(use "sample" to test\) | True |
    | Client Secret | The client secret provided by your Cyren Representative. \(use "sample" to test\) | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| instance_name | The name of the integration instance you want to apply the command. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| data.status | string | status of actions performed | 


#### Command Example
```!cyren-resolve-and-remediate resolution=phishing resolution_reason="Identified suspicious sender" case_id="62877980-6ac7-4944-b3fa-62ddf628a0fe" resolution_reason_text="I think it is phishing" actions=ADD_BANNER,MOVE_TO_DELETED```

#### Context Example
```json
{
    "data": {
        "status": "ok"
    }
}
```

#### Human Readable Output

>{"data": {"status": "ok"}}
>
>*** end of results ***
