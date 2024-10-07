The only cloud-native security platform that stops targeted social engineering and phishing attacks on cloud email platforms like Office 365 and G Suite.
This integration was integrated and tested with version 2.0 of GreatHorn
## Configure GreatHorn in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Base URL | True |
| api_version | API Version | True |
| apikey | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gh-get-message
***
Return message details for the specified event


#### Base Command

`gh-get-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GreatHorn eventId, multiple values supported via CSV. | Required | 
| includeheaders | Whether or not to include full message headers in the War Room output. Possible values are: true, false. Default is false. | Optional | 
| showalllinks | Whether or not to show all links in the War Room output. When false only suspicious and malicious links will be returned to the War Room. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GreatHorn.Message.eventId | Number | The GreatHorn event id | 
| GreatHorn.Message.origin | String | Mailbox email was discovered | 
| GreatHorn.Message.status | String | Has the system taken action on the event | 
| GreatHorn.Message.xMailer | Unknown | X-Mailer header entry | 
| GreatHorn.Message.sourcePath | String | GreatHorn discovered domain of sender | 
| GreatHorn.Message.ip | String | GreatHorn discovered originating ip of sender | 
| GreatHorn.Message.bodyOnlyWhitespace | Number | Body of email content is only whitespace | 
| GreatHorn.Message.collector | Unknown | Email provider email discovered | 
| GreatHorn.Message.dkim | String | dmarc authentication result | 
| GreatHorn.Message.spf | String | spf authentication result | 
| GreatHorn.Message.contentHash | String | Hash of email body conten | 
| GreatHorn.Message.violations | Number | All body of email policy matches | 
| GreatHorn.Message.workflow | String | Current action of event | 
| GreatHorn.Message.targets | String | All recepients of the email | 
| GreatHorn.Message.source | String | Email sender address | 
| GreatHorn.Message.location | String | Location of sender ip origin | 
| GreatHorn.Message.quarReleasedBy | Unknown | Who released the quarantined email | 
| GreatHorn.Message.quarDeleted | Unknown | Has the event been deleted from quarantined | 
| GreatHorn.Message.quarDeletedBy | Unknown | Who deleted the quarantined email | 
| GreatHorn.Message.quarDenied | Unknown | Has the event been denied released from quarantined | 
| GreatHorn.Message.subject | String | Email subject | 
| GreatHorn.Message.xAuthResults | Unknown | X-Original-Authentication-Results header entry | 
| GreatHorn.Message.dmarc | String | dmarc authentication result | 
| GreatHorn.Message.returnPath | String | Return-Path header entry' | 
| GreatHorn.Message.received | String | Received header entry | 
| GreatHorn.Message.replyTo | String | Reply-To header entry | 
| GreatHorn.Message.timestamp | Date | timestamp of the event, usually receivedTime | 
| GreatHorn.Message.flag | Number | All policies the event matched | 
| GreatHorn.Message.homographScore | Number | GreatHorn homograph score | 
| GreatHorn.Message.owlScore | Number | GreatHorn threat score | 
| GreatHorn.Message.anomalyScore | Number | GreatHorn anomaly score | 
| GreatHorn.Message.authScore | Number | GreatHorn illegitmacy score | 
| GreatHorn.Message.remediation | Unknown | Remediation action taken | 
| GreatHorn.Message.quarantined | Unknown | Has the event been quarantined | 
| GreatHorn.Message.quarExpired | Unknown | Has the event been expired from quarantined | 
| GreatHorn.Message.quarReleaseRequested | Unknown | Has the event been requested to be relased from quarantined | 
| GreatHorn.Message.quarReleased | Unknown | Has the event been released from quarantined | 
| GreatHorn.Message.displayName | String | Display name of sender | 
| GreatHorn.Message.country | String | Country of sender ip country | 
| GreatHorn.Message.region | String | Region of sender ip origin | 
| GreatHorn.Message.authenticationResults | String | Authentication-Results header entry | 
| GreatHorn.Message.messageId | String | Message-Id header entry | 
| GreatHorn.Message.headers | Object | Full set of headers for the email | 
| GreatHorn.Message.links.resolvedUrl | Unknown | The URL of the resolved link if it points elsewhere | 
| GreatHorn.Message.links.text | String | The text showing for the link discovered in the body of the email | 
| GreatHorn.Message.links.url | String | URL of link discovered in body of email | 
| GreatHorn.Message.links.tags | String | List of tags describing the analysis of the event | 


#### Command Example
```!gh-get-message id="12345" includeheaders="true"```

#### Context Example
```json
{}
```

#### Human Readable Output

>GreatHorn event not found

### gh-search-message
***
Search for message based on filtering input


#### Base Command

`gh-search-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | The fields to include in the response. By default, all fields are returned. | Optional | 
| filters | The criteria to use in filtering search results.  This should be input as a dictionary. | Optional | 
| limit | The maximum number of entries to return per page of results. Default is 10; max is 200. Default is 10. | Optional | 
| offset | The zero-based offset of the first item in the collection. Default is 0; max is 10000. | Optional | 
| sort | The field to use in sorting results. Default is eventId. Default is eventId. | Optional | 
| sortDir | Indicates if the sort direction is ascending or descending. Default is descending. Possible values are: desc, asc. Default is desc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GreatHorn.Message.eventId | Number | The GreatHorn event id | 
| GreatHorn.Message.origin | String | Mailbox email was discovered | 
| GreatHorn.Message.status | String | Has the system taken action on the event | 
| GreatHorn.Message.xMailer | Unknown | X-Mailer header entry | 
| GreatHorn.Message.sourcePath | String | GreatHorn discovered domain of sender | 
| GreatHorn.Message.ip | String | GreatHorn discovered originating ip of sender | 
| GreatHorn.Message.bodyOnlyWhitespace | Number | Body of email content is only whitespace | 
| GreatHorn.Message.collector | Unknown | Email provider email discovered | 
| GreatHorn.Message.dkim | String | dmarc authentication result | 
| GreatHorn.Message.spf | String | spf authentication result | 
| GreatHorn.Message.contentHash | String | Hash of email body conten | 
| GreatHorn.Message.violations | Number | All body of email policy matches | 
| GreatHorn.Message.workflow | String | Current action of event | 
| GreatHorn.Message.targets | String | All recepients of the email | 
| GreatHorn.Message.source | String | Email sender address | 
| GreatHorn.Message.location | String | Location of sender ip origin | 
| GreatHorn.Message.quarReleasedBy | Unknown | Who released the quarantined email | 
| GreatHorn.Message.quarDeleted | Unknown | Has the event been deleted from quarantined | 
| GreatHorn.Message.quarDeletedBy | Unknown | Who deleted the quarantined email | 
| GreatHorn.Message.quarDenied | Unknown | Has the event been denied released from quarantined | 
| GreatHorn.Message.subject | String | Email subject | 
| GreatHorn.Message.xAuthResults | Unknown | X-Original-Authentication-Results header entry | 
| GreatHorn.Message.dmarc | String | dmarc authentication result | 
| GreatHorn.Message.returnPath | String | Return-Path header entry' | 
| GreatHorn.Message.received | String | Received header entry | 
| GreatHorn.Message.replyTo | String | Reply-To header entry | 
| GreatHorn.Message.timestamp | Date | timestamp of the event, usually receivedTime | 
| GreatHorn.Message.flag | Number | All policies the event matched | 
| GreatHorn.Message.homographScore | Number | GreatHorn homograph score | 
| GreatHorn.Message.owlScore | Number | GreatHorn threat score | 
| GreatHorn.Message.anomalyScore | Number | GreatHorn anomaly score | 
| GreatHorn.Message.authScore | Number | GreatHorn illegitmacy score | 
| GreatHorn.Message.remediation | Unknown | Remediation action taken | 
| GreatHorn.Message.quarantined | Unknown | Has the event been quarantined | 
| GreatHorn.Message.quarExpired | Unknown | Has the event been expired from quarantined | 
| GreatHorn.Message.quarReleaseRequested | Unknown | Has the event been requested to be relased from quarantined | 
| GreatHorn.Message.quarReleased | Unknown | Has the event been released from quarantined | 
| GreatHorn.Message.displayName | String | Display name of sender | 
| GreatHorn.Message.country | String | Country of sender ip country | 
| GreatHorn.Message.region | String | Region of sender ip origin | 
| GreatHorn.Message.authenticationResults | String | Authentication-Results header entry | 
| GreatHorn.Message.messageId | String | Message-Id header entry | 
| GreatHorn.Message.headers | Object | Full set of headers for the email | 
| GreatHorn.Message.links.resolvedUrl | Unknown | The URL of the resolved link if it points elsewhere | 
| GreatHorn.Message.links.text | String | The text showing for the link discovered in the body of the email | 
| GreatHorn.Message.links.url | String | URL of link discovered in body of email | 
| GreatHorn.Message.links.tags | String | List of tags describing the analysis of the event | 


#### Command Example
```!gh-search-message filters="[{\"targets\": [\"penguin@scuftysails.com\"], \"origin\": [\"action@ifttt.com\"]}]"```

#### Context Example
```json
{
    "GreatHorn": {
        "Message": {
            "Message": [],
            "SearchCount": 0
        }
    }
}
```

#### Human Readable Output

>### Events
>**No entries.**


### gh-remediate-message
***
Perform the specified remediation action on message


#### Base Command

`gh-remediate-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The action to take on the given message. Possible values are: archive, banner, delete, label, move, quarantine, delete, removeattachments, review, trash. | Required | 
| eventId | The GreatHorn event ID. | Required | 
| hasButton | If true, the banner will include a button enabling the end-user to remove the banner. Default is True. Possible values are: True, False. Default is True. | Optional | 
| message | The text to display in the email's banner. | Optional | 
| label | The name of the label to add. If the label name does not exist, it will be created. | Optional | 
| location | The target location in the user's mailbox. If the location does not exist, it will be created. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GreatHorn.Remediation.action | String | Remediation action requested to be taken on the event | 
| GreatHorn.Remediation.eventId | String | The Greathorn event ID | 
| GreatHorn.Remediation.reason | String | Details of error seen if any | 
| GreatHorn.Remediation.success | Number | Indication if the request was successful | 


#### Command Example
```!gh-remediate-message action="banner" message="This email may be a phishing attempt" eventId="20128"```

#### Context Example
```json
{
    "GreatHorn": {
        "Remediation": {
            "action": "banner",
            "eventId": "20128",
            "reason": "completed",
            "success": true
        }
    }
}
```

#### Human Readable Output

>Remediate action banner applied successfully to message 20128

### gh-revert-remediate-message
***
Revert the specified remediation action on the given message


#### Base Command

`gh-revert-remediate-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Remediation action to revert. Possible values are: banner, quarantinerequest, quarantinerelease, quarantinedeny, removeattachments, review. | Required | 
| eventId | The GreatHorn event ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GreatHorn.Remediation.action | String | Remediation action that was reverted | 
| GreatHorn.Remediation.eventId | String | The GreatHorn event ID | 
| GreatHorn.Remediation.reason | String | Details of error seen if any | 
| GreatHorn.Remediation.success | Number | Indication if the request was successful | 


#### Command Example
```!gh-revert-remediate-message action="banner" eventId="20128"```

#### Context Example
```json
{
    "GreatHorn": {
        "Remediation": {
            "action": "banner",
            "eventId": "20128",
            "reason": "completed",
            "success": true
        }
    }
}
```

#### Human Readable Output

>Revert action banner applied successfully to message 20128

### gh-get-policy
***
Retrieve details about the policy specified


#### Base Command

`gh-get-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyid | The ID of the policy. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GreatHorn.Policy.name | String | The user-defined name of the policy | 
| GreatHorn.Policy.enabled | Number | Whether the policy is enabled | 
| GreatHorn.Policy.config | String | The match configuration of the policy | 
| GreatHorn.Policy.id | Number | The ID of the policy | 
| GreatHorn.Policy.description | String | The user-defined description of the policy | 


#### Command Example
```!gh-get-policy policyid="16567"```

#### Context Example
```json
{
    "GreatHorn": {
        "Policy": {
            "actions": [
                {
                    "addresses": [
                        ""
                    ],
                    "quarantineNotification": false,
                    "releaseNotification": false,
                    "type": "quarantine"
                }
            ],
            "config": [
                "or",
                [
                    "and",
                    {
                        "opt": "from",
                        "type": "regex",
                        "values": [
                            "asdf2@asdf2.com",
                            "asdf@asdf.com"
                        ]
                    }
                ]
            ],
            "description": "",
            "enabled": true,
            "id": 16567,
            "name": "Penalty box policy"
        }
    }
}
```

#### Human Readable Output

>### Policy
>|ID|Name|Enabled|Description|Actions|
>|---|---|---|---|---|
>| 16567 | Penalty box policy | true |  | quarantine |


### gh-set-policy
***
Retrieve details about the policy specified.


#### Base Command

`gh-set-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| updatemethod | Update method for the given policy. Possible values are: patch, put. | Required | 
| policyid | The ID of the policy. | Required | 
| policyjson | Policy defintion or policy change defintion.  Input as a dictionary. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GreatHorn.Policy.id | Number | The ID of the policy. | 


#### Command Example
```!gh-set-policy policyid="16567" updatemethod="patch" policyjson="{\"config\": [\"or\", [\"and\", {\"opt\": \"from\", \"values\": [\"asdf@asdf.com\",\"asdf2@asdf2.com\"], \"type\": \"regex\"}]]}"```

#### Context Example
```json
{
    "GreatHorn": {
        "Policy": {
            "id": "16567",
            "success": true
        }
    }
}
```

#### Human Readable Output

>Update applied successfully to policy 16567