The only cloud-native security platform that stops targeted social engineering and phishing attacks on cloud email platforms like Office 365 and G Suite.
This integration was integrated and tested with version 2 of GreatHorn
## Configure GreatHorn on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GreatHorn.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Base URL | True |
    | api_version | API Version | True |
    | apikey | API Key | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| GreatHorn.Message.origin | String | Mailbox email was discovered | 
| GreatHorn.Message.status | String | Has the system taken action on the event | 
| GreatHorn.Message.xMailer | Unknown | X-Mailer header entry | 
| GreatHorn.Message.links.resolvedUrl | Unknown | The URL of the resolved link if it points elsewhere | 
| GreatHorn.Message.links.text | String | The text showing for the link discovered in the body of the email | 
| GreatHorn.Message.links.url | String | URL of link discovered in body of email | 
| GreatHorn.Message.links.tags | String | List of tags describing the analysis of the event | 
| GreatHorn.Message.sourcePath | String | GreatHorn discovered domain of sender | 
| GreatHorn.Message.ip | String | GreatHorn discovered originating ip of sender | 
| GreatHorn.Message.bodyOnlyWhitespace | Number | Body of email content is only whitespace | 
| GreatHorn.Message.quarReleasedBy | Unknown | Who released the quarantined email | 
| GreatHorn.Message.dmarc | String | dmarc authentication result | 
| GreatHorn.Message.collector | Unknown | Email provider email discovered | 
| GreatHorn.Message.dkim | String | dmarc authentication result | 
| GreatHorn.Message.spf | String | spf authentication result | 
| GreatHorn.Message.contentHash | String | Hash of email body conten | 
| GreatHorn.Message.workflow | String | Current action of event | 
| GreatHorn.Message.targets | String | All recepients of the email | 
| GreatHorn.Message.source | String | Email sender address | 
| GreatHorn.Message.location | String | Location of sender ip origin | 
| GreatHorn.Message.quarDeleted | Unknown | Has the event been deleted from quarantined | 
| GreatHorn.Message.quarDeletedBy | Unknown | Who deleted the quarantined email | 
| GreatHorn.Message.violations | Number | All body of email policy matches | 
| GreatHorn.Message.subject | String | Email subject | 
| GreatHorn.Message.xAuthResults | Unknown | X-Original-Authentication-Results header entry | 
| GreatHorn.Message.returnPath | String | Return-Path header entry' | 
| GreatHorn.Message.eventId | Number | The GreatHorn event id | 
| GreatHorn.Message.quarDenied | Unknown | Has the event been denied released from quarantined | 
| GreatHorn.Message.received | String | Received header entry | 
| GreatHorn.Message.replyTo | String | Reply-To header entry | 
| GreatHorn.Message.timestamp | Date | timestamp of the event, usually receivedTime | 
| GreatHorn.Message.quarReleased | Unknown | Has the event been released from quarantined | 
| GreatHorn.Message.authenticationResults | String | Authentication-Results header entry | 
| GreatHorn.Message.quarantined | Unknown | Has the event been quarantined | 
| GreatHorn.Message.flag | Number | All policies the event matched | 
| GreatHorn.Message.homographScore | Number | GreatHorn homograph score | 
| GreatHorn.Message.remediation | Unknown | Remediation action taken | 
| GreatHorn.Message.owlScore | Number | GreatHorn threat score | 
| GreatHorn.Message.quarReleaseRequested | Unknown | Has the event been requested to be relased from quarantined | 
| GreatHorn.Message.anomalyScore | Number | GreatHorn anomaly score | 
| GreatHorn.Message.quarExpired | Unknown | Has the event been expired from quarantined | 
| GreatHorn.Message.displayName | String | Display name of sender | 
| GreatHorn.Message.country | String | Country of sender ip country | 
| GreatHorn.Message.region | String | Region of sender ip origin | 
| GreatHorn.Message.headers | Object | Full set of headers for the email | 
| GreatHorn.Message.messageId | String | Message-Id header entry | 
| GreatHorn.Message.authScore | Number | GreatHorn illegitmacy score | 


#### Command Example
``` ```

#### Human Readable Output



### gh-search-message
***
Search for message based on filtering input


#### Base Command

`gh-search-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | The fields to include in the response. By default, all fields are returned. | Optional | 
| filters | The criteria to use in filtering search results. | Optional | 
| limit | The maximum number of entries to return per page of results. Default is 10; max is 200. Default is 10. | Optional | 
| offset | The zero-based offset of the first item in the collection. Default is 0; max is 10000. | Optional | 
| sort | The field to use in sorting results. Default is eventId. Default is eventId. | Optional | 
| sortDir | Indicates if the sort direction is ascending or descending. Default is descending. Possible values are: desc, asc. Default is desc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GreatHorn.Message.origin | String | Mailbox email was discovered | 
| GreatHorn.Message.status | String | Has the system taken action on the event | 
| GreatHorn.Message.xMailer | Unknown | X-Mailer header entry | 
| GreatHorn.Message.links.resolvedUrl | Unknown | The URL of the resolved link if it points elsewhere | 
| GreatHorn.Message.links.text | String | The text showing for the link discovered in the body of the email | 
| GreatHorn.Message.links.url | String | URL of link discovered in body of email | 
| GreatHorn.Message.links.tags | String | List of tags describing the analysis of the event | 
| GreatHorn.Message.sourcePath | String | GreatHorn discovered domain of sender | 
| GreatHorn.Message.ip | String | GreatHorn discovered originating ip of sender | 
| GreatHorn.Message.bodyOnlyWhitespace | Number | Body of email content is only whitespace | 
| GreatHorn.Message.quarReleasedBy | Unknown | Who released the quarantined email | 
| GreatHorn.Message.dmarc | String | dmarc authentication result | 
| GreatHorn.Message.collector | Unknown | Email provider email discovered | 
| GreatHorn.Message.dkim | String | dmarc authentication result | 
| GreatHorn.Message.spf | String | spf authentication result | 
| GreatHorn.Message.contentHash | String | Hash of email body conten | 
| GreatHorn.Message.workflow | String | Current action of event | 
| GreatHorn.Message.targets | String | All recepients of the email | 
| GreatHorn.Message.source | String | Email sender address | 
| GreatHorn.Message.location | String | Location of sender ip origin | 
| GreatHorn.Message.quarDeleted | Unknown | Has the event been deleted from quarantined | 
| GreatHorn.Message.quarDeletedBy | Unknown | Who deleted the quarantined email | 
| GreatHorn.Message.violations | Number | All body of email policy matches | 
| GreatHorn.Message.subject | String | Email subject | 
| GreatHorn.Message.xAuthResults | Unknown | X-Original-Authentication-Results header entry | 
| GreatHorn.Message.returnPath | String | Return-Path header entry' | 
| GreatHorn.Message.eventId | Number | The GreatHorn event id | 
| GreatHorn.Message.quarDenied | Unknown | Has the event been denied released from quarantined | 
| GreatHorn.Message.received | String | Received header entry | 
| GreatHorn.Message.replyTo | String | Reply-To header entry | 
| GreatHorn.Message.timestamp | Date | timestamp of the event, usually receivedTime | 
| GreatHorn.Message.quarReleased | Unknown | Has the event been released from quarantined | 
| GreatHorn.Message.authenticationResults | String | Authentication-Results header entry | 
| GreatHorn.Message.quarantined | Unknown | Has the event been quarantined | 
| GreatHorn.Message.flag | Number | All policies the event matched | 
| GreatHorn.Message.homographScore | Number | GreatHorn homograph score | 
| GreatHorn.Message.remediation | Unknown | Remediation action taken | 
| GreatHorn.Message.owlScore | Number | GreatHorn threat score | 
| GreatHorn.Message.quarReleaseRequested | Unknown | Has the event been requested to be relased from quarantined | 
| GreatHorn.Message.anomalyScore | Number | GreatHorn anomaly score | 
| GreatHorn.Message.quarExpired | Unknown | Has the event been expired from quarantined | 
| GreatHorn.Message.displayName | String | Display name of sender | 
| GreatHorn.Message.country | String | Country of sender ip country | 
| GreatHorn.Message.region | String | Region of sender ip origin | 
| GreatHorn.Message.headers | Object | Full set of headers for the email | 
| GreatHorn.Message.messageId | String | Message-Id header entry | 
| GreatHorn.Message.authScore | Number | GreatHorn illegitmacy score | 


#### Command Example
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output


