This integration enables you to manage and interact with Microsoft O365 - Exchange Online from within XSOAR.
This integration was integrated and tested with version V1 of Exchange Online PowerShell.

## Enable or disable access to Exchange Online PowerShell

Exchange Online PowerShell enables you to manage your Exchange Online organization from the command line.
By default, all accounts you create in Microsoft 365 are allowed to use Exchange Online PowerShell.
Administrators can use Exchange Online PowerShell to enable or disable a user's ability to connect to Exchange Online PowerShell.
Note that access to Exchange Online PowerShell doesn't give users extra administrative powers in your organization.
A user's capabilities in Exchange Online PowerShell are still defined by a role based access control (RBAC) and the roles that are assigned to them.

For more [info](https://docs.microsoft.com/en-us/powershell/exchange/disable-access-to-exchange-online-powershell?view=exchange-ps)

## Configure O365 - EWS - Extension on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.

2. Search for O365 - EWS - Extension.

3. Authentication / Authorization methods:

    1. OAuth2.0 authorization (recommended):

        1. Click **Add an instance** to create and configure a new integration instance.

           | **Parameter** | **Description**                                          | **Required** |
           | ------------- | -------------------------------------------------------- | ------------ |
           | url           | Echange online URL                                       | True         |
           | credentials   | Fill **only** Email (aka UPN), Password should be empty. | False        |
           | insecure      | Trust any certificate \(not secure\)                     | False        |

        2. Open playground -  War-room:

            1. Run the ***!ews-auth-start*** command and follow the instructions. Expected output is:

            > ## EWS extension - Authorize instructions
            >
            > 1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin) and enter the code **XXXXXXX** to authenticate.
            > 2. Run the command ***!ews-auth-complete*** command in the War Room.

            2. Test - OAuth2.0 authorization, Run the ***!ews-auth-test*** command. 

2. Basic authentication (Not recommended):

    1. Click **Add an instance** to create and configure a new integration instance.

       | **Parameter** | **Description** | **Required** |
                | --- | --- | --- |
       | url | Search and Compliance URL | True |
       | credentials | Fill Email (aka UPN) and password | False |
       | insecure | Trust any certificate \(not secure\) | False |

    2. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ews-auth-start
***
OAuth2.0 - Start authorization.


#### Base Command

`ews-auth-start`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!ews-auth-start```

#### Human Readable Output

>## EWS extension - Authorize instructions
>1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin) and enter the code **XXXXXXX** to authenticate.
>2. Run the ***!ews-auth-complete*** command in the War Room.


### ews-auth-complete
***
Completes the OAuth2.0 authorization process.


#### Base Command

`ews-auth-complete`

#### Input

There are no input arguments for this command.


#### Context Output

There is no context output for this command.

#### Command Example
```!ews-auth-complete```

#### Human Readable Output

>Your account **successfully** authorized!

### ews-auth-test
***
Tests the OAuth2.0 authorization process.

#### Base Command

`ews-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!ews-auth-test```

#### Human Readable Output

>**Test ok!**

### ews-junk-rules-get
***
Gets junk rules for the specified mailbox.


#### Base Command

`ews-junk-rules-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mailbox | ID of the mailbox for which to get junk rules. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Rule.Junk.BlockedSendersAndDomains | String | Blocked senders and domains list. | 
| EWS.Rule.Junk.ContactsTrusted | Boolean | If true, contacts are trusted by default. | 
| EWS.Rule.Junk.Email | String | Junk rule mailbox. | 
| EWS.Rule.Junk.Enabled | Boolean | If true, junk rule is enabled. | 
| EWS.Rule.Junk.Identity | String | Junk rule identity. | 
| EWS.Rule.Junk.MailboxOwnerId | String | Mail box owner ID. | 
| EWS.Rule.Junk.TrustedListsOnly | Boolean | If true, only a list defined in the trusted lists are trusted. | 
| EWS.Rule.Junk.TrustedRecipientsAndDomains | String | List of trusted recipients and domains. | 
| EWS.Rule.Junk.TrustedSendersAndDomains | String | List of trusted senders and domains. | 


#### Command Example
```!ews-junk-rules-get mailbox="xsoar@dev.onmicrosoft.com"```

#### Context Example
```json
{
    "EWS": {
        "Rule": {
            "Junk": {
                "BlockedSendersAndDomains": [
                    "user1@gmail.com",
                    "user2@gmail.com"
                ],
                "ContactsTrusted": false,
                "Enabled": false,
                "Identity": "xsoar",
                "MailboxOwnerId": "xsoar",
                "TrustedListsOnly": false,
                "TrustedRecipientsAndDomains": [
                  "user1@gmail.com",
                  "user2@gmail.com"
                ],
                "TrustedSendersAndDomains": [
                  "user1@gmail.com",
                  "user2@gmail.com"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### EWS extension - 'xsoar@dev.onmicrosoft.com' Junk rules
>| BlockedSendersAndDomains | ContactsTrusted | Enabled | TrustedListsOnly | TrustedSendersAndDomains
>| --- | --- | --- | --- | ---
>| \["user1@gmail.com","user2@gmail.com"\] | False | False | False | \["user1@gmail.com","user2@gmail.com"\]


### ews-junk-rules-set
***
Sets junk rules for the specified mailbox.


#### Base Command

`ews-junk-rules-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mailbox | ID of the mailbox for which to set junk rules. | Required | 
| add_blocked_senders_and_domains | Comma-separated list of blocked senders and domains to add to the mailbox. | Optional | 
| remove_blocked_senders_and_domains | Comma-separated list of blocked senders and domains to remove from the mailbox. | Optional | 
| add_trusted_senders_and_domains | Comma-separated list of trusted senders and domains to add to the mailbox. | Optional | 
| remove_trusted_senders_and_domains | Comma-separated list of trusted senders and domains to remove from the mailbox. | Optional | 
| trusted_lists_only | If true, trust only lists defined in the trusted lists. Can be "true" or "false". Possible values are: true, false. | Optional | 
| contacts_trusted | If true, contacts are trusted by default. Can be "true" or "false". Possible values are: true, false. | Optional | 
| enabled | If true, the junk rule is enabled. Can be "true" or "false". Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ews-junk-rules-set mailbox="xsoar@dev.onmicrosoft.com" add_blocked_senders_and_domains="test@gmail.com" add_trusted_senders_and_domains="dev.onmicrosoft.com"```

#### Human Readable Output

>EWS extension - 'xsoar@dev.onmicrosoft.com' Junk rules **modified**!

### ews-global-junk-rules-set
***
Sets junk rules in all managed accounts.


#### Base Command

`ews-global-junk-rules-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| add_blocked_senders_and_domains | Comma-separated list of blocked senders and domains to add to the mailbox. | Optional | 
| remove_blocked_senders_and_domains | Comma-separated list of blocked senders and domains to remove from the mailbox. | Optional | 
| add_trusted_senders_and_domains | Comma-separated list of trusted senders and domains to add to the mailbox. | Optional | 
| remove_trusted_senders_and_domains | Comma-separated list of trusted senders and domains to remove from the mailbox. | Optional | 
| trusted_lists_only | If true, trust only lists defined in the trusted lists. Can be "true" or "false". Possible values are: true, false. | Optional | 
| contacts_trusted | If true, contacts are trusted by default. Can be "true" or "false". Possible values are: true, false. | Optional | 
| enabled | If true, the junk rule is enabled. Can be "true" or "false". Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ews-global-junk-rules-set add_blocked_senders_and_domains="test@demisto.com" add_trusted_senders_and_domains="demisto.com"```

#### Human Readable Output

>EWS extension - Junk rules globally **modified**!

### ews-message-trace-get
***
Searches message data for the last 10 days. If you run this command without any arguments, only data from the last 48 hours is returned.
If you enter a start date that is older than 10 days, you will receive an error and the command will return no results.
This command returns a maximum of 1,000,000 results, and will timeout on very large queries. If your query returns too many results, consider splitting it up using shorter start_date and end_date intervals.



#### Base Command

`ews-message-trace-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sender_address | The sender_address parameter filters the results by the sender's email address. You can specify multiple values separated by commas.<br/>. | Optional | 
| recipient_address | The recipient_address parameter filters the results by the recipient's email address. You can specify multiple values separated by commas.<br/>. | Optional | 
| from_ip | The from_ip parameter filters the results by the source IP address.<br/>For incoming messages, the value of from_ip is the public IP address of the SMTP email server that sent the message.<br/>For outgoing messages from Exchange Online, the value is blank.<br/>. | Optional | 
| to_ip | The to_ip parameter filters the results by the destination IP address.<br/>For outgoing messages, the value of to_ip is the public IP address in the resolved MX record for the destination domain.<br/>For incoming messages to Exchange Online, the value is blank.<br/>. | Optional | 
| message_id | The message_id parameter filters the results by the Message-ID header field of the message.<br/>This value is also known as the Client ID. The format of the Message-ID depends on the messaging server that sent the message.<br/>The value should be unique for each message. However, not all messaging servers create values for the Message-ID in the same way.<br/>Be sure to include the full Message ID string (which may include angle brackets) and enclose the value in quotation marks (for example,"d9683b4c-127b-413a-ae2e-fa7dfb32c69d@DM3NAM06BG401.Eop-nam06.prod.protection.outlook.com").<br/>. | Optional | 
| message_trace_id | The message_trace_id parameter can be used with the recipient address to uniquely identify a message trace and obtain more details.<br/>A message trace ID is generated for every message that's processed by the system.<br/>. | Optional | 
| page | The page number of the results you want to view.<br/>Can be an integer between 1 and 1000. The default value is 1.<br/>. Default is 1. | Optional | 
| page_size | The maximum number of entries per page.<br/>Can be an integer between 1 and 5000. The default value is 100.<br/>. Default is 100. | Optional | 
| start_date | The start date of the date range.<br/>Use the short date format that's defined in the Regional Options settings on the computer where you're running the command. For example, if the computer is configured to use the short date format mm/dd/yyyy,<br/>enter 09/01/2018 to specify September 1, 2018. You can enter the date only, or you can enter the date and time of day.<br/>If you enter the date and time of day, enclose the value in quotation marks ("), for example, "09/01/2018 5:00 PM".<br/>Valid input for this parameter is from 10 days - now ago. The default value is 48 hours ago.<br/>. | Optional | 
| end_date | The end date of the date range.<br/>Use the short date format that's defined in the Regional Options settings on the computer where you're running the command.<br/>For example, if the computer is configured to use the short date format mm/dd/yyyy, enter 09/01/2018 to specify September 1, 2018.<br/>You can enter the date only, or you can enter the date and time of day.<br/>If you enter the date and time of day, enclose the value in quotation marks ("), for example, "09/01/2018 5:00 PM".<br/>Valid input for this parameter is from start_date - now. The default value is now.<br/>. | Optional | 
| status | The status of the message. Can be one of the following:<br/>  * GettingStatus: The message is waiting for status update.<br/>  * Failed: Message delivery was attempted and it failed or the message was filtered as spam or malware, or by transport rules.<br/>  * Pending: Message delivery is underway or was deferred and is being retried.<br/>  * Delivered: The message was delivered to its destination.<br/>  * Expanded: There was no message delivery because the message was addressed to a distribution group and the membership of the distribution was expanded.<br/>  * Quarantined: The message was quarantined.<br/>  * FilteredAsSpam: The message was marked as spam.<br/>. Possible values are: GettingStatus, Failed, Pending, Delivered, Expanded, Quarantined, FilteredAsSpam. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.MessageTrace.FromIP | String | The public IP address of the SMTP email server that sent the message. | 
| EWS.MessageTrace.ToIP | String | The public IP address in the resolved MX record for the destination domain. For incoming messages to Exchange Online, the value is blank. | 
| EWS.MessageTrace.Index | Number | Message index in pagination. \(Index starts from 0\) | 
| EWS.MessageTrace.MessageId | String | Message-ID header field of the message. | 
| EWS.MessageTrace.MessageTraceId | String | Message trace ID of the message. | 
| EWS.MessageTrace.Organization | String | Message trace organization source. | 
| EWS.MessageTrace.Received | Date | Message receive time. | 
| EWS.MessageTrace.RecipientAddress | String | Message recipients address. | 
| EWS.MessageTrace.SenderAddress | String | Message sender address. | 
| EWS.MessageTrace.Size | Number | Message size in bytes. | 
| EWS.MessageTrace.StartDate | Date | Message trace start date. | 
| EWS.MessageTrace.EndDate | Date | Message trace end date. | 
| EWS.MessageTrace.Status | String | Message status. | 
| EWS.MessageTrace.Subject | String | Message subject. | 


#### Command Example
```!ews-message-trace-get```

#### Context Example
```json
{
    "EWS": {
        "MessageTrace": [
            {
                "EndDate": "2021-01-03T06:14:14.9596257Z",
                "FromIP": "8.8.8.8",
                "Index": 1,
                "MessageId": "xxx",
                "MessageTraceId": "xxxx",
                "Organization": "dev.onmicrosoft.com",
                "Received": "2021-01-03T04:45:36.4662406",
                "RecipientAddress": "xsoar@dev.onmicrosoft.com",
                "SenderAddress": "xsoar@dev.onmicrosoft.com",
                "Size": 1882,
                "StartDate": "2021-01-01T06:14:14.9596257Z",
                "Status": "GettingStatus",
                "Subject": "Test mail",
                "ToIP": null
            },
            {
                "EndDate": "2021-01-03T06:15:14.9596257Z",
                "FromIP": "8.8.8.8",
                "Index": 2,
                "MessageId": "xxx",
                "MessageTraceId": "xxxx",
                "Organization": "dev.onmicrosoft.com",
                "Received": "2021-01-03T04:46:36.4662406",
                "RecipientAddress": "xsoar@dev.onmicrosoft.com",
                "SenderAddress": "xsoar@dev.onmicrosoft.com",
                "Size": 1882,
                "StartDate": "2021-01-01T06:15:14.9596257Z",
                "Status": "GettingStatus",
                "Subject": "Test mail",
                "ToIP": null
            }
        ]
    }
}
```

#### Human Readable Output

>### EWS extension - Messages trace
>| EndDate | FromIP | Index | MessageId | MessageTraceId | Organization | Received | RecipientAddress | SenderAddress | Size | StartDate | Status | Subject | ToIP
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| 1/3/2021 6:14:14 AM | 8.8.8.8 | 0 | xxx | xxxx | microsoft.com | 1/3/2021 4:45:36 AM | xsoar@dev.microsoft.com | xsoar@dev.onmicrosoft.com | 6975 | 1/1/2021 6:14:14 AM | Delivered | Test mail |
>| 1/3/2021 6:15:14 AM | 8.8.8.8 | 1 | xxx | xxxx | microsoft.com | 1/3/2021 4:46:36 AM | xsoar@dev.microsoft.com | xsoar@dev.onmicrosoft.com | 6975 | 1/1/2021 6:15:14 AM | Delivered | Test mail | 
