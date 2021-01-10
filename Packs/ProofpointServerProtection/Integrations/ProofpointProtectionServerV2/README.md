Proofpoint email security appliance.

This integration was integrated and tested with version xx of Proofpoint Protection Server.
## Authentication
An administrator must have a Role that includes access to a specific REST API. 

Proofpoint on Demand (PoD) administrators must file a support ticket to Proofpoint support to obtain a role with access to an API.

On premise administrators: edit the **filter.cfg** file and set the following key to true: `com.proofpoint.admin.apigui.enable=t`

In the management interface, create a Role of Type API and select the APIs under ***Managed Modules*** for the Role so that you can give an administrator that Role.

The required managed modules for this integration:
 - pss
 - Quarantine
 
 TODO: add screenshot

The operations are accessed through port 10000.

## Configure Proofpoint Protection Server v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Proofpoint Protection Server v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Server URL \(e.g., https://xxxxxxxx.pphosted.com:10000\) | True |
    | credentials | Username | True |
    | unsecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### proofpoint-pps-smart-search
***
Trace and analyze information about messages after they have been filtered by the Proofpoint Protection Server.


#### Base Command

`proofpoint-pps-smart-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Final message disposition. Possible values are: accept, continue, discard, redirect, reject, retry. | Optional | 
| start_time | Beginning time the search is performed against. Can be either free text (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) or ISO-8601 (YYYY-MM-DDThh:mm:ssZ, e.g., 2020-01-25T10:00:00Z). Default is 24 hours. | Optional | 
| end_time | Ending time the search is performed against. Can be either free text (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) or ISO-8601 (YYYY-MM-DDThh:mm:ssZ, e.g., 2020-01-25T10:00:00Z). | Optional | 
| virus | Detected virus name that infected the message (comma separated string). | Optional | 
| sender | Sender email address. | Optional | 
| recipient | Recipient email address. | Optional | 
| attachment | Message attachments (comma separated string). | Optional | 
| queue_id | Message queue ID. | Optional | 
| host | Sending host/IP address of the email message. | Optional | 
| sid | SID of the email message. | Optional | 
| subject | Subject of the email message. | Optional | 
| guid | Global unique ID of the email message. | Optional | 
| message_id | Header message ID. Corresponds to Message ID field<br/>in UI. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.SmartSearch.Rule_ID | String | Message rule ID \(e.g., system\). | 
| Proofpoint.SmartSearch.Disposition_Action | String | Message disposition action. | 
| Proofpoint.SmartSearch.Sendmail_Action | String | Message send mail action. | 
| Proofpoint.SmartSearch.Attachment_Names | String | Message attachment names. | 
| Proofpoint.SmartSearch.Recipients | String | Mail message recipient email addresses. | 
| Proofpoint.SmartSearch.SendmailRaw_Log | String | Mail message send mail raw log. | 
| Proofpoint.SmartSearch.GUID | String | Mail message GUID. | 
| Proofpoint.SmartSearch.Date | Date | Mail message date. | 
| Proofpoint.SmartSearch.Raw_Log | String | Mail message raw log. | 
| Proofpoint.SmartSearch.Sender_Host | String | Mail message sender host. | 
| Proofpoint.SmartSearch.Module_ID | String | Mail message module ID \(e.g., access\). | 
| Proofpoint.SmartSearch.Sender_IP_Address | String | Mail message sender IP address. | 
| Proofpoint.SmartSearch.Quarantine_Folder | String | Mail message quarantine folder. | 
| Proofpoint.SmartSearch.QID | String | Mail message queue ID. | 
| Proofpoint.SmartSearch.Quarantine_Rule | String | Mail message quarantine rule. | 
| Proofpoint.SmartSearch.Spam_Score | String | Mail message spam score. | 
| Proofpoint.SmartSearch.country | String | Mail message country \(e.g., \*\*\). | 
| Proofpoint.SmartSearch.TLS | String | Mail message TLS. | 
| Proofpoint.SmartSearch.Policy_Routes | String | Mail message policy routes \(comma separated string, e.g., allow_relay,firewallsafe\). | 
| Proofpoint.SmartSearch.current_folder | String | Mail message current folder. | 
| Proofpoint.SmartSearch.FID | String | Mail message folder ID. | 
| Proofpoint.SmartSearch.module_rules | String | Mail message module rules \(e.g., access.system\). | 
| Proofpoint.SmartSearch.PE_Recipients | String | Mail message PE recipients. | 
| Proofpoint.SmartSearch.Virus_Names | String | Mail message virus names. | 
| Proofpoint.SmartSearch.Sendmail_Errorcode | String | Mail message error codes. | 
| Proofpoint.SmartSearch.FQIN | String | Mail message FQIN \(e.g., example.com-10000_instance1\). | 
| Proofpoint.SmartSearch.SMIME_Recipients | String | Mail message SMIME recipients. | 
| Proofpoint.SmartSearch.Agent | String | Mail message agent host, | 
| Proofpoint.SmartSearch.Subject | String | Mail message subject. | 
| Proofpoint.SmartSearch.Final_Rule | String | Mail message final rule \(e.g., access.system\). | 
| Proofpoint.SmartSearch.Suborg | String | Mail message sub-organization. | 
| Proofpoint.SmartSearch.SMIME_Recipients_Signed | String | Mail message SMIME recipients signed. | 
| Proofpoint.SmartSearch.Message_Encrypted | String | Mail message encypted. | 
| Proofpoint.SmartSearch.Message_Split | String | Mail message splitted. | 
| Proofpoint.SmartSearch.Disposition_SmtpProfile | String | Mail message disposition SMTP profile. | 
| Proofpoint.SmartSearch.Sendmail_To | String | Mail message send mail to. | 
| Proofpoint.SmartSearch.Sendmail_Stat | String | Mail message send mail stat. | 
| Proofpoint.SmartSearch.SID | String | Mail message SID. | 
| Proofpoint.SmartSearch.Message_ID | String | Mail message ID. | 
| Proofpoint.SmartSearch.Final_Action | String | Mail message final action \(e.g., accept\) | 
| Proofpoint.SmartSearch.Sender | String | Mail message sender. | 
| Proofpoint.SmartSearch.Sendmail_To_Stat | String | Mail message send mail to stat. | 
| Proofpoint.SmartSearch.Message_Size | String | Mail message size. | 


#### Command Example
```!proofpoint-pps-smart-search```

#### Context Example
```json
{
    "Proofpoint": {
        "SmartSearch": [
            {
                "Agent": "example.com",
                "Attachment_Names": "",
                "Date": "2020-05-20 14:13:02 [UTC-0600]",
                "Disposition_Action": "",
                "Disposition_SmtpProfile": "",
                "Duration": "0.124094999905240",
                "FID": "8lLtu31xs8H24NF8McYw-S6EidtLK-y_",
                "FQIN": "example.com-10000_instance1",
                "Final_Action": "accept",
                "Final_Rule": "access.system",
                "GUID": "9rLtu31xs8H24NF8KcRw-S6EihtLK-y_",
                "Message_Encrypted": "",
                "Message_ID": "<551609250613.u8P6D1l3019878@user.example.com>",
                "Message_Size": "1142",
                "Message_Split": "",
                "Module_ID": "access",
                "PE_Recipients": "",
                "Policy_Routes": "allow_relay,firewallsafe,internalnet",
                "QID": "u8P6D24m919880",
                "Quarantine_Folder": "",
                "Quarantine_Rule": "",
                "Raw_Log": "",
                "Recipients": "user@example.com",
                "Rule_ID": "system",
                "SID": "25nnq08028",
                "SMIME_Recipients": "",
                "SMIME_Recipients_Signed": "",
                "Sender": "root@user.example.com",
                "Sender_Host": "localhost",
                "Sender_IP_Address": "127.0.0.1",
                "SendmailRaw_Log": "",
                "Sendmail_Action": "",
                "Sendmail_Errorcode": "",
                "Sendmail_Stat": "",
                "Sendmail_To": "",
                "Sendmail_To_Stat": "",
                "Spam_Score": "",
                "Subject": "Cron <pps@user> /opt/proofpoint/pps8.0.1.1446/admin/tools/dbutil.sh -optimize -db msgqueue",
                "Suborg": "",
                "TLS": "",
                "Virus_Names": "",
                "country": "**",
                "current_folder": "",
                "module_rules": [
                    "access.system"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Proofpoint Protection Server Smart Search Results
>|Agent|Attachment_Names|Date|Disposition_Action|Disposition_SmtpProfile|Duration|FID|FQIN|Final_Action|Final_Rule|GUID|Message_Encrypted|Message_ID|Message_Size|Message_Split|Module_ID|PE_Recipients|Policy_Routes|QID|Quarantine_Folder|Quarantine_Rule|Raw_Log|Recipients|Rule_ID|SID|SMIME_Recipients|SMIME_Recipients_Signed|Sender|Sender_Host|Sender_IP_Address|SendmailRaw_Log|Sendmail_Action|Sendmail_Errorcode|Sendmail_Stat|Sendmail_To|Sendmail_To_Stat|Spam_Score|Subject|Suborg|TLS|Virus_Names|country|current_folder|module_rules|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| example.com |  | 2020-05-20 14:13:02 [UTC-0600] |  |  | 0.124094999905240 | 8lLtu31xs8H24NF8McYw-S6EidtLK-y_ | example.com-10000_instance1 | accept | access.system | 9rLtu31xs8H24NF8KcRw-S6EihtLK-y_ |  | <551609250613.u8P6D1l3019878@user.example.com> | 1142 |  | access |  | allow_relay,firewallsafe,internalnet | u8P6D24m919880 |  |  |  | user@example.com | system | 25nnq08028 |  |  | root@user.example.com | localhost | 127.0.0.1 |  |  |  |  |  |  |  | Cron <pps@user> /opt/proofpoint/pps8.0.1.1446/admin/tools/dbutil.sh -optimize -db msgqueue |  |  |  | ** |  | access.system |


### proofpoint-pps-list-quarantined-messages
***
Search for quarantine messages.


#### Base Command

`proofpoint-pps-list-quarantined-messages`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | Envelope message sender equals, starts with, ends with or is in a domain such as "bar.com". At least one of the following arguments must be specified: from, to, subject. | Optional | 
| to | Envelope message recipient equals, starts with, ends with or is in a domain such as "bar.com". At least one of the following arguments must be specified: from, to, subject. | Optional | 
| subject | Message subject starts with, ends with or contains. At least one of the following arguments must be specified: from, to, subject. | Optional | 
| start_time | Beginning time the search is performed against. Can be either free text (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) or ISO-8601 (YYYY-MM-DDThh:mm:ssZ, e.g., 2020-01-25T10:00:00Z). Default is 24 hours. | Optional | 
| end_time | Ending time the search is performed against. Can be either free text (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) or ISO-8601 (YYYY-MM-DDThh:mm:ssZ, e.g., 2020-01-25T10:00:00Z). | Optional | 
| folder_name | Quarantine folder name. Default is Quarantine. | Optional | 
| guid | Message Global Unique Identifier (generated by PPS) to retrieve raw data for a message. If it is specified and a message is found, the message’s raw data will be returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.QuarantinedMessage.processingserver | String | Quarantined message processing server. | 
| Proofpoint.QuarantinedMessage.date | Date | Quarantined message date. | 
| Proofpoint.QuarantinedMessage.subject | String | Quarantined message subject. | 
| Proofpoint.QuarantinedMessage.messageid | String | Quarantined message ID. | 
| Proofpoint.QuarantinedMessage.folder | String | Quarantined message folder. | 
| Proofpoint.QuarantinedMessage.size | String | Quarantined message size. | 
| Proofpoint.QuarantinedMessage.rcpts | String | Quarantined message recipients. | 
| Proofpoint.QuarantinedMessage.from | String | Quarantined message sender. | 
| Proofpoint.QuarantinedMessage.spamscore | String | Quarantined message spam score. | 
| Proofpoint.QuarantinedMessage.guid | String | Quarantined message GUID. | 
| Proofpoint.QuarantinedMessage.host_ip | String | Quarantined message host IP address. | 
| Proofpoint.QuarantinedMessage.localguid | String | Quarantined message local GUID. | 


#### Command Example
```!proofpoint-pps-list-quarantined-messages```

#### Context Example
```json
{
    "Proofpoint": {
        "QuarantinedMessage": [
            {
                "date": "2020-01-15 20:00:00",
                "folder": "Quarantine",
                "from": "john@doe.com",
                "guid": "lR_SjEF1Llfn9gML8YZzpVPUukjXQcPO",
                "host_ip": "[10.54.40.3] [10.54.40.3]",
                "localguid": "6:6:239",
                "messageid": "YATQ2LPCWC3MFA2YUTDH.448380834@example.net",
                "processingserver": "...",
                "rcpts": [
                    "foo@bar.com"
                ],
                "size": "6496",
                "spamscore": "100",
                "subject": "Loan"
            },
            {
                "date": "2020-01-22 10:00:18",
                "folder": "Quarantine",
                "from": "john@doe.com",
                "guid": "edlp0pU9YXkWB5nmat91i9HUl7J-K-ep",
                "host_ip": "[10.12.40.4] [10.12.40.4]",
                "localguid": "6:6:4",
                "messageid": "TLW25LKOCDR72DBE06JF.221045479@email1.example.com",
                "processingserver": "...",
                "rcpts": [
                    "user@test.com"
                ],
                "size": "6143",
                "spamscore": "100",
                "subject": "Loan"
            }
        ]
    }
}
```

#### Human Readable Output

>### Proofpoint Protection Server Quarantined Messages
>|date|folder|from|guid|host_ip|localguid|messageid|processingserver|rcpts|size|spamscore|subject|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-01-15 20:00:00 | Quarantine | john@doe.com | lR_SjEF1Llfn9gML8YZzpVPUukjXQcPO | [10.54.40.3] [10.54.40.3] | 6:6:239 | YATQ2LPCWC3MFA2YUTDH.448380834@example.net | ... | foo@bar.com | 6496 | 100 | Loan |
>| 2020-01-22 10:00:18 | Quarantine | john@doe.com | edlp0pU9YXkWB5nmat91i9HUl7J-K-ep | [10.12.40.4] [10.12.40.4] | 6:6:4 | TLW25LKOCDR72DBE06JF.221045479@email1.example.com | ... | user@test.com | 6143 | 100 | Loan |


### proofpoint-pps-release-message
***
Releases the message to the email infrastructure without further scanning. The message remains in the folder and will be moved to the `deleted_folder` if specified.


#### Base Command

`proofpoint-pps-release-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | Name of the folder where the message is stored (e.g., HIPAA). | Required | 
| local_guid | Message GUID (comma separated string). Format is folder_id:table_id:dbase_id (e.g., 4:2:6), or in Cloud Quarantine format is GUID (e.g., g4fsnj_sTLMk9hECaJ<br/>wmmxwP6lQkr5k7). | Required | 
| deleted_folder | Name of the folder to move the message to. The folder must be for quarantined messages from the same type of module. For example, you cannot send deleted spam messages to a folder for deleted DLP Incidents, and vice versa. | Optional | 
| scan | Whether to rescan the message by the DLP and Attachment Defense filtering modules. Possible values are: true, false. Default is false. | Optional | 
| brand_template | When Encryption is licensed, uses this Branding Template when an encrypted message is released. The Branding Templates are listed on the System &gt; End User Services &gt; Branding Templates page in the management interface (admin GUI). | Optional | 
| security_policy | The Secure Reader response profile to use when release is used for an encrypted message.The Response Profiles are listed on the Information Protection &gt; Encryption &gt; Response Profiles page in the management interface (admin GUI). | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!proofpoint-pps-release-message folder_name=HIPAA local_guid=4:2:6```

#### Human Readable Output

>The message was released successfully.

### proofpoint-pps-resubmit-message
***
Resubmits the message to the filtering modules. The message is removed from the folder and will not be moved to any folder.


#### Base Command

`proofpoint-pps-resubmit-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | Name of the folder where the message is stored (e.g., HIPAA). | Required | 
| local_guid | Message GUID (comma separated string). Format is folder_id:table_id:dbase_id (e.g., 4:2:6), or in Cloud Quarantine format is GUID (e.g., g4fsnj_sTLMk9hECaJ<br/>wmmxwP6lQkr5k7). | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!proofpoint-pps-resubmit-message folder_name=HIPAA local_guid=4:2:6```

#### Human Readable Output

>The message was resubmitted successfully.

### proofpoint-pps-forward-message
***
Forwards the message to another recipient. The message remains in the folder and will be moved to the `deleted_folder` if specified.


#### Base Command

`proofpoint-pps-forward-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | Name of the folder where the message is stored (e.g., HIPAA). | Required | 
| local_guid | Message GUID (comma separated string). Format is folder_id:table_id:dbase_id (e.g., 4:2:6), or in Cloud Quarantine format is GUID (e.g., g4fsnj_sTLMk9hECaJ<br/>wmmxwP6lQkr5k7). | Required | 
| deleted_folder | Name of the folder to move the message to. The folder must be for quarantined messages from the same type of module. For example, you cannot send deleted spam messages to a folder for deleted DLP Incidents, and vice versa. | Optional | 
| subject | Overwrite the original subject for the message with a new subject. | Optional | 
| append_old_subject | Whether to append original subject to the string specified in the `subject` argument. Possible values are: true, false. Default is false. | Optional | 
| from | The envelope from email address. | Optional | 
| header_from | The header from email address. | Optional | 
| to | Recipient email address (comma separated string). | Optional | 
| comment | New message body (The original message is<br/>sent as an attachment). | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!proofpoint-pps-forward-message folder_name=HIPAA local_guid=4:2:6```

#### Human Readable Output

>The message was forwarded successfully.

### proofpoint-pps-move-message
***
Moves the message to the specified target folder.


#### Base Command

`proofpoint-pps-move-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | Name of the folder where the message is stored (e.g., HIPAA). | Required | 
| local_guid | Message GUID (comma separated string). Format is folder_id:table_id:dbase_id (e.g., 4:2:6), or in Cloud Quarantine format is GUID (e.g., g4fsnj_sTLMk9hECaJ<br/>wmmxwP6lQkr5k7). | Required | 
| target_folder | Name of the folder to move the email message to (e.g., PCI).The folder for moved messages must be for quarantined messages from the same type of module. For example, you cannot move spam messages to a folder for DLP Incidents, and vice versa. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!proofpoint-pps-move-message folder_name=HIPAA local_guid=4:2:6 target_folder=PCI```

#### Human Readable Output

>The message was moved successfully.

### proofpoint-pps-delete-message
***
Deletes the message from the Quarantine. The message is removed from its folder and is moved to the `deleted_folder if specified.


#### Base Command

`proofpoint-pps-delete-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | Name of the folder where the message is stored (e.g., HIPAA). | Required | 
| local_guid | Message GUID (comma separated string). Format is folder_id:table_id:dbase_id (e.g., 4:2:6), or in Cloud Quarantine format is GUID (e.g., g4fsnj_sTLMk9hECaJ<br/>wmmxwP6lQkr5k7). | Required | 
| deleted_folder | Name of the folder to move the message to. The folder must be for quarantined messages from the same type of module. For example, you cannot send deleted spam messages to a folder for deleted DLP Incidents, and vice versa. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!proofpoint-pps-delete-message folder_name=HIPAA local_guid=4:2:6```

#### Human Readable Output

>The message was deleted successfully.

### proofpoint-pps-download-message
***
Downloads email message raw data.

#### Base Command

`proofpoint-pps-download-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | Global unique ID of the email message (e.g., g4fsnj_sTLMk9hECaJwmmxwP6lQkr5k7). Can be retrieved using the proofpoint-pps-smart-search command or the proofpoint-pps-list-quarantined-messages. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!proofpoint-pps-download-message guid=g4fsnj_sTLMk9hECaJwmmxwP6lQkr5k7```



