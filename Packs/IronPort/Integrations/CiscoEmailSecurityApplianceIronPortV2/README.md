The Cisco Email Security Appliance is an email security gateway product. It is designed to detect and block a wide variety of email-born threats, such as malware, spam and phishing attempts.
This integration was integrated and tested with version 14.0 of Cisco Email Security Appliance.
## Configure Cisco ESA in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL, e.g., https://XXX.eu.iphmx.com | True |
| Username |  | True |
| Password |  | True |
| Maximum incidents per fetch | Default is 50. Maximum is 100. | False |
| First fetch timestamp | Timestamp in ISO format or number time unit,<br/>e.g., 2022-01-01T00:00:00000Z, 12 hours, 7 days, 3 months, now. | False |
| Filter by | The message field by which to fetch results. | False |
| Filter operator | The message field operator by which to fetch results. | False |
| Filter value | The message filter value by which to fetch results. | False |
| Recipient filter operator | The message recipient filter operator by which to fetch results. | False |
| Recipient filter value | The message recipient filter value by which to fetch results. | False |
| Time to live for the JWT connection token (in minutes). |   | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |


### Troubleshooting
If you encounter multiple recurring errors similar to the following message:
```
Authorization Error: make sure username and password are set correctly.
```
By default, the integration assumes your JWT session tokens have a time to live of 30 minutes. 
If the time to live is shorter, it can lead to the authorization error above. To resolve this error, reduce the value for the *Time to live* for JWT session token parameter. 
By default, this value is 30 minutes and should only be reduced if these errors occur.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cisco-esa-spam-quarantine-message-search
***
Search messages in the spam quarantine.


#### Base Command

`cisco-esa-spam-quarantine-message-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start date in ISO format or &lt;number&gt; &lt;time unit&gt;,<br/>e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | Required | 
| end_date | End date in ISO format or &lt;number&gt; &lt;time unit&gt;,<br/>e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | Required | 
| filter_by | The message field by which to filter the results. Possible values are: from_address, to_address, subject. | Optional | 
| filter_operator | Filter operator by which to filter the results. Possible values are: contains, is, begins_with, ends_with, does_not_contain. | Optional | 
| filter_value | The value to search for. This is a user defined value. D.g., filterValue=abc.com. | Optional | 
| recipient_filter_operator | Recipient operator filter by which to filter the results. Possible values are: contains, is, begins_with, ends_with, does_not_contain. | Optional | 
| recipient_filter_value | Recipient filter by which to filter the results. | Optional | 
| order_by | The attribute by which to order the data in the response. Possible values are: from_address, date, subject, size. | Optional | 
| order_dir | Results order direction. Possible values are: asc, desc. | Optional | 
| page | Page number of paginated results.<br/>Minimum value: 1. | Optional | 
| page_size | Number of results per page. Maximum value 100. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoESA.SpamQuarantineMessage.envelopeRecipient | String | Recipient email address. | 
| CiscoESA.SpamQuarantineMessage.toAddress | String | Recipient email address. | 
| CiscoESA.SpamQuarantineMessage.subject | String | Email subject. | 
| CiscoESA.SpamQuarantineMessage.date | String | Email due date. | 
| CiscoESA.SpamQuarantineMessage.fromAddress | String | Sender email address. | 
| CiscoESA.SpamQuarantineMessage.size | String | email size. | 
| CiscoESA.SpamQuarantineMessage.mid | Number | Message ID. | 

#### Command example
```!cisco-esa-spam-quarantine-message-search start_date=2weeks end_date=now page=3 page_size=2```
#### Context Example
```json
{
    "CiscoESA": {
        "SpamQuarantineMessage": [
            {
                "date": "13 Oct 2022 11:56 (GMT +00:00)",
                "envelopeRecipient": [
                    "test@test.com"
                ],
                "fromAddress": [
                    "Test Test <test@test.com>"
                ],
                "mid": 1573,
                "size": "10.20K",
                "subject": "hello 1",
                "toAddress": [
                    "test@test.com <test@test.com>"
                ]
            },
            {
                "date": "13 Oct 2022 11:54 (GMT +00:00)",
                "envelopeRecipient": [
                    "test@test.com"
                ],
                "fromAddress": [
                    "Test Test <test@test.com>"
                ],
                "mid": 1571,
                "size": "10.20K",
                "subject": "test 2",
                "toAddress": [
                    "test@test.com <test@test.com>"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Spam Quarantine Messages List
>Showing page 3.
> Current page size: 2.
>|Mid|Date|From Address|To Address|Subject|Size|
>|---|---|---|---|---|---|
>| 1573 | 13 Oct 2022 11:56 (GMT +00:00) | Test Test <test@test.com> | "test@test.com" <test@test.com> | hello 1 | 10.20K |
>| 1571 | 13 Oct 2022 11:54 (GMT +00:00) | Test Test <test@test.com> | "test@test.com" <test@test.com> | test 2 | 10.20K |


### cisco-esa-spam-quarantine-message-get
***
Get spam quarantine message details.


#### Base Command

`cisco-esa-spam-quarantine-message-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | Message ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoESA.SpamQuarantineMessage.envelopeRecipient | String | Message recipient. | 
| CiscoESA.SpamQuarantineMessage.toAddress | String | Message recipient. | 
| CiscoESA.SpamQuarantineMessage.messageBody | String | Message body. | 
| CiscoESA.SpamQuarantineMessage.date | String | Message date. | 
| CiscoESA.SpamQuarantineMessage.fromAddress | String | Message sender. | 
| CiscoESA.SpamQuarantineMessage.subject | String | Message subject. | 
| CiscoESA.SpamQuarantineMessage.mid | Number | Message ID. | 

#### Command example
```!cisco-esa-spam-quarantine-message-get message_id=1572```
#### Context Example
```json
{
    "CiscoESA": {
        "SpamQuarantineMessage": {
            "attachments": [],
            "date": "13 Oct 2022 11:56 (GMT +00:00)",
            "envelopeRecipient": [
                "test@test.com"
            ],
            "fromAddress": [
                "Test Test <test@test.com>"
            ],
            "messageBody": "X-MGA-submission: MDFwkBZw0xxrJATK37WrEGRJETolGcH/Ec0fhopBiCRuw7z3sB/lgKvnfUMzauVhijIde5pya7OR9Xn3ykXf7DGOX2PG4OSu//hcfzlboDzNMfYKbQ2c3Zs+883VYMeiUtz+xN/UCnIv9OHLDgJQ93IexI75JnATjKoedFoZpy80/g==<br />\nIronPort-HdrOrdr: A9a23:3J6AuqN81clqn8BcTyb155DYdb4zR+YMi2TDiHoddfUFSKalfp\r\n 6V98jzjSWE7gr5K0tQ4OxoWZPwNk80kKQY3WB/B8bHYOCLggqVxeJZnP3fKl/bakrDH4dmvM\r\n 8OHZSWY+eAbmSS+PyKhTVQZOxQouVvnprJuc7ui1NWCS16YaBp6Al0TiyBFFdteQVADZ0lUL\r\n KB+8tuvVObCDwqR/X+IkNAc/nIptXNmp6jSwUBHQQb5A6Hii7twKLmEiKfwgwVX1p0sPwfGC\r\n n+4kbED5eYwr2GIyznpiDuBlNt6ZXcI+54dYGxYw4uW3TRY0iTFcRcsva5zUgISamUmS0XeZ\r\n /30l4d1o1ImgnsV3Dwrh331wb61jEyr3fk1F+DmHPm5df0XTQgFqN69PBkmzbimjodVetHod\r\n F29nPcs4ASAQLLnSz76dSNXxZ2llCsqX5nleIIlXRQXYYXdbcU9OUkjTdoOYZFGDi/5JEsEe\r\n FoAs2Z7PFKcUmCZ3ScumV02tSjUnk6Ax/72<br />\nX-SLBL-Result: BLOCK-LISTED<br />\nX-IronPort-MailFlowPolicy: $ACCEPTED<br />\nX-IronPort-SenderGroup: ACCEPTLIST<br />\nX-IronPort-Listener: MailFlow<br />\nX-IronPort-Reputation: 3.5<br />\nX-IronPort-MID: 1572<br />\nX-IronPort-RemoteIP: 1.1.1.1<br />\nIronPort-SDR:\r\n\tboundary=_000_AS4P192MB1694AF23A0D358D3FE1B6B71AB259AS4P192MB1694EURP_<br />\nMIME-Version: 1.0<br />\nX-OriginatorOrg: test.com<br />\nX-MS-Exchange-CrossTenant-AuthAs: Internal<br />\nX-MS-Exchange-CrossTenant-AuthSource: test.test.COM<br />\nX-MS-Exchange-CrossTenant-Network-Message-Id: 26a48316-d039-47af-e556-08daad11e929<br />\nX-MS-Exchange-CrossTenant-originalarrivaltime: 13 Oct 2022 11:56:06.4076\r\n (UTC)<br />\nX-MS-Exchange-CrossTenant-fromentityheader: Hosted<br />\nX-MS-Exchange-CrossTenant-id: ed363dfd-16fd-4038-8e58-9237411a84e5<br />\nX-MS-Exchange-CrossTenant-mailboxtype: HOSTED<br />\nX-MS-Exchange-CrossTenant-userprincipalname: CkxCbZ1GZcqcuiVMCbo/AlVFa3/u8MxVWLuGIDg099YXDpyeHTh+tTrYpdMa/AWXF41GXNn/phrOWU4SsBEH6A==<br />\nX-MS-Exchange-Transport-CrossTenantHeadersStamped: DB8P192MB0598<br /><br />\n\r<br>\n",
            "mid": 1572,
            "subject": "hello",
            "toAddress": [
                "test@test.com <test@test.com>"
            ]
        }
    }
}
```

#### Human Readable Output

>### Spam Quarantine Message
>Found spam quarantine message with ID: 1572
>|Mid|From Address|To Address|Date|Subject|
>|---|---|---|---|---|
>| 1572 | Test Test <test@test.com> | "test@test.com" <test@test.com> | 13 Oct 2022 11:56 (GMT +00:00) | hello |


### cisco-esa-spam-quarantine-message-release
***
Release quarantine emails.


#### Base Command

`cisco-esa-spam-quarantine-message-release`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_ids | A comma-separated list of message IDs. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-esa-spam-quarantine-message-release message_ids=1573```
#### Human Readable Output

>Quarantined message 1573 successfully released.

### cisco-esa-spam-quarantine-message-delete
***
Delete quarantine emails.


#### Base Command

`cisco-esa-spam-quarantine-message-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_ids | A comma-separated list of message IDs to delete. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-esa-spam-quarantine-message-delete message_ids=1574```
#### Human Readable Output

>Quarantined message 1574 successfully deleted.

### cisco-esa-list-entry-get
***
Get spam quarantine blocklist/safelist entry.


#### Base Command

`cisco-esa-list-entry-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_type | List entry type. Possible values are: blocklist, safelist. | Required | 
| page | Page number of paginated results.<br/>Minimum value: 1. | Optional | 
| page_size | Number of results per page. Maximum value 100. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| order_by | The attribute by which to order the data in the response. Possible values are: recipient, sender. | Optional | 
| order_dir | Results order direction. Possible values are: asc, desc. | Optional | 
| view_by | View results by. Possible values are: recipient, sender. Default is recipient. | Optional | 
| search | Search for recipients or senders in blocklist/safelist with 'contains' operator.<br/>e.g., test@test.com, test.com<br/>This is only supported for the argument view_by=recipient. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoESA.ListEntry.Blocklist.senderList | String | Sender list. | 
| CiscoESA.ListEntry.Blocklist.recipientAddress | String | Recipient address. | 
| CiscoESA.ListEntry.Blocklist.recipientList | String | Recipient list. | 
| CiscoESA.ListEntry.Blocklist.senderAddress | String | Sender address. | 
| CiscoESA.ListEntry.Safelist.senderList | String | Sender list. | 
| CiscoESA.ListEntry.Safelist.recipientAddress | String | Recipient address. | 
| CiscoESA.ListEntry.Safelist.recipientList | String | Recipient list. | 
| CiscoESA.ListEntry.Safelist.senderAddress | String | Sender address. | 

#### Command example
```!cisco-esa-list-entry-get entry_type=safelist page=2 page_size=3 view_by=recipient order_by=recipient order_dir=desc```
#### Context Example
```json
{
    "CiscoESA": {
        "ListEntry": {
            "Safelist": [
                {
                    "recipientAddress": "test4@test.com",
                    "senderList": [
                        "test@test.com"
                    ]
                },
                {
                    "recipientAddress": "test3@test.com",
                    "senderList": [
                        "test@test.com"
                    ]
                },
                {
                    "recipientAddress": "test2@test.com",
                    "senderList": [
                        "test@test.com"
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Safelist Entries
>Showing page 2.
> Current page size: 3.
>|Recipient Address|Sender List|
>|---|---|
>| test4@test.com | test@test.com |
>| test3@test.com | test@test.com |
>| test2@test.com | test@test.com |


### cisco-esa-list-entry-add
***
Add spam quarantine blocklist/safelist entry.


#### Base Command

`cisco-esa-list-entry-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_type | List entry type. Possible values are: blocklist, safelist. | Required | 
| view_by | Add list entry by recipient/sender.<br/>When view_by = recipient, recipient_addresses and sender_list are mandatory.<br/>When view_by = sender, sender_addresses and recipient_list are mandatory. Possible values are: recipient, sender. Default is recipient. | Optional | 
| recipient_addresses | A comma-separated list of recipient addresses to add. | Optional | 
| sender_list | A comma-separated list of senders to add. | Optional | 
| sender_addresses | A comma-separated list of sender addresses to add. | Optional | 
| recipient_list | A comma-separated list of recipients to add. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-esa-list-entry-add entry_type=blocklist view_by=recipient recipient_addresses=test@test.com sender_list=t1@test.com,t2@test.com```
#### Human Readable Output

>Successfully added t1@test.com, t2@test.com senders to test@test.com recipients in blocklist.

### cisco-esa-list-entry-append
***
Append spam quarantine blocklist/safelist entry.


#### Base Command

`cisco-esa-list-entry-append`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_type | List entry type. Possible values are: blocklist, safelist. | Required | 
| view_by | Append list entry by recipient/sender.<br/>When view_by = recipient, recipient_addresses and sender_list are mandatory.<br/>When view_by = sender, sender_addresses and recipient_list are mandatory. Possible values are: recipient, sender. Default is recipient. | Optional | 
| recipient_list | A comma-separated list of recipients to append. | Optional | 
| sender_list | A comma-separated list of senders to append. | Optional | 
| recipient_addresses | A comma-separated list of recipient addresses to append. | Optional | 
| sender_addresses | A comma-separated list of sender addresses to append. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-esa-list-entry-append entry_type=blocklist recipient_addresses=test@test.com sender_list=t4@test.com```
#### Human Readable Output

>Successfully appended t4@test.com senders to test@test.com recipients in blocklist.

### cisco-esa-list-entry-edit
***
Edit spam quarantine blocklist/safelist entry. Using this command will override the existing value.


#### Base Command

`cisco-esa-list-entry-edit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_type | List entry type. Possible values are: blocklist, safelist. | Required | 
| view_by | Edit list entry by recipient/sender.<br/>When view_by = recipient, recipient_addresses and sender_list are mandatory.<br/>When view_by = sender, sender_addresses and recipient_list are mandatory. Possible values are: recipient, sender. Default is recipient. | Optional | 
| recipient_list | A comma-separated list of recipients to edit. | Optional | 
| sender_list | A comma-separated list of senders to edit. | Optional | 
| recipient_addresses | A comma-separated list of recipient addresses to edit. | Optional | 
| sender_addresses | A comma-separated list of sender addresses to edit. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-esa-list-entry-edit entry_type=blocklist view_by=recipient recipient_addresses=test@test.com sender_list=t5@test.com,t6@test.com```
#### Human Readable Output

>Successfully edited test@test.com recipients' senders to t5@test.com, t6@test.com in blocklist.

### cisco-esa-list-entry-delete
***
Delete spam quarantine blocklist/safelist entry.


#### Base Command

`cisco-esa-list-entry-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_type | List entry type. Possible values are: blocklist, safelist. | Required | 
| view_by | Delete list entry by recipient/sender.<br/>When view_by = recipient, recipient_list is mandatory.<br/>When view_by = sender, sender_list is mandatory. Possible values are: recipient, sender. Default is recipient. | Optional | 
| recipient_list | List of recipient/sender addresses to delete. | Optional | 
| sender_list | List of recipient/sender addresses to delete. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-esa-list-entry-delete entry_type=blocklist view_by=recipient recipient_list=test@test.com```
#### Human Readable Output

>Successfully deleted test@test.com recipients from blocklist.

### cisco-esa-message-search
***
Search tracking messages.


#### Base Command

`cisco-esa-message-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start date in ISO format or &lt;number&gt; &lt;time unit&gt;,<br/>e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | Required | 
| end_date | End date in ISO format or &lt;number&gt; &lt;time unit&gt;,<br/>e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | Required | 
| page | Page number of paginated results.<br/>Minimum value: 1. | Optional | 
| page_size | Number of results per page. Maximum value 100. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| sender_filter_operator | Sender filter operator. Possible values are: contains, is, begins_with. | Optional | 
| sender_filter_value | Sender filter value. | Optional | 
| recipient_filter_operator | Recipient filter operator. Possible values are: contains, is, begins_with. | Optional | 
| recipient_filter_value | Recipient filter value. | Optional | 
| subject_filter_operator | Subject filter operator. Possible values are: contains, is, begins_with. | Optional | 
| subject_filter_value | Subject filter value. | Optional | 
| attachment_name_operator | Attachment name operator. Possible values are: contains, is, begins_with. | Optional | 
| attachment_name_value | Attachment name value. | Optional | 
| file_sha_256 | SHA256 must be 64 characters long and can contain only "0-9" and "a-f" characters.<br/>e.g. e0d123e5f316bef78bfdf5a008837577e0d123e5f316bef78bfdf5a008837577. | Optional | 
| custom_query | Custom query for cisco ESA's advanced filters.<br/>Syntax: &lt;key&gt;=&lt;value&gt;;&lt;key&gt;=&lt;value&gt;;&lt;key&gt;=&lt;value&gt;<br/>e.g., graymail=True;message_delivered=True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoESA.Message.hostName | String | Email gateway hostname. | 
| CiscoESA.Message.friendly_from | String | Friendly formatted sender email address. | 
| CiscoESA.Message.isCompleteData | String | Whether the entire data was pulled. | 
| CiscoESA.Message.messageStatus | String | Message delivery status. | 
| CiscoESA.Message.recipientMap | String | Recipients list. | 
| CiscoESA.Message.senderIp | String | Sender IP address. | 
| CiscoESA.Message.mailPolicy | String | Matched mail policy. | 
| CiscoESA.Message.senderGroup | String | Matched sender group. | 
| CiscoESA.Message.subject | String | Subject of email message. | 
| CiscoESA.Message.mid | Number | Message ID. | 
| CiscoESA.Message.senderDomain | String | Domain of email message sender. | 
| CiscoESA.Message.finalSubject | String | Extended email subject. | 
| CiscoESA.Message.direction | String | Message direction, incoming or outgoing. | 
| CiscoESA.Message.icid | Number | An Injection Connection ID \(ICID\). A numerical identifier for an individual SMTP connection to the system. | 
| CiscoESA.Message.replyTo | String | Email message reply to. | 
| CiscoESA.Message.timestamp | String | Time of the email message. | 
| CiscoESA.Message.messageID | String | Extended message ID. | 
| CiscoESA.Message.verdictChart | String | Verdict visual chart ID. | 
| CiscoESA.Message.recipient | String | Recipients email addresses list. | 
| CiscoESA.Message.sender | String | Sender email address. | 
| CiscoESA.Message.serialNumber | String | Cisco ESA email gateway serial number. | 
| CiscoESA.Message.allIcid | Number | ICIDs list. | 
| CiscoESA.Message.sbrs | String | Sender Base Reputation Scores. | 

#### Command example
```!cisco-esa-message-search start_date=1month end_date=now page=3 page_size=2 subject_filter_operator=contains subject_filter_value=test```
#### Context Example
```json
{
    "CiscoESA": {
        "Message": [
            {
                "allIcid": [
                    29969
                ],
                "direction": "incoming",
                "finalSubject": {
                    "1438": "test"
                },
                "friendly_from": [
                    "test@test.com"
                ],
                "hostName": "",
                "icid": 29969,
                "isCompleteData": "N/A",
                "mailPolicy": [
                    "DEFAULT"
                ],
                "messageID": {
                    "1438": "<test@test.test.COM>"
                },
                "messageStatus": {
                    "1438": "Quarantined by Anti-Spam/Graymail"
                },
                "mid": [
                    1438
                ],
                "morDetails": {},
                "recipient": [
                    "test@test.com"
                ],
                "recipientMap": {
                    "1438": [
                        "test@test.com"
                    ]
                },
                "replyTo": "N/A",
                "sbrs": "3.5",
                "sender": "test@test.com",
                "senderDomain": "test.com",
                "senderGroup": "ACCEPTLIST",
                "senderIp": "1.1.1.1",
                "serialNumber": "test-test",
                "subject": "test",
                "timestamp": "2022-10-03T11:54:28Z",
                "unique_message_id": "1438",
                "verdictChart": {
                    "1438": "16140210"
                }
            },
            {
                "allIcid": [
                    19653
                ],
                "direction": "incoming",
                "finalSubject": {
                    "758": "test123"
                },
                "friendly_from": [
                    "test@test.com"
                ],
                "hostName": "",
                "icid": 19653,
                "isCompleteData": "N/A",
                "mailPolicy": [
                    "DEFAULT"
                ],
                "messageID": {
                    "758": "<test@test.test.COM>"
                },
                "messageStatus": {
                    "758": "Quarantined by Anti-Spam/Graymail"
                },
                "mid": [
                    758
                ],
                "morDetails": {},
                "recipient": [
                    "test@test.com"
                ],
                "recipientMap": {
                    "758": [
                        "test@test.com"
                    ]
                },
                "replyTo": "N/A",
                "sbrs": "3.5",
                "sender": "test@test.com",
                "senderDomain": "test.com",
                "senderGroup": "ACCEPTLIST",
                "senderIp": "1.1.1.1",
                "serialNumber": "test-test",
                "subject": "test123",
                "timestamp": "2022-09-20T15:03:40Z",
                "unique_message_id": "758",
                "verdictChart": {
                    "758": "16130210"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Messages List
>Showing page 3.
> Current page size: 2.
>|Mid|All Icid|Serial Number|Sender|Recipient|Subject|Message Status|Timestamp|Sender Ip|Sbrs|
>|---|---|---|---|---|---|---|---|---|---|
>| 1438 | 29969 | test-test | test@test.com | test@test.com | test | 1438: Quarantined by Anti-Spam/Graymail | 2022-10-03T11:54:28Z | 1.1.1.1 | 3.5 |
>| 758 | 19653 | test-test | test@test.com | test@test.com | test123 | 758: Quarantined by Anti-Spam/Graymail | 2022-09-20T15:03:40Z | 1.1.1.1 | 3.5 |


### cisco-esa-message-details-get
***
Get message details.


#### Base Command

`cisco-esa-message-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial_number | Email gateway serial number. | Required | 
| message_ids | Message ID list. | Required | 
| injection_connection_id | Injection connection ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoESA.Message.sdrAge | String | Sender domain reputation age. | 
| CiscoESA.Message.attachments | String | Message attachments. | 
| CiscoESA.Message.hostName | String | Email gateway hostname. | 
| CiscoESA.Message.isCompleteData | Boolean | Whether the entire data was pulled. | 
| CiscoESA.Message.messageStatus | String | Message delivery status. | 
| CiscoESA.Message.mailPolicy | String | Matched mail policy. | 
| CiscoESA.Message.senderGroup | String | Matched sender group. | 
| CiscoESA.Message.subject | String | Subject of email message. | 
| CiscoESA.Message.showSummaryTimeBox | Boolean | Whether to display the summary timebox. | 
| CiscoESA.Message.sdrCategory | String | Sender domain reputation category. | 
| CiscoESA.Message.mid | Number | Message ID. | 
| CiscoESA.Message.sendingHostSummary.reverseDnsHostname | String | Sending host reverse DNS hostname. | 
| CiscoESA.Message.sendingHostSummary.ipAddress | String | Sending host IP address. | 
| CiscoESA.Message.sendingHostSummary.sbrsScore | String | Sending host sender base reputation scores. | 
| CiscoESA.Message.direction | String | Message direction, incoming or outgoing. | 
| CiscoESA.Message.smtpAuthId | String | SMTP authorization ID. | 
| CiscoESA.Message.midHeader | String | Message ID header. | 
| CiscoESA.Message.timestamp | String | Email message time. | 
| CiscoESA.Message.showDLP | Boolean | Whether the DLP report is available. | 
| CiscoESA.Message.messageSize | String | Email message size. | 
| CiscoESA.Message.sdrReputation | String | Sender domain reputation. | 
| CiscoESA.Message.showURL | Boolean | Whether the URL report is available. | 
| CiscoESA.Message.recipient | String | Message recipient email address. | 
| CiscoESA.Message.sender | String | Message sender email address. | 
| CiscoESA.Message.showAMP | Boolean | Whether the AMP report is available. | 
| CiscoESA.Message.summary.timestamp | String | Event summary time. | 
| CiscoESA.Message.summary.description | String | Event summary description | 
| CiscoESA.Message.summary.lastEvent | Boolean | Whether this is the last summary event. | 
| CiscoESA.Message.allIcid | Number | ICIDs list. | 
| CiscoESA.Message.headerFrom | String | Email message header from. | 

#### Command example
```!cisco-esa-message-details-get serial_number=test-test message_ids=1576 injection_connection_id=36859```
#### Context Example
```json
{
    "CiscoESA": {
        "Message": {
            "allIcid": [
                36859
            ],
            "ampTgCategories": [],
            "attachments": [],
            "direction": "incoming",
            "headerFrom": "test@test.com",
            "hostName": "(Name unresolved,  SN:test-test)",
            "isCompleteData": false,
            "mailPolicy": [
                "DEFAULT"
            ],
            "messageSize": "9.17 (KB)",
            "messageStatus": "Quarantined by Anti-Spam/Graymail",
            "mid": [
                1576
            ],
            "midHeader": "<test@test.test.com>",
            "recipient": [
                "test@test.com"
            ],
            "sdrAge": "30 days (or greater)",
            "sdrCategory": "N/A",
            "sdrReputation": "Neutral",
            "sdrThreatLevels": "3",
            "sender": "test@test.com",
            "senderGroup": "ACCEPTLIST",
            "sendingHostSummary": {
                "ipAddress": "1.1.1.1",
                "reverseDnsHostname": "mail-test.test.test.test.com (verified)",
                "sbrsScore": "3.5"
            },
            "showAMP": false,
            "showDLP": false,
            "showSummaryTimeBox": true,
            "showURL": false,
            "smtpAuthId": "",
            "subject": "hello 4",
            "summary": [
                {
                    "description": "Incoming connection (ICID 36859) has sender_group: ACCEPTLIST, sender_ip: 1.1.1.1 and sbrs: 3.5",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:22Z"
                },
                {
                    "description": "Protocol SMTP interface Data 1  (IP 1.1.1.1) on incoming connection (ICID 36859) from sender IP 1.1.1.1. Reverse DNS  host mail-test.test.test.test.com verified yes.",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:22Z"
                },
                {
                    "description": "(ICID 36859) ACCEPT sender group ACCEPTLIST match sbrs[0.0:10.0] SBRS 3.5 country Ireland",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:22Z"
                },
                {
                    "description": "Incoming connection (ICID 36859) successfully accepted TLS protocol TLSv1.2 cipher test-test-test.",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 Sender Domain: test.com",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Start message 1576 on incoming connection (ICID 36859).",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 enqueued on incoming connection (ICID 36859) from test@test.com.",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 direction: incoming",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 Domains for which SDR is requested: reverse DNS host: mail-test.test.test.test.com, helo: test.test.test.com, env-from: test.com, header_from: Not Present, reply_to: Not Present",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 Consolidated Sender Threat Level: Neutral, Threat Category: N/A, Suspected Domain(s) : N/A (other reasons for verdict). Sender Maturity: 30 days (or greater) for domain: test.com",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 on incoming connection (ICID 36859) added recipient (test@test.com).",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 SPF: mailfrom identity test@test.com Pass",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 DKIM: pass signature verified (d=test.test.com s=selector2-test-test-com i=@test.test.com)",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576: DMARC Verification skipped (No record found for the sending domain).",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 contains message ID header '<test@test.test.com>'.",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 original subject on injection: hello 4",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 Domains for which SDR is requested: reverse DNS host: mail-test.test.test.test.com, helo: test.test.test.com, env-from: test.com, header_from: test.com, reply_to: Not Present",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 Consolidated Sender Threat Level: Neutral, Threat Category: N/A, Suspected Domain(s) : N/A (other reasons for verdict). Sender Maturity: 30 days (or greater) for domain: test.com",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 (9389 bytes) from test@test.com ready.",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 has sender_group: ACCEPTLIST, sender_ip: 1.1.1.1 and sbrs: 3.5",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 matched per-recipient policy DEFAULT for inbound mail policies.",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 scanned by Anti-Spam engine: SLBL. Interim verdict: Positive",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 scanned by Anti-Spam engine: SLBL. Final verdict: Positive",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Incoming connection (ICID 36859) lost.",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 scanned by Anti-Virus engine McAfee. Interim verdict: CLEAN",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 scanned by Anti-Virus engine Sophos. Interim verdict: CLEAN",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 scanned by Anti-Virus engine. Final verdict: Negative ",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 scanned by Advanced Malware Protection engine. Final verdict: SKIPPED(no attachment in message)",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:23Z"
                },
                {
                    "description": "Message 1576 scanned by Outbreak Filters. Verdict: Negative",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:24Z"
                },
                {
                    "description": "Message 1576 queued for delivery.",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:24Z"
                },
                {
                    "description": "Remote procedure call connection (RCID 1) started for message 1576 to local Spam Quarantine.",
                    "lastEvent": false,
                    "timestamp": "2022-10-13T11:56:27Z"
                },
                {
                    "description": "Message 1576 quarantined in Spam Quarantine.",
                    "lastEvent": true,
                    "timestamp": "2022-10-13T11:56:27Z"
                }
            ],
            "timestamp": "2022-10-13T11:56:23Z",
            "unique_message_id": "1576"
        }
    }
}
```

#### Human Readable Output

>### Message Details
>Found message with ID 1576.
>|Mid|All Icid|Subject|Sender|Recipient|Timestamp|Message Size|Sending Host Summary|Message Status|Direction|Mail Policy|Sender Group|Show AMP|Show DLP|Show URL|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1576 | 36859 | hello 4 | test@test.com | test@test.com | 2022-10-13T11:56:23Z | 9.17 (KB) | reverseDnsHostname: mail-test.test.test.test.com (verified)<br/>ipAddress: 1.1.1.1<br/>sbrsScore: 3.5 | Quarantined by Anti-Spam/Graymail | incoming | DEFAULT | ACCEPTLIST | false | false | false |
>### Message Summary
>|Description|Timestamp|Last Event|
>|---|---|---|
>| Incoming connection (ICID 36859) has sender_group: ACCEPTLIST, sender_ip: 1.1.1.1 and sbrs: 3.5 | 2022-10-13T11:56:22Z | false |
>| Protocol SMTP interface Data 1  (IP 1.1.1.1) on incoming connection (ICID 36859) from sender IP 1.1.1.1. Reverse DNS  host mail-test.test.test.test.com verified yes. | 2022-10-13T11:56:22Z | false |
>| (ICID 36859) ACCEPT sender group ACCEPTLIST match sbrs[0.0:10.0] SBRS 3.5 country Ireland | 2022-10-13T11:56:22Z | false |
>| Incoming connection (ICID 36859) successfully accepted TLS protocol TLSv1.2 cipher test-test-test. | 2022-10-13T11:56:23Z | false |
>| Message 1576 Sender Domain: test.com | 2022-10-13T11:56:23Z | false |
>| Start message 1576 on incoming connection (ICID 36859). | 2022-10-13T11:56:23Z | false |
>| Message 1576 enqueued on incoming connection (ICID 36859) from test@test.com. | 2022-10-13T11:56:23Z | false |
>| Message 1576 direction: incoming | 2022-10-13T11:56:23Z | false |
>| Message 1576 Domains for which SDR is requested: reverse DNS host: mail-test.test.test.test.com, helo: test.test.test.com, env-from: test.com, header_from: Not Present, reply_to: Not Present | 2022-10-13T11:56:23Z | false |
>| Message 1576 Consolidated Sender Threat Level: Neutral, Threat Category: N/A, Suspected Domain(s) : N/A (other reasons for verdict). Sender Maturity: 30 days (or greater) for domain: test.com | 2022-10-13T11:56:23Z | false |
>| Message 1576 on incoming connection (ICID 36859) added recipient (test@test.com). | 2022-10-13T11:56:23Z | false |
>| Message 1576 SPF: mailfrom identity test@test.com Pass | 2022-10-13T11:56:23Z | false |
>| Message 1576 DKIM: pass signature verified (d=test.test.com s=selector2-test-test-com i=@test.test.com) | 2022-10-13T11:56:23Z | false |
>| Message 1576: DMARC Verification skipped (No record found for the sending domain). | 2022-10-13T11:56:23Z | false |
>| Message 1576 contains message ID header '<test@test.test.com>'. | 2022-10-13T11:56:23Z | false |
>| Message 1576 original subject on injection: hello 4 | 2022-10-13T11:56:23Z | false |
>| Message 1576 Domains for which SDR is requested: reverse DNS host: mail-test.test.test.test.com, helo: test.test.test.com, env-from: test.com, header_from: test.com, reply_to: Not Present | 2022-10-13T11:56:23Z | false |
>| Message 1576 Consolidated Sender Threat Level: Neutral, Threat Category: N/A, Suspected Domain(s) : N/A (other reasons for verdict). Sender Maturity: 30 days (or greater) for domain: test.com | 2022-10-13T11:56:23Z | false |
>| Message 1576 (9389 bytes) from test@test.com ready. | 2022-10-13T11:56:23Z | false |
>| Message 1576 has sender_group: ACCEPTLIST, sender_ip: 1.1.1.1 and sbrs: 3.5 | 2022-10-13T11:56:23Z | false |
>| Message 1576 matched per-recipient policy DEFAULT for inbound mail policies. | 2022-10-13T11:56:23Z | false |
>| Message 1576 scanned by Anti-Spam engine: SLBL. Interim verdict: Positive | 2022-10-13T11:56:23Z | false |
>| Message 1576 scanned by Anti-Spam engine: SLBL. Final verdict: Positive | 2022-10-13T11:56:23Z | false |
>| Incoming connection (ICID 36859) lost. | 2022-10-13T11:56:23Z | false |
>| Message 1576 scanned by Anti-Virus engine McAfee. Interim verdict: CLEAN | 2022-10-13T11:56:23Z | false |
>| Message 1576 scanned by Anti-Virus engine Sophos. Interim verdict: CLEAN | 2022-10-13T11:56:23Z | false |
>| Message 1576 scanned by Anti-Virus engine. Final verdict: Negative  | 2022-10-13T11:56:23Z | false |
>| Message 1576 scanned by Advanced Malware Protection engine. Final verdict: SKIPPED(no attachment in message) | 2022-10-13T11:56:23Z | false |
>| Message 1576 scanned by Outbreak Filters. Verdict: Negative | 2022-10-13T11:56:24Z | false |
>| Message 1576 queued for delivery. | 2022-10-13T11:56:24Z | false |
>| Remote procedure call connection (RCID 1) started for message 1576 to local Spam Quarantine. | 2022-10-13T11:56:27Z | false |
>| Message 1576 quarantined in Spam Quarantine. | 2022-10-13T11:56:27Z | true |


### cisco-esa-message-amp-details-get
***
Get message AMP summary details.


#### Base Command

`cisco-esa-message-amp-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial_number | Email gateway serial number. | Required | 
| message_ids | Message ID list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoESA.AMPDetail.sdrAge | String | Sender domain reputation age. | 
| CiscoESA.AMPDetail.attachments | String | Message attachments. | 
| CiscoESA.AMPDetail.hostName | String | Email gateway hostname. | 
| CiscoESA.AMPDetail.direction | String | Message direction, incoming or outgoing. | 
| CiscoESA.AMPDetail.messageStatus | String | Message delivery status. | 
| CiscoESA.AMPDetail.senderGroup | String | Matched sender group. | 
| CiscoESA.AMPDetail.subject | String | Email message subject. | 
| CiscoESA.AMPDetail.sdrCategory | String | Sender domain reputation category. | 
| CiscoESA.AMPDetail.mid | Number | Message ID. | 
| CiscoESA.AMPDetail.ampDetails.timestamp | String | AMP event summary details timestamp. | 
| CiscoESA.AMPDetail.ampDetails.description | String | AMP event summary details description. | 
| CiscoESA.AMPDetail.ampDetails.lastEvent | Boolean | AMP event summary details last event. | 
| CiscoESA.AMPDetail.smtpAuthId | String | SMTP authorization ID. | 
| CiscoESA.AMPDetail.midHeader | String | Message ID header. | 
| CiscoESA.AMPDetail.timestamp | String | Email message time. | 
| CiscoESA.AMPDetail.messageSize | String | Email message size. | 
| CiscoESA.AMPDetail.sdrThreatLevels | String | Sender domain reputation threat levels. | 
| CiscoESA.AMPDetail.sdrReputation | String | Sender domain reputation. | 
| CiscoESA.AMPDetail.recipient | String | Message recipient email address. | 
| CiscoESA.AMPDetail.sender | String | Message sender email address. | 
| CiscoESA.AMPDetail.showAMPDetails | Boolean | Whether to show AMP details. | 
| CiscoESA.AMPDetail.allIcid | Number | ICIDs list. | 
| CiscoESA.AMPDetail.headerFrom | String | Email header from. | 

#### Command example
```!cisco-esa-message-amp-details-get message_ids=741,742,743 serial_number=test-test```
#### Context Example
```json
{
    "CiscoESA": {
        "AMPDetail": {
            "allIcid": [
                19599
            ],
            "ampDetails": [
                {
                    "description": "File reputation query initiating. File Name = bear.jpg, MID = 741, File Size = 325663 bytes, File Type = image/jpeg",
                    "timestamp": "2022-09-20T13:31:18Z"
                },
                {
                    "description": "Response received for file reputation query from Cache. File Name = bear.jpg, MID = 741, Disposition = FILE UNKNOWN, Malware = None, Analysis Score = 0, sha256 = 23a9113530549916cd5b410edee79cb5a0fc01233eb9051f9c882a2e7c3fbfbe, upload_action = Recommended to send the file for analysis, verdict_source = AMP, Suspected Malware Categories = None",
                    "timestamp": "2022-09-20T13:31:18Z"
                },
                {
                    "description": "File not uploaded for analysis. MID = 741 File SHA256[23a9113530549916cd5b410edee79cb5a0fc01233eb9051f9c882a2e7c3fbfbe] file mime[image/jpeg] Reason: The file type is not configured for analysis",
                    "lastEvent": true,
                    "timestamp": "2022-09-20T13:31:18Z"
                }
            ],
            "ampTgCategories": [],
            "attachments": [
                "bear.jpg"
            ],
            "direction": "incoming",
            "headerFrom": "test@test.com",
            "hostName": "(Name unresolved,  SN:test-test)",
            "messageSize": "439.26 (KB)",
            "messageStatus": "Quarantined by Multiple Engines",
            "mid": [
                741,
                742,
                743
            ],
            "midHeader": "<test@test.test.com>",
            "recipient": [
                "test@test.com"
            ],
            "sdrAge": "30 days (or greater)",
            "sdrCategory": "N/A",
            "sdrReputation": "Neutral",
            "sdrThreatLevels": "3",
            "sender": "test@test.com",
            "senderGroup": "ACCEPTLIST",
            "sendingHostSummary": {},
            "showAMPDetails": true,
            "smtpAuthId": "",
            "subject": "Fwd: test",
            "timestamp": "2022-09-20T13:31:15Z"
        }
    }
}
```

#### Human Readable Output

>### Message AMP Report Details
>Found AMP details for message ID 741, 742, 743.
>|Mid|All Icid|Subject|Sender|Recipient|Attachments|Timestamp|Message Size|Message Status|Direction|Sender Group|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 741,<br/>742,<br/>743 | 19599 | Fwd: test | test@test.com | test@test.com | bear.jpg | 2022-09-20T13:31:15Z | 439.26 (KB) | Quarantined by Multiple Engines | incoming | ACCEPTLIST |
>### Message AMP Report Details Summary
>|Description|Timestamp|
>|---|---|
>| File reputation query initiating. File Name = bear.jpg, MID = 741, File Size = 325663 bytes, File Type = image/jpeg | 2022-09-20T13:31:18Z |
>| Response received for file reputation query from Cache. File Name = bear.jpg, MID = 741, Disposition = FILE UNKNOWN, Malware = None, Analysis Score = 0, sha256 = 23a9113530549916cd5b410edee79cb5a0fc01233eb9051f9c882a2e7c3fbfbe, upload_action = Recommended to send the file for analysis, verdict_source = AMP, Suspected Malware Categories = None | 2022-09-20T13:31:18Z |
>| File not uploaded for analysis. MID = 741 File SHA256[23a9113530549916cd5b410edee79cb5a0fc01233eb9051f9c882a2e7c3fbfbe] file mime[image/jpeg] Reason: The file type is not configured for analysis | 2022-09-20T13:31:18Z |


### cisco-esa-message-dlp-details-get
***
Get message DLP summary details.


#### Base Command

`cisco-esa-message-dlp-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial_number | Email gateway serial number. | Required | 
| message_ids | Message ID list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoESA.DLPDetail.direction | String | Message direction, incoming or outgoing. | 
| CiscoESA.DLPDetail.smtpAuthId | String | SMTP authorization ID. | 
| CiscoESA.DLPDetail.sdrAge | String | Sender domain reputation age. | 
| CiscoESA.DLPDetail.sender | String | Message sender email address. | 
| CiscoESA.DLPDetail.midHeader | String | Message ID header. | 
| CiscoESA.DLPDetail.timestamp | String | Email message time. | 
| CiscoESA.DLPDetail.sdrCategory | String | Sender domain reputation category. | 
| CiscoESA.DLPDetail.hostName | String | Email gateway hostname. | 
| CiscoESA.DLPDetail.mid | Number | Message ID. | 
| CiscoESA.DLPDetail.attachments | String | Message attachments. | 
| CiscoESA.DLPDetail.messageSize | String | Email message size. | 
| CiscoESA.DLPDetail.dlpDetails.violationSeverity | String | DLP details violation severity. | 
| CiscoESA.DLPDetail.dlpDetails.dlpMatchedContent.messagePartMatch.classifier | String | DLP matched content classifier. | 
| CiscoESA.DLPDetail.dlpDetails.dlpMatchedContent.messagePartMatch.classifierMatch | String | DLP matched content classifier match. | 
| CiscoESA.DLPDetail.dlpDetails.dlpMatchedContent.messagePart | String | DLP matched content message part. | 
| CiscoESA.DLPDetail.dlpDetails.mid | String | DLP message ID. | 
| CiscoESA.DLPDetail.dlpDetails.riskFactor | Number | DLP risk factor. | 
| CiscoESA.DLPDetail.dlpDetails.dlpPolicy | String | DLP policy. | 
| CiscoESA.DLPDetail.sdrThreatLevels | String | Sender domain reputation threat levels. | 
| CiscoESA.DLPDetail.sdrReputation | String | Sender domain reputation. | 
| CiscoESA.DLPDetail.messageStatus | String | Message delivery status. | 
| CiscoESA.DLPDetail.allIcid | Number | ICIDs list. | 
| CiscoESA.DLPDetail.senderGroup | String | Matched sender group. | 
| CiscoESA.DLPDetail.recipient | String | Message recipient email address. | 
| CiscoESA.DLPDetail.subject | String | Email message subject. | 
| CiscoESA.DLPDetail.headerFrom | String | Email header from. | 

#### Command example
```!cisco-esa-message-dlp-details-get message_ids=1131 serial_number=test-test```
#### Context Example
```json
{
    "CiscoESA": {
        "DLPDetail": {
            "allIcid": [
                20460
            ],
            "ampTgCategories": [],
            "attachments": [],
            "direction": "outgoing",
            "dlpDetails": {
                "dlpMatchedContent": [
                    {
                        "messagePart": "Message",
                        "messagePartMatch": [
                            {
                                "classifier": "Proper Names (US)",
                                "classifierMatch": [
                                    "Tim Lowe",
                                    "Albert Iorio",
                                    "Adriane Morrison",
                                    "Lisa Garrison",
                                    "Charles Jackson",
                                    "Danny Reyes",
                                    "Christopher Diaz",
                                    "Marjorie Green",
                                    "Mark Hall",
                                    "Stacey Peacock",
                                    "Robert Aragon",
                                    "Thomas Conley"
                                ]
                            },
                            {
                                "classifier": "Personal Information (US)",
                                "classifierMatch": [
                                    "Test Test <test@test.com>\nSubject: DLP\n\nFirst and Last Name     SSN     Credit Card Number\nVisa MC AMEX\nRobert Aragon   489-36-8350     4929-3813-3266-4295\nAshley Borden   514-14-8905     5370-4638-8881-3020\nThomas Conley   690-05-5315     4916-4811-5814-8111\nSusan Davis     421-37-1396     4916-4034-9269-8783\nChristopher Diaz        458-02-6124     5299-1561-5689-1938\nRick Edwards    612-20-6832     5293-8502-0071-3058\nVictor Faulkner 300-62-3266     5548-0246-6336-5664\nLisa Garrison   660-03-8360     4539-5385-7425-5825\nMarjorie Green  213-46-8915     4916-9766-5240-6147\nMark Hall       449-48-3135     4556-0072-1294-7415\nJames Heard     559-81-1301     4532-4220-6922-9909\nAlbert Iorio    322-84-2281     4916-6734-7572-5015\nCharles Jackson 646-44-9061     5218-0144-2703-9266\nTeresa Kaminski 465-73-5022     5399-0706-4128-0178\nTim Lowe        044-34-6954     5144-8691-2776-1108\nMonte Mceachern 477-36-0282     5527-1247-5046-7780\nAdriane Morrison        421-90-3440     4539-0031-3703-0728\nJerome Munsch   524-02-7657     5180-3807-3679-8221\nAgnes Nelson    205-52-0027     5413-4428-0145-0036\nLynette Oyola   587-03-2682     4532-9929-3036-9308\nStacey Peacock  687-05-8365     5495-8602-4508-6804\nJulie Renfro    751-01-2327"
                                ]
                            }
                        ]
                    }
                ],
                "dlpPolicy": "US HIPAA and HITECH (Low Threshold)",
                "mid": "1131",
                "riskFactor": 72,
                "violationSeverity": "HIGH"
            },
            "headerFrom": "test@test.com",
            "hostName": "(Name unresolved,  SN:test-test)",
            "messageSize": "29.67 (KB)",
            "messageStatus": "Delivered",
            "mid": [
                1131
            ],
            "midHeader": "<test@test.test.com>",
            "recipient": [
                "test@test.com"
            ],
            "sender": "test@test.com",
            "senderGroup": "RELAY_O365",
            "sendingHostSummary": {},
            "showDLPDetails": true,
            "smtpAuthId": "",
            "subject": "Fw: DLP",
            "timestamp": "2022-09-21T08:42:32Z"
        }
    }
}
```

#### Human Readable Output

>### Message DLP Report Details
>Found DLP details for message ID 1131.
>|Mid|All Icid|Subject|Sender|Recipient|Timestamp|Message Size|Message Status|Direction|Sender Group|
>|---|---|---|---|---|---|---|---|---|---|
>| 1131 | 20460 | Fw: DLP | test@test.com | test@test.com | 2022-09-21T08:42:32Z | 29.67 (KB) | Delivered | outgoing | RELAY_O365 |
>### Message DLP Report Details Summary
>|Mid|Violation Severity|Risk Factor|Dlp Policy|
>|---|---|---|---|
>| 1131 | HIGH | 72 | US HIPAA and HITECH (Low Threshold) |


### cisco-esa-message-url-details-get
***
Get message URL summary details.


#### Base Command

`cisco-esa-message-url-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial_number | Email gateway serial number. | Required | 
| message_ids | Message ID list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoESA.URLDetail.sdrAge | String | Sender domain reputation age. | 
| CiscoESA.URLDetail.attachments | String | Message attachments. | 
| CiscoESA.URLDetail.showURLDetails | Boolean | Whether to show URL event details. | 
| CiscoESA.URLDetail.urlDetails.timestamp | String | URL event details timestamp. | 
| CiscoESA.URLDetail.urlDetails.description | String | URL event details description. | 
| CiscoESA.URLDetail.hostName | String | Email gateway hostname. | 
| CiscoESA.URLDetail.direction | String | Message direction, incoming or outgoing. | 
| CiscoESA.URLDetail.messageStatus | String | Message delivery status. | 
| CiscoESA.URLDetail.senderGroup | String | Matched sender group. | 
| CiscoESA.URLDetail.subject | String | Email message subject. | 
| CiscoESA.URLDetail.sdrCategory | String | Sender domain reputation category. | 
| CiscoESA.URLDetail.mid | Number | Message ID. | 
| CiscoESA.URLDetail.smtpAuthId | String | SMTP authorization ID. | 
| CiscoESA.URLDetail.midHeader | String | Message ID header. | 
| CiscoESA.URLDetail.timestamp | String | Email message time. | 
| CiscoESA.URLDetail.messageSize | String | Email message size. | 
| CiscoESA.URLDetail.sdrThreatLevels | String | Sender domain reputation threat levels. | 
| CiscoESA.URLDetail.sdrReputation | String | Sender domain reputation. | 
| CiscoESA.URLDetail.recipient | String | Message recipient email address. | 
| CiscoESA.URLDetail.sender | String | Message sender email address. | 
| CiscoESA.URLDetail.allIcid | Number | ICIDs list. | 
| CiscoESA.URLDetail.headerFrom | String | Email header from. | 

#### Command example
```!cisco-esa-message-url-details-get message_ids=737,738,739 serial_number=test-test```
#### Context Example
```json
{
    "CiscoESA": {
        "URLDetail": {
            "allIcid": [
                19598
            ],
            "ampTgCategories": [],
            "attachments": [
                "bear.jpg"
            ],
            "direction": "incoming",
            "headerFrom": "test@test.com",
            "hostName": "(Name unresolved,  SN:test-test)",
            "messageSize": "439.25 (KB)",
            "messageStatus": "Quarantined by Multiple Engines",
            "mid": [
                737,
                738,
                739
            ],
            "midHeader": "<test@test.test.com>",
            "recipient": [
                "test@test.com"
            ],
            "sdrAge": "30 days (or greater)",
            "sdrCategory": "N/A",
            "sdrReputation": "Neutral",
            "sdrThreatLevels": "3",
            "sender": "test@test.com",
            "senderGroup": "ACCEPTLIST",
            "sendingHostSummary": {},
            "showURLDetails": true,
            "smtpAuthId": "",
            "subject": "Fwd: test",
            "timestamp": "2022-09-20T13:31:08Z",
            "urlDetails": [
                {
                    "description": "Message 737 URL: http://1.1.1.1:8080/, URL reputation: -6.8, Condition: URL Reputation Rule.",
                    "timestamp": "2022-09-20T13:31:12Z"
                },
                {
                    "description": "Message 737 URL: https://test.com/test/, URL reputation: -6.6, Condition: URL Reputation Rule.",
                    "timestamp": "2022-09-20T13:31:12Z"
                },
                {
                    "description": "Message 737 URL: http://1.1.1.1:8080, URL reputation: -6.8, Condition: URL Reputation Rule.",
                    "timestamp": "2022-09-20T13:31:12Z"
                },
                {
                    "description": "Message 737 rewritten URL u'http://1.1.1.1:8080'.",
                    "timestamp": "2022-09-20T13:31:12Z"
                },
                {
                    "description": "Message 737 rewritten URL u'https://test.com/test/'.",
                    "timestamp": "2022-09-20T13:31:12Z"
                },
                {
                    "description": "Message 737 rewritten URL u'http://1.1.1.1:8080/'.",
                    "timestamp": "2022-09-20T13:31:12Z"
                },
                {
                    "description": "Message 737 rewritten URL u'https://test.com/test/'.",
                    "timestamp": "2022-09-20T13:31:12Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Message URL Report Details
>Found URL details for message ID 737, 738, 739.
>|Mid|All Icid|Subject|Sender|Recipient|Attachments|Timestamp|Message Size|Message Status|Direction|Sender Group|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 737,<br/>738,<br/>739 | 19598 | Fwd: test | test@test.com | test@test.com | bear.jpg | 2022-09-20T13:31:08Z | 439.25 (KB) | Quarantined by Multiple Engines | incoming | ACCEPTLIST |
>### Message URL Report Details Summary
>|Description|Timestamp|
>|---|---|
>| Message 737 URL: http:<span>//</span>1.1.1.1:8080/, URL reputation: -6.8, Condition: URL Reputation Rule. | 2022-09-20T13:31:12Z |
>| Message 737 URL: https:<span>//</span>test.com/test/, URL reputation: -6.6, Condition: URL Reputation Rule. | 2022-09-20T13:31:12Z |
>| Message 737 URL: http:<span>//</span>1.1.1.1:8080, URL reputation: -6.8, Condition: URL Reputation Rule. | 2022-09-20T13:31:12Z |
>| Message 737 rewritten URL u'http:<span>//</span>1.1.1.1:8080'. | 2022-09-20T13:31:12Z |
>| Message 737 rewritten URL u'https:<span>//</span>test.com/test/'. | 2022-09-20T13:31:12Z |
>| Message 737 rewritten URL u'http:<span>//</span>1.1.1.1:8080/'. | 2022-09-20T13:31:12Z |
>| Message 737 rewritten URL u'https:<span>//</span>test.com/test/'. | 2022-09-20T13:31:12Z |


### cisco-esa-report-get
***
Get statistics reports.
Note that each report type is compatible with different arguments.
Refer to Addendum for Cisco Secure Email Gateway ("Secure Email Reporting" sheet in the file), to view the dedicated arguments for each report type.
https://www.cisco.com/c/dam/en/us/td/docs/security/esa/esa14-0/api/AsyncOS-14-0-API-Addendum.xlsx


#### Base Command

`cisco-esa-report-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_type | Report Type. Possible values are: mail_incoming_traffic_summary, reporting_system, mail_vof_threat_summary, mail_vof_specific_threat_summary, mail_amp_threat_summary. Default is mail_incoming_traffic_summary. | Optional | 
| custom_report_type | Custom report type.<br/>Specify this argument to get a report that does not exist in the report_type argument. | Optional | 
| start_date | Start date in ISO format or &lt;number&gt; &lt;time unit&gt;,<br/>e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | Required | 
| end_date | End date in ISO format or &lt;number&gt; &lt;time unit&gt;,<br/>e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | Required | 
| order_by | The attribute by which to order the data in the response. For example, orderBy=total_clean_recipients. | Optional | 
| order_dir | The report sort order direction. Possible values are: asc, desc. | Optional | 
| top | The number of records with the highest values to return. | Optional | 
| filter_value | The filter value to search for. | Optional | 
| filter_by | The filter field to use. Filter the data to be retrieved according to the filter property and value. | Optional | 
| filter_operator | The filter operator. Filter the response data based on the value specified. Possible values are: begins_with, is. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoESA.Report.type | String | Report type. | 
| CiscoESA.Report.resultSet | Number | Report results summary. | 

#### Command example
```!cisco-esa-report-get start_date=2weeks end_date=now report_type=mail_incoming_traffic_summary```
#### Context Example
```json
{
    "CiscoESA": {
        "Report": {
            "resultSet": [
                {
                    "failed_dkim": 0
                },
                {
                    "total_graymail_recipients": 5
                },
                {
                    "detected_spam": 19
                },
                {
                    "malicious_url": 3
                },
                {
                    "total_spoofed_emails": 1
                },
                {
                    "verif_decrypt_success": 0
                },
                {
                    "detected_virus": 0
                },
                {
                    "threat_content_filter": 4
                },
                {
                    "blocked_invalid_recipient": 12
                },
                {
                    "blocked_sdr": 0
                },
                {
                    "marketing_mail": 4
                },
                {
                    "ims_spam_increment_over_case": 0
                },
                {
                    "total_mailbox_auto_remediated_recipients": 0
                },
                {
                    "detected_spam_certain": 15
                },
                {
                    "detected_spam_suspect": 4
                },
                {
                    "blocked_dmarc": 1
                },
                {
                    "total_threat_recipients": 1383
                },
                {
                    "total_recipients": 1567
                },
                {
                    "verif_decrypt_fail": 0
                },
                {
                    "detected_amp": 0
                },
                {
                    "bulk_mail": 1
                },
                {
                    "social_mail": 0
                },
                {
                    "total_clean_recipients": 179
                },
                {
                    "detected_virus_per_msg": 0
                },
                {
                    "failed_spf": 0
                },
                {
                    "blocked_reputation": 1345
                }
            ],
            "type": "mail_incoming_traffic_summary",
            "uuid": "6535f7b3-0d35-411b-ab76-42e27ea661ce"
        }
    }
}
```

#### Human Readable Output

>### Report type: mail_incoming_traffic_summary
>Report UUID: 6535f7b3-0d35-411b-ab76-42e27ea661ce
>|Blocked Dmarc|Blocked Invalid Recipient|Blocked Reputation|Blocked Sdr|Bulk Mail|Detected Amp|Detected Spam|Detected Spam Certain|Detected Spam Suspect|Detected Virus|Detected Virus Per Msg|Failed Dkim|Failed Spf|Ims Spam Increment Over Case|Malicious Url|Marketing Mail|Social Mail|Threat Content Filter|Total Clean Recipients|Total Graymail Recipients|Total Mailbox Auto Remediated Recipients|Total Recipients|Total Spoofed Emails|Total Threat Recipients|Verif Decrypt Fail|Verif Decrypt Success|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | 12 | 1345 | 0 | 1 | 0 | 19 | 15 | 4 | 0 | 0 | 0 | 0 | 0 | 3 | 4 | 0 | 4 | 179 | 5 | 0 | 1567 | 1 | 1383 | 0 | 0 |


### cisco-esa-dictionary-add

***
Add a new dictionary.

#### Base Command

`cisco-esa-dictionary-add`

#### Input

| **Argument Name** | **Description**| **Required** |
| --- |---| --- |
| mode | The cluster mode of the email gateway determines its configuration. If the cluster mode is set to 'group', specify a group_name. If the cluster mode is set to 'machine', specify a host_name. Possible values are: cluster, group, machine. Default is cluster.| Optional | 
| host_name | Required when cluster mode is 'machine'.| Optional | 
| group_name | Required when cluster mode is 'group'.| Optional | 
| dictionary_name | The name of the dictionary for which to get information. This argument is optional. | Optional | 
| whole_words | Indicates if the words need to be matched completely. Possible values are: True, False. Default value is True. | Required | 
| words | A list of terms to add to a dictionary. The term can have a weight of (0-10) associated with it. If no weight is given, the default weight is taken as "1".<br/>A smart identifier can have an additional parameter - "prefix" associated with it. If no value is mentioned, no prefix is taken as default.<br/>Example: ['*credit',2,'prefix'],['*aba'],['À term 1']. | Required | 
| ignore_case_sensitive | Indicates if the term that needs to be matched is case-sensitive. Possible values are: True, False. Default value is False.| Required | 

#### Context Output

There is no context output for this command.

#### Command example
```!cisco-esa-dictionary-add dictionary_name=testing1 ignore_case_sensitive=False whole_words=False mode=cluster words=['*credit',2,'prefix'],['test2']```

```!cisco-esa-dictionary-add dictionary_name=testing2 words=['*credit',2,'prefix'],['test2']```

#### Human Readable Output

**test_dictionary was added successfully.**

### cisco-esa-dictionary-edit

***
Edit a dictionary.

#### Base Command

`cisco-esa-dictionary-edit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- |------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| mode | The cluster mode of the email gateway determines its configuration. If the cluster mode is set to 'group', specify a group_name. If the cluster mode is set to 'machine', specify a host_name. Possible values are: cluster, group, machine. Default is cluster.                                                                                                       | Optional | 
| host_name | Required when cluster mode is 'machine'.                                                                                                                                                                                                                                                                                                                               | Optional | 
| group_name | Required when cluster mode is 'group'.                                                                                                                                                                                                                                                                                                                                 | Optional | 
| dictionary_name | The name of the dictionary for which to get information. This argument is optional.                                                                                                                                                                                                                                                                                    | Optional | 
| updated_name | Specifies a new name for the dictionary to modify.                                                                                                                                                                                                                                                                                                                     | Optional | 
| whole_words | Indicates if the words need to be matched completely. Possible values are: True, False. Default value is True.                                                                                                                                                                                                                                                         | Optional | 
| words | A list of terms to add to a dictionary. The term can have a weight of (0-10) associated with it. If no weight is given, the default weight is taken as "1".<br/>A smart identifier can have an additional parameter - "prefix" associated with it. If no value is mentioned, no prefix is taken as default.<br/>Example: ['*credit',2,'prefix'],['*aba'],['À term 1']. | Required | 
| ignore_case_sensitive | Indicates if the term that needs to be matched is case-sensitive. Possible values are: True, False. Default value is False. | Required | 

#### Context Output

There is no context output for this command.

#### Command example
```!cisco-esa-dictionary-edit dictionary_name=testing1 words=['*credit',6,'prefix'],['test2']```

#### Human Readable Output

**test_dictionary has been successfully updated.**

### cisco-esa-dictionary-list

***
Retrieve information of all dictionaries or a specific configured dictionary and their list of words.

#### Base Command

`cisco-esa-dictionary-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mode | The cluster mode of the email gateway determines its configuration. If the cluster mode is set to 'group', please a group_name. If the cluster mode is set to 'machine', specify a host_name. Possible values are: cluster, group, machine. Default is cluster. | Optional | 
| host_name | Required when cluster mode is 'machine'. | Optional | 
| group_name | Required when cluster mode is 'group'. | Optional | 
| dictionary_name | The name of the dictionary for which to get information. This argument is optional.  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoESA.Dictionary.name | String | The name of the dictionary. | 
| CiscoESA.Dictionary.encoding | String | The encoding format used for the dictionary. | 
| CiscoESA.Dictionary.ignorecase | Number | Indicates whether the dictionary ignores case sensitivity \(1 for true, 0 for false\). | 
| CiscoESA.Dictionary.words | List | The words in the dictionary. | 
| CiscoESA.Dictionary.words_count.term_count | Number | The count of individual terms in the dictionary. | 
| CiscoESA.Dictionary.words_count.smart_identifier_count | Number | The count of smart identifiers in the dictionary \(special terms with additional metadata\). | 
| CiscoESA.Dictionary.wholewords | Number | Indicates whether the dictionary considers whole words only \(1 for true, 0 for false\). | 

#### Command example
```!cisco-esa-dictionary-list mode=cluster dictionary_name=test```

#### Human Readable Output

>### Information for Dictionary: testing
>| Name | Words | Ignore Case | Whole Words | Words Count | Smart Identifier Count | Encoding |
>| --- | --- | --- | --- | --- | --- | --- |
>| testing | ['test6', 1], ['testing7', 1], ['noy', 1] | 1 | 1 | term_count: 4 | 0 | utf-8 |


### cisco-esa-dictionary-words-delete

***
Delete existing words from a specific dictionary.

#### Base Command

`cisco-esa-dictionary-words-delete`

#### Input

| **Argument Name** | **Description**| **Required** |
| --- |---| --- |
| mode | The cluster mode of the email gateway determines its configuration. If the cluster mode is set to 'group', specify a group_name. If the cluster mode is set to 'machine', specify a host_name. Possible values are: cluster, group, machine. Default is cluster. | Optional | 
| host_name | Required when cluster mode is 'machine'.| Optional | 
| group_name | Required when cluster mode is 'group'.| Optional | 
| dictionary_name | The name of the dictionary for which to get information. This argument is optional.| Optional | 
| words | A list of terms that need to be deleted.<br/>Example: *credit,aba,term.| Required | 

#### Context Output

There is no context output for this command.

#### Command example
```!cisco-esa-dictionary-words-delete dictionary_name=testing mode=cluster words=*credit```

```!cisco-esa-dictionary-words-delete dictionary_name=testing words=test1,test2```

#### Human Readable Output

**Words deleted successfully from test_dictionary.**

### cisco-esa-dictionary-words-add

***
Add words to a specific dictionary.

#### Base Command

`cisco-esa-dictionary-words-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mode | The cluster mode of the email gateway determines its configuration. If the cluster mode is set to 'group', specify a group_name. If the cluster mode is set to 'machine', specify a host_name. Possible values are: cluster, group, machine. Default is cluster. | Optional | 
| host_name | Required when cluster mode is 'machine'. | Optional | 
| group_name | Required when cluster mode is 'group'. | Optional | 
| dictionary_name | The name of the dictionary for which to get information. This argument is optional.  | Optional | 
| words | A list of terms to add to a dictionary. The term can have a weight of (0-10) associated with it. If no weight is given, the default weight is taken as "1".<br/>A smart identifier can have an additional parameter - "prefix" associated with it. If no value is mentioned, no prefix is taken as default.<br/>Example: ['*credit',2,'prefix'],['*aba'],['À term 1']. | Required | 

#### Context Output

There is no context output for this command.

#### Command example
```!cisco-esa-dictionary-words-add dictionary_name=testing words=['*ssn',2,'prefix'],['test3']```

```!cisco-esa-dictionary-words-add dictionary_name=testing1 mode=cluster words=['test1'],['testing2']```

#### Human Readable Output

**Added successfully to test_dictionary.**

### cisco-esa-dictionary-delete

***
Delete a dictionary.

#### Base Command

`cisco-esa-dictionary-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mode | The cluster mode of the email gateway determines its configuration. If the cluster mode is set to 'group', specify a group_name. If the cluster mode is set to 'machine', specify a host_name. Possible values are: cluster, group, machine. Default is cluster. | Optional | 
| host_name | Required when cluster mode is 'machine'. | Optional | 
| group_name | Required when cluster mode is 'group'. | Optional | 
| dictionary_name | The name of the dictionary for which to get information. This argument is optional.  | Optional | 

#### Context Output

There is no context output for this command.


#### Command example
```!cisco-esa-dictionary-delete dictionary_name=test mode=cluster```

#### Human Readable Output

**test_dictionary deleted successfully.**
