The Security Management Appliance (SMA) is used to centralize services from Email Security Appliances (ESAs) and Web Security Appliances (WSAs).
This integration was integrated and tested with version 12.0 of Cisco Security Management Appliance.

## Configure Cisco Security Management Appliance in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL, e.g., https://XXX.eu.iphmx.com | True |
| Username |  | True |
| Password |  | True |
| Maximum incidents per fetch | Default is 50. Maximum is 100. | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). | Timestamp in ISO format or &amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;,<br/>e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | False |
| Filter by | Message field by which to filter the results. | False |
| Filter operator | Operator on the message field. | False |
| Filter value | The value to search for. | False |
| Recipient filter operator | Recipient operator filter. | False |
| Recipient filter value | Recipient filter value to fetch by message field. | False |
| Timeout | HTTP requests timeout in seconds. The default is 60 seconds. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cisco-sma-spam-quarantine-message-search
***
Search messages in the spam quarantine.


#### Base Command

`cisco-sma-spam-quarantine-message-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start date in ISO format or &lt;number&gt; &lt;time unit&gt;,<br/>e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | Required | 
| end_date | End date in ISO format or &lt;number&gt; &lt;time unit&gt;,<br/>e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | Required | 
| filter_by | Field by which to filter the results. Possible values are: from_address, to_address, subject. | Optional | 
| filter_operator | Filter operator. Possible values are: contains, is, begins_with, ends_with, does_not_contain. | Optional | 
| filter_value | The value to search for. This is a user defined value, e.g., filterValue=abc.com. | Optional | 
| recipient_filter_operator | Recipient operator filter. Possible values are: contains, is, begins_with, ends_with, does_not_contain. | Optional | 
| recipient_filter_value | Recipient filter value. | Optional | 
| order_by | How the results should be ordered. Possible values are: from_address, date, subject, size. | Optional | 
| order_dir | Direction in which the results should be ordered. Possible values are: asc, desc. | Optional | 
| page | Page number of paginated results.<br/>Minimum value is 1. | Optional | 
| page_size | Number of results per page. Maximum value is 100. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSMA.SpamQuarantineMessage.envelopeRecipient | String | Message recipient. | 
| CiscoSMA.SpamQuarantineMessage.toAddress | String | Message recipient. | 
| CiscoSMA.SpamQuarantineMessage.subject | String | Message subject. | 
| CiscoSMA.SpamQuarantineMessage.date | String | Message date. | 
| CiscoSMA.SpamQuarantineMessage.fromAddress | String | Message sender. | 
| CiscoSMA.SpamQuarantineMessage.size | String | Message size. | 
| CiscoSMA.SpamQuarantineMessage.mid | Number | Message ID. | 

#### Command example
```!cisco-sma-spam-quarantine-message-search start_date=2weeks end_date=now page=3 page_size=2```
#### Context Example
```json
{
    "CiscoSMA": {
        "SpamQuarantineMessage": [
            {
                "date": "11 Sep 2022 07:55 (GMT)",
                "envelopeRecipient": [
                    "test@test.com"
                ],
                "fromAddress": [
                    "Test Test <t1@test.com>"
                ],
                "mid": 70,
                "size": "17.60K",
                "subject": "test 2",
                "toAddress": [
                    "test@test.com <test@test.com>"
                ]
            },
            {
                "date": "11 Sep 2022 07:55 (GMT)",
                "envelopeRecipient": [
                    "test@test.com"
                ],
                "fromAddress": [
                    "Test Test <t1@test.com>"
                ],
                "mid": 69,
                "size": "17.70K",
                "subject": "hello",
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
>| 70 | 11 Sep 2022 07:55 (GMT) | Test Test <t1@test.com> | "test@test.com" <test@test.com> | test 2 | 17.60K |
>| 69 | 11 Sep 2022 07:55 (GMT) | Test Test <t1@test.com> | "test@test.com" <test@test.com> | hello | 17.70K |


### cisco-sma-spam-quarantine-message-get
***
Get spam quarantine message.


#### Base Command

`cisco-sma-spam-quarantine-message-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | Message ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSMA.SpamQuarantineMessage.envelopeRecipient | String | Message recipient. | 
| CiscoSMA.SpamQuarantineMessage.toAddress | String | Message recipient. | 
| CiscoSMA.SpamQuarantineMessage.messageBody | String | Message body. | 
| CiscoSMA.SpamQuarantineMessage.date | String | Message date. | 
| CiscoSMA.SpamQuarantineMessage.fromAddress | String | Message sender. | 
| CiscoSMA.SpamQuarantineMessage.subject | String | Message subject. | 
| CiscoSMA.SpamQuarantineMessage.mid | Number | Message ID. | 

#### Command example
```!cisco-sma-spam-quarantine-message-get message_id=64```
#### Context Example
```json
{
    "CiscoSMA": {
        "SpamQuarantineMessage": {
            "attachments": [],
            "date": "11 Sep 2022 06:07 (GMT)",
            "envelopeRecipient": [
                "test@test.com"
            ],
            "fromAddress": [
                "Test Test <t1@test.com>"
            ],
            "messageBody": "Received: from esa2.test.eu.iphmx.com ([2.2.2.2])  by sma1.test.eu.iphmx.com with ESMTP; 11 Sep 2022 06:07:11 +0000Received-SPF: Pass (esa2.test.eu.iphmx.com: domain of  t1@test.com designates 22.22.22.22 as permitted  sender) identity=mailfrom; client-ip=22.22.22.22;  receiver=esa2.test.eu.iphmx.com;  envelope-from=t1@test.com;  x-sender=t1@test.com; x-conformance=spf_only;  x-record-type=v=spf1; x-record-text=v=spf1  ip4:8.8.8.8/15 ip4:1.1.1.1/16 ip4:1.1.1.1/14  ip4:1.1.1.1/17 ip1.1.1.1/48  ip1.1.1.1/49 ip1.1.1.1/50  ip1.1.1.1/51 ip1.1.1.1/52  include:spfd.protection.outlook.com -allAuthentication-Results: esa2.test.eu.iphmx.com; spf=Pass smtp.mailfrom=t1@test.com; dkim=pass (signature verified) header.i=@Qmasters.onmicrosoft.comX-Ironport-Dmarc-Check-Result: validskipIronPort-SDR: 631d7b0e_gYHRKFozU63bNGUcBmI6bZxMVbnKq771Bg3g/PXeqXGnCcb en8XOitOlv+hcIvMhGPgHjLS3GSW298LZ8xVyrA==X-IronPort-RemoteIP: 22.22.22.22X-IronPort-MID: 427X-IronPort-Reputation: 3.5X-IronPort-Listener: MailFlowX-IronPort-SenderGroup: ACCEPTLISTX-IronPort-MailFlowPolicy: $ACCEPTEDX-SLBL-Result: BLOCK-LISTEDX-IronPort-AV: E=McAfee;i=6500,9779,10466; a=427X-IronPort-AV: E=Sophos;i=5.93,307,1654549200;    d=scan'208,217;a=427X-Amp-Result: SKIPPED(no attachment in message)X-Amp-File-Uploaded: FalseX-IPAS-Result: =?us-ascii?q?vGpBb5TsaWco2WF0CJmG5A=3D=3D?=Received: from mail-eopbgr150082.outbound.protection.outlook.com (HELO EUR01-DB5-obe.outbound.protection.outlook.com) ([22.22.22.22])  by esa2.test.eu.iphmx.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Sep 2022 09:07:10 +0300ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none; b=/saT6U5NS0IZCdFJ8PRhIOdlfgGhCHg==ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com; s=arcselector9901; h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1 mx.microsoft.com 1; spf=pass smtp.mailfrom=qmasters.co; dmarc=pass action=none header.from=qmasters.co; dkim=pass header.d=qmasters.co; arc=noneDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=Qmasters.onmicrosoft.com; s=selector2-Qmasters-onmicrosoft-com; h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck; bh=8EDhl0WksFhflNDqiZFXIJI/gERNfydqE0p9gIt/k1E=; b=/0nVjDfeQJk=Received: from AS4P192MB1694.EURP192.PROD.OUTLOOK.COM (1.1.1.11) by GV1P192MB1739.EURP192.PROD.OUTLOOK.COM (1.1.1.115) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5612.20; Sun, 11 Sep 2022 06:07:08 +0000Received: from AS4P192MB1694.EURP192.PROD.OUTLOOK.COM ([1.1.1.1ddbc:6c6a:6e24:2ddc]) by AS4P192MB1694.EURP192.PROD.OUTLOOK.COM ([1.1.1.1ddbc:6c6a:6e24:2ddc%5]) with mapi id 15.20.5612.022; Sun, 11 Sep 2022 06:07:08 +0000From: Test Test &lt;t1@test.com&gt;To: test@test.com &lt;test@test.com&gt;Subject: test1Thread-Topic: test1Thread-Index: AdjFpLjMMletPLuSTiamq2aPR00gtw==Date: Sun, 11 Sep 2022 06:07:07 +0000Message-ID:-Language: en-US, he-ILContent-Language: en-USX-MS-Has-Attach: X-MS-TNEF-Correlator: x-ms-publictraffictype: Emailx-ms-traffictypediagnostic: AS4P192MB1694:EE_|GV1P192MB1739:EE_x-ms-office365-filtering-correlation-id: 1f4793f4-e7cb-44f4-45d0-08da93bbdbabx-ms-exchange-senderadcheck: 1x-ms-exchange-antispam-relay: 0x-microsoft-antispam: BCL:0;x-microsoft-antispam-message-info:  4DkFMorvBGYa2L7kv5m1ibET5n0EvYTCLJhZmOPqKgjLW+eH0zwrxtxJBRcchZ1ZkamOBS+alGY0FGLHiHyUMavSvkdOvmk526KzQDiXoY5xcIHN6un/c6CzO9pcvrGN2D3aPGL5NGw16o+lG/TlArEoyjMC5PM/forefront-antispam-report:  CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:AS4P192MB1694.EURP192.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230016)(4636009)(346002)(376002)(136003)(366004)(39830400003)(396003)(2906002)(8936002);DIR:OUT;Q?C1JbgP7At7ztN6x7KY7DAv3gpBtr1wcCZy2aTMfk?=Content-Type: multipart/alternative;\tboundary=_000_AS4P192MB1694E446958C283FF6146212AB459AS4P192MB1694EURP_MIME-Version: 1.0X-OriginatorOrg: qmasters.coX-MS-Exchange-CrossTenant-AuthAs: InternalX-MS-Exchange-CrossTenant-AuthSource: AS4P192MB1694.EURP192.PROD.OUTLOOK.COMX-MS-Exchange-CrossTenant-Network-Message-Id: 1f4793f4-e7cb-44f4-45d0-08da93bbdbabX-MS-Exchange-CrossTenant-originalarrivaltime: 11 Sep 2022 06:07:07.9480 (UTC)X-MS-Exchange-CrossTenant-fromentityheader: HostedX-MS-Exchange-CrossTenant-id: ed363dfd-16fd-4038-8e58-9237411a84e5X-MS-Exchange-CrossTenant-mailboxtype: HOSTEDX-MS-Exchange-CrossTenant-userprincipalname: oeEevxfXcCiCthJ0sdKmama9rN1O92XcZ3RYCBNpAtJGc1YO+C9f+UGf6qp4y0t2aVaTNORJqi/cQeynDtX1hQ==X-MS-Exchange-Transport-CrossTenantHeadersStamped: GV1P192MB1739",
            "mid": 64,
            "subject": "test1",
            "toAddress": [
                "test@test.com <test@test.com>"
            ]
        }
    }
}
```

#### Human Readable Output

>### Spam Quarantine Message
>Found spam quarantine message with ID: 64
>|Mid|From Address|To Address|Date|Subject|
>|---|---|---|---|---|
>| 64 | Test Test <t1@test.com> | "test@test.com" <test@test.com> | 11 Sep 2022 06:07 (GMT) | test1 |


### cisco-sma-spam-quarantine-message-release
***
Release spam quarantined message.


#### Base Command

`cisco-sma-spam-quarantine-message-release`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_ids | Comma-separated list of message IDs. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-sma-spam-quarantine-message-release message_ids=65```
#### Human Readable Output

>Quarantined message 65 successfully released.

### cisco-sma-spam-quarantine-message-delete
***
Delete spam quarantined message.


#### Base Command

`cisco-sma-spam-quarantine-message-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_ids | Comma-separated list of message IDs. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-sma-spam-quarantine-message-delete message_ids=66```
#### Human Readable Output

>Quarantined message 66 successfully deleted.

### cisco-sma-list-entry-get
***
Get spam quarantine blocklist/safelist entry.


#### Base Command

`cisco-sma-list-entry-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_type | List entry type. Possible values are: blocklist, safelist. | Required | 
| page | Page number of paginated results.<br/>Minimum value is 1. | Optional | 
| page_size | Number of results per page. Maximum value is 100. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| order_by | How the results should be ordered. Possible values are: recipient, sender. | Optional | 
| order_dir | Direction in which the results should be ordered. Possible values are: asc, desc. | Optional | 
| view_by | View results by. Possible values are: recipient, sender. Default is recipient. | Optional | 
| search | Search for recipients or senders in blocklist/safelist with 'contains' operator.<br/>e.g., test@test.com, test.com<br/>This is only supported for the argument view_by=recipient. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSMA.ListEntry.Blocklist.senderList | String | Sender list. | 
| CiscoSMA.ListEntry.Blocklist.recipientAddress | String | Recipient address. | 
| CiscoSMA.ListEntry.Blocklist.recipientList | String | Recipient list. | 
| CiscoSMA.ListEntry.Blocklist.senderAddress | String | Sender address. | 
| CiscoSMA.ListEntry.Safelist.senderList | String | Sender list. | 
| CiscoSMA.ListEntry.Safelist.recipientAddress | String | Recipient address. | 
| CiscoSMA.ListEntry.Safelist.recipientList | String | Recipient list. | 
| CiscoSMA.ListEntry.Safelist.senderAddress | String | Sender address. | 

#### Command example
```!cisco-sma-list-entry-get entry_type=safelist page=2 page_size=3 view_by=recipient order_by=recipient order_dir=desc```
#### Context Example
```json
{
    "CiscoSMA": {
        "ListEntry": {
            "Safelist": [
                {
                    "recipientAddress": "test4@test.com",
                    "senderList": [
                        "t3@test.com"
                    ]
                },
                {
                    "recipientAddress": "test3@test.com",
                    "senderList": [
                        "t3@test.com"
                    ]
                },
                {
                    "recipientAddress": "test2@test.com",
                    "senderList": [
                        "testi@test.com"
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
>| test4@test.com | t3@test.com |
>| test3@test.com | t3@test.com |
>| test2@test.com | testi@test.com |


### cisco-sma-list-entry-add
***
Add spam quarantine blocklist/safelist entry.


#### Base Command

`cisco-sma-list-entry-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_type | List entry type. Possible values are: blocklist, safelist. | Required | 
| view_by | Add list entry by recipient/sender.<br/>When view_by = recipient: recipient_addresses and sender_list are mandatory.<br/>When view_by = sender: sender_addresses and recipient_list are mandatory. Possible values are: recipient, sender. Default is recipient. | Optional | 
| recipient_addresses | A comma-separated list of recipients to add. | Optional | 
| sender_list | A comma-separated list of senders to add. | Optional | 
| sender_addresses | A comma-separated list of senders to add. | Optional | 
| recipient_list | A comma-separated list of recipients to add. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-sma-list-entry-add entry_type=blocklist view_by=recipient recipient_addresses=test@test.com sender_list=t1@test.com,t2@test.com```
#### Human Readable Output

>Successfully added t1@test.com, t2@test.com senders to test@test.com recipients in blocklist.

### cisco-sma-list-entry-append
***
Append spam quarantine blocklist/safelist entry.


#### Base Command

`cisco-sma-list-entry-append`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_type | List entry type. Possible values are: blocklist, safelist. | Required | 
| view_by | Append list entry by recipient/sender.<br/>When view_by = recipient: recipient_addresses and sender_list are mandatory.<br/>When view_by = sender: sender_addresses and recipient_list are mandatory. Possible values are: recipient, sender. Default is recipient. | Optional | 
| recipient_list | A comma-separated list of recipients to append. | Optional | 
| sender_list | A comma-separated list of senders to append. | Optional | 
| recipient_addresses | A comma-separated list of recipients to append. | Optional | 
| sender_addresses | A comma-separated list of senders to append. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-sma-list-entry-append entry_type=blocklist recipient_addresses=test@test.com sender_list=t4@test.com```
#### Human Readable Output

>Successfully appended t4@test.com senders to test@test.com recipients in blocklist.

### cisco-sma-list-entry-edit
***
Edit the spam quarantine blocklist/safelist entry. Using this command will override the existing value.


#### Base Command

`cisco-sma-list-entry-edit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_type | List entry type. Possible values are: blocklist, safelist. | Required | 
| view_by | Edit list entry by recipient/sender.<br/>When view_by = recipient: recipient_addresses and sender_list are mandatory.<br/>When view_by = sender: sender_addresses and recipient_list are mandatory. Possible values are: recipient, sender. Default is recipient. | Optional | 
| recipient_list | A comma-separated list of recipients to edit. | Optional | 
| sender_list | A comma-separated list of senders to edit. | Optional | 
| recipient_addresses | A comma-separated list of recipients to edit. | Optional | 
| sender_addresses | A comma-separated list of senders to edit. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-sma-list-entry-edit entry_type=blocklist view_by=recipient recipient_addresses=test@test.com sender_list=t5@test.com,t6@test.com```
#### Human Readable Output

>Successfully edited test@test.com recipients' senders to t5@test.com, t6@test.com in blocklist.

### cisco-sma-list-entry-delete
***
Delete a spam quarantine blocklist/safelist entry.


#### Base Command

`cisco-sma-list-entry-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_type | List entry type. Possible values are: blocklist, safelist. | Required | 
| view_by | Delete list entry by recipient/sender.<br/>When view_by = recipient: recipient_list is mandatory.<br/>When view_by = sender: sender_list is mandatory. Possible values are: recipient, sender. Default is recipient. | Optional | 
| recipient_list | A comma-separated list of recipients to delete. | Optional | 
| sender_list | A comma-separated list of senders to delete. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-sma-list-entry-delete entry_type=blocklist view_by=recipient recipient_list=test@test.com```
#### Human Readable Output

>Successfully deleted test@test.com recipients from blocklist.

### cisco-sma-message-search
***
Search tracking messages.


#### Base Command

`cisco-sma-message-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start date in ISO format or &lt;number&gt; &lt;time unit&gt;,<br/>e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | Required | 
| end_date | End date in ISO format or &lt;number&gt; &lt;time unit&gt;,<br/>e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | Required | 
| page | Page number of paginated results.<br/>Minimum value is 1. | Optional | 
| page_size | Number of results per page. Maximum value is 100. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| sender_filter_operator | Sender filter operator. Possible values are: contains, is, begins_with. | Optional | 
| sender_filter_value | Sender filter value. | Optional | 
| recipient_filter_operator | Recipient filter operator. Possible values are: contains, is, begins_with. | Optional | 
| recipient_filter_value | Recipient filter value. | Optional | 
| subject_filter_operator | Subject filter operator. Possible values are: contains, is, begins_with. | Optional | 
| subject_filter_value | Subject filter value. | Optional | 
| attachment_name_operator | Attachment name operator. Possible values are: contains, is, begins_with. | Optional | 
| attachment_name_value | Attachment name value. | Optional | 
| cisco_host | Cisco host. Default is All_Hosts. | Optional | 
| file_sha_256 | SHA256 must be 64 characters long and can contain only "0-9" and "a-f" symbols.<br/>E.g., e0d123e5f316bef78bfdf5a008837577e0d123e5f316bef78bfdf5a008837577. | Optional | 
| custom_query | Custom query for cisco SMA's advanced filters.<br/>Syntax: &lt;key&gt;=&lt;value&gt;;&lt;key&gt;=&lt;value&gt;;&lt;key&gt;=&lt;value&gt;<br/>E.g.,  graymail=True;message_delivered=True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSMA.Message.hostName | String | Email gateway hostname. | 
| CiscoSMA.Message.friendly_from | String | Friendly formatted sender email address. | 
| CiscoSMA.Message.isCompleteData | String | Is complete data pulled? | 
| CiscoSMA.Message.messageStatus | String | Message delivery status. | 
| CiscoSMA.Message.recipientMap | String | Recipients list. | 
| CiscoSMA.Message.senderIp | String | Sender IP address. | 
| CiscoSMA.Message.mailPolicy | String | Matched mail policy. | 
| CiscoSMA.Message.senderGroup | String | Matched sender group. | 
| CiscoSMA.Message.subject | String | Subject of email message. | 
| CiscoSMA.Message.dcid | Number | Delivery Connection ID. | 
| CiscoSMA.Message.mid | String | Message ID. | 
| CiscoSMA.Message.senderDomain | String | Domain of email message sender. | 
| CiscoSMA.Message.finalSubject | String | Extended email subject. | 
| CiscoSMA.Message.direction | String | Message direction, incoming or outgoing. | 
| CiscoSMA.Message.icid | Number | An Injection Connection ID \(ICID\) is a numerical identifier for an individual SMTP connection to the system. | 
| CiscoSMA.Message.replyTo | String | Email message reply to. | 
| CiscoSMA.Message.timestamp | String | Time of email message. | 
| CiscoSMA.Message.messageID | String | Extended message ID. | 
| CiscoSMA.Message.verdictChart | String | Verdict visual chart ID. | 
| CiscoSMA.Message.recipient | String | Recipients email addresses list. | 
| CiscoSMA.Message.sender | String | Sender email address. | 
| CiscoSMA.Message.serialNumber | String | Cisco ESA email gateway serial number. | 
| CiscoSMA.Message.allIcid | Number | ICIDs list. | 
| CiscoSMA.Message.sbrs | String | Sender Base Reputation Scores. | 

#### Command example
```!cisco-sma-message-search start_date=1month end_date=now page=3 page_size=2 subject_filter_operator=contains subject_filter_value=test```
#### Context Example
```json
{
    "CiscoSMA": {
        "Message": [
            {
                "allIcid": [
                    13538
                ],
                "unique_message_id": "433",
                "dcid": [],
                "direction": "incoming",
                "finalSubject": {
                    "433": "test 2"
                },
                "friendly_from": [
                    "t1@test.com"
                ],
                "hostName": "esa2.test.eu.iphmx.com",
                "icid": 13538,
                "isCompleteData": "N/A",
                "mailPolicy": [
                    "DEFAULT"
                ],
                "messageID": {
                    "433": "<AS4P192MB1694F8603766320A4C87D29AAB459@AS4P192MB1694.EURP192.PROD.OUTLOOK.COM>"
                },
                "messageStatus": {
                    "433": "Quarantined by Anti-Spam/Graymail"
                },
                "mid": [
                    433
                ],
                "morDetails": {},
                "recipient": [
                    "test@test.com"
                ],
                "recipientMap": {
                    "433": [
                        "test@test.com"
                    ]
                },
                "replyTo": "N/A",
                "sbrs": "3.5",
                "sender": "t1@test.com",
                "senderDomain": "qmasters.co",
                "senderGroup": "ACCEPTLIST",
                "senderIp": "1.1.1.1",
                "serialNumber": "423ADC9EBD9C5F1A7A64-B81D2582608C",
                "subject": "test 2",
                "timestamp": "2022-09-11T07:55:25Z",
                "verdictChart": {
                    "433": "16140210"
                }
            },
            {
                "allIcid": [
                    13536
                ],
                "unique_message_id": "431",
                "dcid": [],
                "direction": "incoming",
                "finalSubject": {
                    "431": "test1"
                },
                "friendly_from": [
                    "t1@test.com"
                ],
                "hostName": "esa2.test.eu.iphmx.com",
                "icid": 13536,
                "isCompleteData": "N/A",
                "mailPolicy": [
                    "DEFAULT"
                ],
                "messageID": {
                    "431": "<AS4P192MB1694630ADD929556BCEC2F09AB459@AS4P192MB1694.EURP192.PROD.OUTLOOK.COM>"
                },
                "messageStatus": {
                    "431": "Quarantined by Anti-Spam/Graymail"
                },
                "mid": [
                    431
                ],
                "morDetails": {},
                "recipient": [
                    "test@test.com"
                ],
                "recipientMap": {
                    "431": [
                        "test@test.com"
                    ]
                },
                "replyTo": "N/A",
                "sbrs": "3.5",
                "sender": "t1@test.com",
                "senderDomain": "qmasters.co",
                "senderGroup": "ACCEPTLIST",
                "senderIp": "1.1.1.1",
                "serialNumber": "423ADC9EBD9C5F1A7A64-B81D2582608C",
                "subject": "test1",
                "timestamp": "2022-09-11T07:55:15Z",
                "verdictChart": {
                    "431": "16140210"
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
>| 433 | 13538 | 423ADC9EBD9C5F1A7A64-B81D2582608C | t1@test.com | test@test.com | test 2 | 433: Quarantined by Anti-Spam/Graymail | 2022-09-11T07:55:25Z | 1.1.1.1 | 3.5 |
>| 431 | 13536 | 423ADC9EBD9C5F1A7A64-B81D2582608C | t1@test.com | test@test.com | test1 | 431: Quarantined by Anti-Spam/Graymail | 2022-09-11T07:55:15Z | 1.1.1.1 | 3.5 |


### cisco-sma-message-details-get
***
Get more details on the message.


#### Base Command

`cisco-sma-message-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial_number | Email gateway serial number. | Required | 
| message_ids | Message ID list. | Required | 
| injection_connection_id | Injection connection ID. | Optional | 
| delivery_connection_id | Delivery connection ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSMA.Message.sdrAge | String | Sender Domain Reputation age. | 
| CiscoSMA.Message.attachments | String | Message attachments. | 
| CiscoSMA.Message.hostName | String | Email gateway hostname. | 
| CiscoSMA.Message.direction | String | Message direction, incoming or outgoing. | 
| CiscoSMA.Message.isCompleteData | Boolean | Is complete data pulled? | 
| CiscoSMA.Message.messageStatus | String | Message delivery status. | 
| CiscoSMA.Message.mailPolicy | String | Matched mail policy. | 
| CiscoSMA.Message.senderGroup | String | Matched sender group. | 
| CiscoSMA.Message.subject | String | Email message subject. | 
| CiscoSMA.Message.showSummaryTimeBox | Boolean | Whether to show the summary time box. | 
| CiscoSMA.Message.sdrCategory | String | Sender Domain Reputation category. | 
| CiscoSMA.Message.mid | String | Message ID. | 
| CiscoSMA.Message.sendingHostSummary.reverseDnsHostname | String | Sending host reverse DNS hostname. | 
| CiscoSMA.Message.sendingHostSummary.ipAddress | String | Sending host IP address. | 
| CiscoSMA.Message.sendingHostSummary.sbrsScore | String | Sending host Sender Base Reputation scores. | 
| CiscoSMA.Message.smtpAuthId | String | SMTP auth ID. | 
| CiscoSMA.Message.midHeader | String | Message ID header. | 
| CiscoSMA.Message.timestamp | String | Email message time. | 
| CiscoSMA.Message.showDLP | Boolean | Whether the DLP report is available. | 
| CiscoSMA.Message.messageSize | String | Email message size. | 
| CiscoSMA.Message.sdrThreatLevels | String | Sender Domain Reputation threat levels. | 
| CiscoSMA.Message.sdrReputation | String | Sender Domain Reputation. | 
| CiscoSMA.Message.showURL | Boolean | Whether the URL report is available. | 
| CiscoSMA.Message.recipient | String | Message recipient email address. | 
| CiscoSMA.Message.sender | String | Message sender email address. | 
| CiscoSMA.Message.showAMP | Boolean | Whether the AMP report is available. | 
| CiscoSMA.Message.summary.timestamp | String | Event summary time. | 
| CiscoSMA.Message.summary.description | String | Event summary description. | 
| CiscoSMA.Message.summary.lastEvent | Boolean | Whether the event summary is the last event. | 
| CiscoSMA.Message.allIcid | Number | ICIDs list. | 
| CiscoSMA.Message.headerFrom | String | Email header from. | 

#### Command example
```!cisco-sma-message-details-get serial_number=423ADC9EBD9C5F1A7A64-B81D2582608C message_ids=322 injection_connection_id=10821 delivery_connection_id=4368```
#### Context Example
```json
{
    "CiscoSMA": {
        "Message": {
            "allIcid": [
                10821
            ],
            "ampTgCategories": [],
            "attachments": "",
            "unique_message_id": "322",
            "direction": "incoming",
            "headerFrom": "defender-noreply@microsoft.com",
            "hostName": "esa2.test.eu.iphmx.com (2.2.2.2)",
            "isCompleteData": true,
            "mailPolicy": [
                "DEFAULT"
            ],
            "messageSize": "70.3 (KB)",
            "messageStatus": "Delivered",
            "mid": [
                322
            ],
            "midHeader": "<add53137-42a8-4753-af53-bad0752af24d@az.westeurope.production.microsoft.com>",
            "recipient": [
                "t2@test.com"
            ],
            "sdrAge": "30 days (or greater)",
            "sdrCategory": "N/A",
            "sdrReputation": "Neutral",
            "sdrThreatLevels": "3",
            "sender": "azure-noreply@microsoft.com",
            "senderGroup": "ACCEPTLIST",
            "sendingHostSummary": {
                "ipAddress": "7.7.7.7",
                "reverseDnsHostname": "test.cloudapp.net (verified)",
                "sbrsScore": "3.5"
            },
            "showAMP": false,
            "showDLP": false,
            "showSummaryTimeBox": true,
            "showURL": false,
            "smtpAuthId": "",
            "subject": "Microsoft 365 Defender has detected a security threat",
            "summary": [
                {
                    "description": "Incoming connection (ICID 10821) has sender_group: ACCEPTLIST, sender_ip: 7.7.7.7 and sbrs: 3.5",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Protocol SMTP interface Data 1  (IP 2.2.2.2) on incoming connection (ICID 10821) from sender IP 7.7.7.7. Reverse DNS  host test.cloudapp.net verified yes.",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "(ICID 10821) ACCEPT sender group ACCEPTLIST match sbrs[0.0:10.0] SBRS 3.5 country Netherlands",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Incoming connection (ICID 10821) successfully accepted TLS protocol TLSv1.2 cipher ECDHE-RSA-AES256-GCM-SHA384.",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 Sender Domain: microsoft.com",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Start message 322 on incoming connection (ICID 10821).",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 enqueued on incoming connection (ICID 10821) from azure-noreply@microsoft.com.",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 direction: incoming",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 Domains for which SDR is requested: reverse DNS host: test.cloudapp.net, helo: test.cloudapp.net, env-from: microsoft.com, header_from: Not Present, reply_to: Not Present",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 Consolidated Sender Threat Level: Neutral, Threat Category: N/A, Suspected Domain(s) : N/A (other reasons for verdict). Sender Maturity: 30 days (or greater) for domain: test.cloudapp.net",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 on incoming connection (ICID 10821) added recipient (t2@test.com).",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 SPF: mailfrom identity azure-noreply@microsoft.com Pass",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 DKIM: pass signature verified (d=microsoft.com s=s1024-meo i=defender-noreply@microsoft.com)",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322: DMARC Message from domain microsoft.com, DMARC pass (SPF aligned True, DKIM aligned True),",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322: DMARC verification passed.",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 contains message ID header '<add53137-42a8-4753-af53-bad0752af24d@az.westeurope.production.microsoft.com>'.",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 original subject on injection: Microsoft 365 Defender has detected a security threat",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 Domains for which SDR is requested: reverse DNS host: test.cloudapp.net, helo: test.cloudapp.net, env-from: microsoft.com, header_from: microsoft.com, reply_to: Not Present",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 Consolidated Sender Threat Level: Neutral, Threat Category: N/A, Suspected Domain(s) : N/A (other reasons for verdict). Sender Maturity: 30 days (or greater) for domain: test.cloudapp.net",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 (71983 bytes) from azure-noreply@microsoft.com ready.",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 has sender_group: ACCEPTLIST, sender_ip: 7.7.7.7 and sbrs: 3.5",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:18Z"
                },
                {
                    "description": "Message 322 matched per-recipient policy DEFAULT for inbound mail policies.",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "Incoming connection (ICID 10821) lost.",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "Message 322 scanned by Anti-Spam engine: CASE. Interim verdict: Negative",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "Message 322 scanned by Anti-Spam engine CASE. Interim verdict: definitely negative.",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "Message 322 scanned by Anti-Spam engine: CASE. Final verdict: Negative",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "Message 322 scanned by Anti-Virus engine McAfee. Interim verdict: CLEAN",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "Message 322 scanned by Anti-Virus engine Sophos. Interim verdict: CLEAN",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "Message 322 scanned by Anti-Virus engine. Final verdict: Negative ",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "Message 322 scanned by Advanced Malware Protection engine. Final verdict: SKIPPED(no attachment in message)",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "Message 322 scanned by Outbreak Filters. Verdict: Negative",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "Message 322 queued for delivery.",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "SMTP delivery connection (DCID 4368) opened from Cisco IronPort interface 2.2.2.2 to IP address 1.1.1.1 on port 25.",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "Delivery connection (DCID 4368) successfully accepted TLS protocol TLSv1.2 cipher ECDHE-RSA-AES256-GCM-SHA384 None.",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "(DCID 4368) Delivery started for message 322 to t2@test.com.",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:19Z"
                },
                {
                    "description": "(DCID 4368) Delivery details: Message 322 sent to t2@test.com [('from', 'Microsoft 365 Defender <defender-noreply@microsoft.com>'), ('to', 't2@test.com')]",
                    "lastEvent": false,
                    "timestamp": "2022-09-07T10:11:20Z"
                },
                {
                    "description": "Message 322 to t2@test.com received remote SMTP response '2.6.0 <add53137-42a8-4753-af53-bad0752af24d@az.westeurope.production.microsoft.com> [InternalId=1511828495895, Hostname=test.test.PROD.OUTLOOK.COM] 92322 bytes in 0.189, 475.293 KB/sec Queued mail for delivery'.",
                    "lastEvent": true,
                    "timestamp": "2022-09-07T10:11:21Z"
                }
            ],
            "timestamp": "2022-09-07T10:11:18Z"
        }
    }
}
```

#### Human Readable Output

>### Message Details
>Found message with ID 322.
>|Mid|All Icid|Subject|Sender|Recipient|Timestamp|Message Size|Sending Host Summary|Message Status|Direction|Mail Policy|Sender Group|Show AMP|Show DLP|Show URL|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 322 | 10821 | Microsoft 365 Defender has detected a security threat | azure-noreply@microsoft.com | t2@test.com | 2022-09-07T10:11:18Z | 70.3 (KB) | reverseDnsHostname: test.cloudapp.net (verified) ipAddress: 7.7.7.7 sbrsScore: 3.5 | Delivered | incoming | DEFAULT | ACCEPTLIST | false | false | false |
>### Message Summary
>|Description|Timestamp|Last Event|
>|---|---|---|
>| Incoming connection (ICID 10821) has sender_group: ACCEPTLIST, sender_ip: 7.7.7.7 and sbrs: 3.5 | 2022-09-07T10:11:18Z | false |
>| Protocol SMTP interface Data 1  (IP 2.2.2.2) on incoming connection (ICID 10821) from sender IP 7.7.7.7. Reverse DNS  host test.cloudapp.net verified yes. | 2022-09-07T10:11:18Z | false |
>| (ICID 10821) ACCEPT sender group ACCEPTLIST match sbrs[0.0:10.0] SBRS 3.5 country Netherlands | 2022-09-07T10:11:18Z | false |
>| Incoming connection (ICID 10821) successfully accepted TLS protocol TLSv1.2 cipher ECDHE-RSA-AES256-GCM-SHA384. | 2022-09-07T10:11:18Z | false |
>| Message 322 Sender Domain: microsoft.com | 2022-09-07T10:11:18Z | false |
>| Start message 322 on incoming connection (ICID 10821). | 2022-09-07T10:11:18Z | false |
>| Message 322 enqueued on incoming connection (ICID 10821) from azure-noreply@microsoft.com. | 2022-09-07T10:11:18Z | false |
>| Message 322 direction: incoming | 2022-09-07T10:11:18Z | false |
>| Message 322 Domains for which SDR is requested: reverse DNS host: test.cloudapp.net, helo: test.cloudapp.net, env-from: microsoft.com, header_from: Not Present, reply_to: Not Present | 2022-09-07T10:11:18Z | false |
>| Message 322 Consolidated Sender Threat Level: Neutral, Threat Category: N/A, Suspected Domain(s) : N/A (other reasons for verdict). Sender Maturity: 30 days (or greater) for domain: test.cloudapp.net | 2022-09-07T10:11:18Z | false |
>| Message 322 on incoming connection (ICID 10821) added recipient (t2@test.com). | 2022-09-07T10:11:18Z | false |
>| Message 322 SPF: mailfrom identity azure-noreply@microsoft.com Pass | 2022-09-07T10:11:18Z | false |
>| Message 322 DKIM: pass signature verified (d=microsoft.com s=s1024-meo i=defender-noreply@microsoft.com) | 2022-09-07T10:11:18Z | false |
>| Message 322: DMARC Message from domain microsoft.com, DMARC pass (SPF aligned True, DKIM aligned True), | 2022-09-07T10:11:18Z | false |
>| Message 322: DMARC verification passed. | 2022-09-07T10:11:18Z | false |
>| Message 322 contains message ID header '<add53137-42a8-4753-af53-bad0752af24d@az.westeurope.production.microsoft.com>'. | 2022-09-07T10:11:18Z | false |
>| Message 322 original subject on injection: Microsoft 365 Defender has detected a security threat | 2022-09-07T10:11:18Z | false |
>| Message 322 Domains for which SDR is requested: reverse DNS host: test.cloudapp.net, helo: test.cloudapp.net, env-from: microsoft.com, header_from: microsoft.com, reply_to: Not Present | 2022-09-07T10:11:18Z | false |
>| Message 322 Consolidated Sender Threat Level: Neutral, Threat Category: N/A, Suspected Domain(s) : N/A (other reasons for verdict). Sender Maturity: 30 days (or greater) for domain: test.cloudapp.net | 2022-09-07T10:11:18Z | false |
>| Message 322 (71983 bytes) from azure-noreply@microsoft.com ready. | 2022-09-07T10:11:18Z | false |
>| Message 322 has sender_group: ACCEPTLIST, sender_ip: 7.7.7.7 and sbrs: 3.5 | 2022-09-07T10:11:18Z | false |
>| Message 322 matched per-recipient policy DEFAULT for inbound mail policies. | 2022-09-07T10:11:19Z | false |
>| Incoming connection (ICID 10821) lost. | 2022-09-07T10:11:19Z | false |
>| Message 322 scanned by Anti-Spam engine: CASE. Interim verdict: Negative | 2022-09-07T10:11:19Z | false |
>| Message 322 scanned by Anti-Spam engine CASE. Interim verdict: definitely negative. | 2022-09-07T10:11:19Z | false |
>| Message 322 scanned by Anti-Spam engine: CASE. Final verdict: Negative | 2022-09-07T10:11:19Z | false |
>| Message 322 scanned by Anti-Virus engine McAfee. Interim verdict: CLEAN | 2022-09-07T10:11:19Z | false |
>| Message 322 scanned by Anti-Virus engine Sophos. Interim verdict: CLEAN | 2022-09-07T10:11:19Z | false |
>| Message 322 scanned by Anti-Virus engine. Final verdict: Negative  | 2022-09-07T10:11:19Z | false |
>| Message 322 scanned by Advanced Malware Protection engine. Final verdict: SKIPPED(no attachment in message) | 2022-09-07T10:11:19Z | false |
>| Message 322 scanned by Outbreak Filters. Verdict: Negative | 2022-09-07T10:11:19Z | false |
>| Message 322 queued for delivery. | 2022-09-07T10:11:19Z | false |
>| SMTP delivery connection (DCID 4368) opened from Cisco IronPort interface 2.2.2.2 to IP address 1.1.1.1 on port 25. | 2022-09-07T10:11:19Z | false |
>| Delivery connection (DCID 4368) successfully accepted TLS protocol TLSv1.2 cipher ECDHE-RSA-AES256-GCM-SHA384 None. | 2022-09-07T10:11:19Z | false |
>| (DCID 4368) Delivery started for message 322 to t2@test.com. | 2022-09-07T10:11:19Z | false |
>| (DCID 4368) Delivery details: Message 322 sent to t2@test.com [('from', 'Microsoft 365 Defender <defender-noreply@microsoft.com>'), ('to', 't2@test.com')] | 2022-09-07T10:11:20Z | false |
>| Message 322 to t2@test.com received remote SMTP response '2.6.0 <add53137-42a8-4753-af53-bad0752af24d@az.westeurope.production.microsoft.com> [InternalId=1511828495895, Hostname=test.test.PROD.OUTLOOK.COM] 92322 bytes in 0.189, 475.293 KB/sec Queued mail for delivery'. | 2022-09-07T10:11:21Z | true |


### cisco-sma-message-amp-details-get
***
Get message AMP summary details.


#### Base Command

`cisco-sma-message-amp-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial_number | Email gateway serial number. | Required | 
| message_ids | Message ID list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSMA.AMPDetail.sdrAge | String | Sender Domain Reputation age. | 
| CiscoSMA.AMPDetail.attachments | String | Message attachments. | 
| CiscoSMA.AMPDetail.hostName | String | Email gateway hostname. | 
| CiscoSMA.AMPDetail.direction | String | Message direction, incoming or outgoing. | 
| CiscoSMA.AMPDetail.messageStatus | String | Message delivery status. | 
| CiscoSMA.AMPDetail.senderGroup | String | Matched sender group. | 
| CiscoSMA.AMPDetail.subject | String | Email message subject. | 
| CiscoSMA.AMPDetail.sdrCategory | String | Sender Domain Reputation category. | 
| CiscoSMA.AMPDetail.mid | Number | Message ID. | 
| CiscoSMA.AMPDetail.ampDetails.timestamp | String | AMP event summary details timestamp. | 
| CiscoSMA.AMPDetail.ampDetails.description | String | AMP event summary details description. | 
| CiscoSMA.AMPDetail.ampDetails.lastEvent | Boolean | AMP event summary details last event. | 
| CiscoSMA.AMPDetail.smtpAuthId | String | SMTP auth ID. | 
| CiscoSMA.AMPDetail.midHeader | String | Message ID header. | 
| CiscoSMA.AMPDetail.timestamp | String | Email message time. | 
| CiscoSMA.AMPDetail.messageSize | String | Email message size. | 
| CiscoSMA.AMPDetail.sdrThreatLevels | String | Sender Domain Reputation threat levels. | 
| CiscoSMA.AMPDetail.sdrReputation | String | Sender Domain Reputation. | 
| CiscoSMA.AMPDetail.recipient | String | Message recipient email address. | 
| CiscoSMA.AMPDetail.sender | String | Message sender email address. | 
| CiscoSMA.AMPDetail.showAMPDetails | Boolean | Whether to show AMP details. | 
| CiscoSMA.AMPDetail.allIcid | Number | ICIDs list. | 
| CiscoSMA.AMPDetail.headerFrom | String | Email header from. | 

#### Command example
```!cisco-sma-message-amp-details-get message_ids=21 serial_number=42356DFA5D016457B182-3616BA148E19```
#### Context Example
```json
{
    "CiscoSMA": {
        "AMPDetail": {
            "allIcid": [
                1269
            ],
            "ampDetails": [
                {
                    "description": "File reputation query initiating. File Name = test.jpg, MID = 21, File Size = 325663 bytes, File Type = image/jpeg",
                    "timestamp": "2022-08-24T10:05:55Z"
                },
                {
                    "description": "Response received for file reputation query from Cloud. File Name = test.jpg, MID = 21, Disposition = FILE UNKNOWN, Malware = None, Analysis Score = 0, sha256 = 23a9113530549916cd5b410edee79cb5a0fc01233eb9051f9c882a2e7c3fbfbe, upload_action = Recommended to send the file for analysis, verdict_source = AMP",
                    "timestamp": "2022-08-24T10:05:56Z"
                },
                {
                    "description": "File not uploaded for analysis. MID = 21 File SHA256[23a9113530549916cd5b410edee79cb5a0fc01233eb9051f9c882a2e7c3fbfbe] file mime[image/jpeg] Reason: The file type is not configured for analysis",
                    "lastEvent": true,
                    "timestamp": "2022-08-24T10:05:56Z"
                }
            ],
            "ampTgCategories": [],
            "attachments": [
                "test.jpg"
            ],
            "direction": "incoming",
            "headerFrom": "t3@test.com",
            "hostName": "esa1.test.eu.iphmx.com (1.1.1.1)",
            "messageSize": "439.29 (KB)",
            "messageStatus": "Quarantined by Content Filters",
            "mid": [
                21
            ],
            "midHeader": "<CAMuXvaVQMGq8uzJQXmfyoYQB55rOCJ0nW9OKncfnuCAnEc5S4g@mail.gmail.com>",
            "recipient": [
                "test@test.com"
            ],
            "sdrAge": "30 days (or greater)",
            "sdrCategory": "N/A",
            "sdrReputation": "Neutral",
            "sdrThreatLevels": "3",
            "sender": "t3@test.com",
            "senderGroup": "ACCEPTLIST",
            "sendingHostSummary": {},
            "showAMPDetails": true,
            "smtpAuthId": "",
            "subject": "Fwd: test12345",
            "timestamp": "2022-08-24T10:05:52Z"
        }
    }
}
```

#### Human Readable Output

>### Message AMP Report Details
>Found AMP details for message ID 21.
>|Mid|All Icid|Subject|Sender|Recipient|Attachments|Timestamp|Message Size|Message Status|Direction|Sender Group|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 21 | 1269 | Fwd: test12345 | t3@test.com | test@test.com | test.jpg | 2022-08-24T10:05:52Z | 439.29 (KB) | Quarantined by Content Filters | incoming | ACCEPTLIST |
>### Message AMP Report Details Summary
>|Description|Timestamp|
>|---|---|
>| File reputation query initiating. File Name = test.jpg, MID = 21, File Size = 325663 bytes, File Type = image/jpeg | 2022-08-24T10:05:55Z |
>| Response received for file reputation query from Cloud. File Name = test.jpg, MID = 21, Disposition = FILE UNKNOWN, Malware = None, Analysis Score = 0, sha256 = 23a9113530549916cd5b410edee79cb5a0fc01233eb9051f9c882a2e7c3fbfbe, upload_action = Recommended to send the file for analysis, verdict_source = AMP | 2022-08-24T10:05:56Z |
>| File not uploaded for analysis. MID = 21 File SHA256[23a9113530549916cd5b410edee79cb5a0fc01233eb9051f9c882a2e7c3fbfbe] file mime[image/jpeg] Reason: The file type is not configured for analysis | 2022-08-24T10:05:56Z |


### cisco-sma-message-dlp-details-get
***
Get message DLP summary details.


#### Base Command

`cisco-sma-message-dlp-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial_number | Email gateway serial number. | Required | 
| message_ids | Message ID list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSMA.DLPDetail.direction | String | Message direction, incoming or outgoing. | 
| CiscoSMA.DLPDetail.smtpAuthId | String | SMTP auth ID. | 
| CiscoSMA.DLPDetail.sdrAge | String | Sender Domain Reputation age. | 
| CiscoSMA.DLPDetail.sender | String | Message sender email address. | 
| CiscoSMA.DLPDetail.midHeader | String | Message ID header. | 
| CiscoSMA.DLPDetail.timestamp | String | Email message time. | 
| CiscoSMA.DLPDetail.sdrCategory | String | Sender Domain Reputation category. | 
| CiscoSMA.DLPDetail.hostName | String | Email gateway hostname. | 
| CiscoSMA.DLPDetail.mid | Number | Message ID. | 
| CiscoSMA.DLPDetail.attachments | String | Message attachments. | 
| CiscoSMA.DLPDetail.messageSize | String | Email message size. | 
| CiscoSMA.DLPDetail.dlpDetails.violationSeverity | String | DLP details violation severity. | 
| CiscoSMA.DLPDetail.dlpDetails.dlpMatchedContent.messagePartMatch.classifier | String | DLP matched content classifier. | 
| CiscoSMA.DLPDetail.dlpDetails.dlpMatchedContent.messagePartMatch.classifierMatch | String | DLP matched content classifier match. | 
| CiscoSMA.DLPDetail.dlpDetails.dlpMatchedContent.messagePart | String | DLP matched content message part. | 
| CiscoSMA.DLPDetail.dlpDetails.mid | String | DLP message ID. | 
| CiscoSMA.DLPDetail.dlpDetails.riskFactor | Number | DLP risk factor. | 
| CiscoSMA.DLPDetail.dlpDetails.dlpPolicy | String | DLP policy. | 
| CiscoSMA.DLPDetail.sdrThreatLevels | String | Sender Domain Reputation threat levels. | 
| CiscoSMA.DLPDetail.sdrReputation | String | Sender Domain Reputation. | 
| CiscoSMA.DLPDetail.messageStatus | String | Message delivery status. | 
| CiscoSMA.DLPDetail.allIcid | Number | ICIDs list. | 
| CiscoSMA.DLPDetail.senderGroup | String | Matched sender group. | 
| CiscoSMA.DLPDetail.recipient | String | Message recipient email address. | 
| CiscoSMA.DLPDetail.subject | String | Email message subject. | 
| CiscoSMA.DLPDetail.headerFrom | String | Email header from. | 

#### Command example
```!cisco-sma-message-dlp-details-get message_ids=84 serial_number=423ADC9EBD9C5F1A7A64-B81D2582608C```
#### Context Example
```json
{
    "CiscoSMA": {
        "DLPDetail": {
            "allIcid": [
                3862
            ],
            "ampTgCategories": [],
            "attachments": "",
            "direction": "outgoing",
            "dlpDetails": {
                "dlpMatchedContent": [
                    {
                        "messagePart": "Message",
                        "messagePartMatch": [
                            {
                                "classifier": "Credit Card Numbers",
                                "classifierMatch": [
                                    "CVV Code Country/Currency Result
                                    Amex 374245455400126 05/2023 Success
                                    Amex 378282246310005",
                                    "Visa 4917484589897107",
                                    "Visa 4263982640269299 (3 matches)",
                                ]
                            }
                        ]
                    }
                ],
                "dlpPolicy": "PCI-DSS (Payment Card Industry Data Security Standard)",
                "mid": 84,
                "riskFactor": 72,
                "violationSeverity": "HIGH"
            },
            "headerFrom": "test@test.com",
            "hostName": "esa2.test.eu.iphmx.com (2.2.2.2)",
            "messageSize": "84.56 (KB)",
            "messageStatus": "Delivered",
            "mid": [
                84
            ],
            "midHeader": "<AM5PR10MB1649CD2104EBDB7ACB849744B6779@AM5PR10MB1649.EURPRD10.PROD.OUTLOOK.COM>",
            "recipient": [
                "t1@test.com"
            ],
            "sender": "test@test.com",
            "senderGroup": "RELAY_O365",
            "sendingHostSummary": {},
            "showDLPDetails": true,
            "smtpAuthId": "",
            "subject": "Fw: Re: ",
            "timestamp": "2022-08-28T06:56:26Z"
        }
    }
}
```

#### Human Readable Output

>### Message DLP Report Details
>Found DLP details for message ID 84.
>|Mid|All Icid|Subject|Sender|Recipient|Timestamp|Message Size|Message Status|Direction|Sender Group|
>|---|---|---|---|---|---|---|---|---|---|
>| 84 | 3862 | Fw: Re:  | test@test.com | t1@test.com | 2022-08-28T06:56:26Z | 84.56 (KB) | Delivered | outgoing | RELAY_O365 |
>### Message DLP Report Details Summary
>|Mid|Violation Severity|Risk Factor|Dlp Policy|
>|---|---|---|---|
>| 84 | HIGH | 72 | PCI-DSS (Payment Card Industry Data Security Standard) |


### cisco-sma-message-url-details-get
***
Get message URL summary details.


#### Base Command

`cisco-sma-message-url-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial_number | Email gateway serial number. | Required | 
| message_ids | Message ID list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSMA.URLDetail.sdrAge | String | Sender Domain Reputation age. | 
| CiscoSMA.URLDetail.attachments | String | Message attachments. | 
| CiscoSMA.URLDetail.showURLDetails | Boolean | Whether to show URL event details. | 
| CiscoSMA.URLDetail.urlDetails.timestamp | String | URL event details timestamp. | 
| CiscoSMA.URLDetail.urlDetails.description | String | URL event details description. | 
| CiscoSMA.URLDetail.hostName | String | Email gateway hostname. | 
| CiscoSMA.URLDetail.direction | String | Message direction, incoming or outgoing. | 
| CiscoSMA.URLDetail.messageStatus | String | Message delivery status. | 
| CiscoSMA.URLDetail.senderGroup | String | Matched sender group. | 
| CiscoSMA.URLDetail.subject | String | Email message subject. | 
| CiscoSMA.URLDetail.sdrCategory | String | Sender Domain Reputation category. | 
| CiscoSMA.URLDetail.mid | Number | Message ID. | 
| CiscoSMA.URLDetail.smtpAuthId | String | SMTP auth ID. | 
| CiscoSMA.URLDetail.midHeader | String | Message ID header. | 
| CiscoSMA.URLDetail.timestamp | String | Email message time. | 
| CiscoSMA.URLDetail.messageSize | String | Email message size. | 
| CiscoSMA.URLDetail.sdrThreatLevels | String | Sender Domain Reputation threat levels. | 
| CiscoSMA.URLDetail.sdrReputation | String | Sender Domain Reputation. | 
| CiscoSMA.URLDetail.recipient | String | Message recipient Email address. | 
| CiscoSMA.URLDetail.sender | String | Message sender email address. | 
| CiscoSMA.URLDetail.allIcid | Number | ICIDs list. | 
| CiscoSMA.URLDetail.headerFrom | String | Email header from. | 

#### Command example
```!cisco-sma-message-url-details-get message_ids=21 serial_number=42356DFA5D016457B182-3616BA148E19```
#### Context Example
```json
{
    "CiscoSMA": {
        "URLDetail": {
            "allIcid": [
                1269
            ],
            "ampTgCategories": [],
            "attachments": [
                "test.jpg"
            ],
            "direction": "incoming",
            "headerFrom": "t3@test.com",
            "hostName": "esa1.test.eu.iphmx.com (1.1.1.1)",
            "messageSize": "439.29 (KB)",
            "messageStatus": "Quarantined by Content Filters",
            "mid": [
                21
            ],
            "midHeader": "<CAMuXvaVQMGq8uzJQXmfyoYQB55rOCJ0nW9OKncfnuCAnEc5S4g@mail.gmail.com>",
            "recipient": [
                "test@test.com"
            ],
            "sdrAge": "30 days (or greater)",
            "sdrCategory": "N/A",
            "sdrReputation": "Neutral",
            "sdrThreatLevels": "3",
            "sender": "t3@test.com",
            "senderGroup": "ACCEPTLIST",
            "sendingHostSummary": {},
            "showURLDetails": true,
            "smtpAuthId": "",
            "subject": "Fwd: test12345",
            "timestamp": "2022-08-24T10:05:52Z",
            "urlDetails": [
                {
                    "description": "Message 21 URL: http://9.9.9.9:8080/ , URL reputation: -6.8, Condition: URL Reputation Rule.",
                    "timestamp": "2022-08-24T10:05:56Z"
                },
                {
                    "description": "Message 21 URL: https://test.com/x1OrRZcf/onIpchhYNy4wy9f4/ , URL reputation: -6.6, Condition: URL Reputation Rule.",
                    "timestamp": "2022-08-24T10:05:56Z"
                },
                {
                    "description": "Message 21 URL: http://9.9.9.9:8080 , URL reputation: -6.8, Condition: URL Reputation Rule.",
                    "timestamp": "2022-08-24T10:05:56Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Message URL Report Details
>Found URL details for message ID 21.
>|Mid|All Icid|Subject|Sender|Recipient|Attachments|Timestamp|Message Size|Message Status|Direction|Sender Group|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 21 | 1269 | Fwd: test12345 | t3@test.com | test@test.com | test.jpg | 2022-08-24T10:05:52Z | 439.29 (KB) | Quarantined by Content Filters | incoming | ACCEPTLIST |
>### Message URL Report Details Summary
>|Description|Timestamp|
>|---|---|
>| Message 21 URL: http:<span>//</span>9.9.9.9:8080/ , URL reputation: -6.8, Condition: URL Reputation Rule. | 2022-08-24T10:05:56Z |
>| Message 21 URL: https:<span>//</span>test.com/test/test/ , URL reputation: -6.6, Condition: URL Reputation Rule. | 2022-08-24T10:05:56Z |
>| Message 21 URL: http:<span>//</span>9.9.9.9:8080 , URL reputation: -6.8, Condition: URL Reputation Rule. | 2022-08-24T10:05:56Z |


### cisco-sma-report-get
***
Get statistics reports.
Note that each report type is compatible with different arguments.
Refer to the following link ("ESA Reporting" section in the file) in order to view the dedicated arguments for each report type.
https://www.cisco.com/c/dam/en/us/td/docs/security/security_management/sma/sma12-0/AsyncOS-API-Addendum-GD_General_Deployment.xlsx.


#### Base Command

`cisco-sma-report-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_type | Report Type. Possible values are: mail_incoming_traffic_summary, reporting_system, mail_vof_threat_summary, mail_vof_specific_threat_summary, mail_amp_threat_summary. Default is mail_incoming_traffic_summary. | Optional | 
| custom_report_type | Custom report type.<br/>Specify this argument in order to get a report that does not exist in the report_type argument. | Optional | 
| start_date | Start date in ISO format or &lt;number&gt; &lt;time unit&gt;,<br/>e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | Required | 
| end_date | End date in ISO format or &lt;number&gt; &lt;time unit&gt;,<br/>e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | Required | 
| device_group_name | The device group name. Default is Hosted_Cluster. | Optional | 
| device_name | The device name. | Optional | 
| order_by | Specify the attribute by which to order the data in the response. For example, orderBy=total_clean_recipients. | Optional | 
| order_dir | The report order direction. Specify sort direction. Possible values are: asc, desc. | Optional | 
| top | Specify the number of records with the highest values to return. | Optional | 
| filter_value | The value to search for. | Optional | 
| filter_by | The filter field to use. Filter the data to be retrieved according to the filter property and value. | Optional | 
| filter_operator | Filter the response data based on the value specified. Possible values are: begins_with, is. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSMA.Report.type | String | Report type. | 
| CiscoSMA.Report.resultSet | Number | Report results summary. | 

#### Command example
```!cisco-sma-report-get start_date=2weeks end_date=now device_group_name=Hosted_Cluster report_type=mail_incoming_traffic_summary```
#### Context Example
```json
{
    "CiscoSMA": {
        "Report": {
            "resultSet": [
                {
                    "failed_dkim": 0
                },
                {
                    "total_graymail_recipients": 6
                },
                {
                    "detected_spam": 35
                },
                {
                    "malicious_url": 2
                },
                {
                    "total_spoofed_emails": 0
                },
                {
                    "verif_decrypt_success": 0
                },
                {
                    "detected_virus": 0
                },
                {
                    "threat_content_filter": 1
                },
                {
                    "blocked_invalid_recipient": 6
                },
                {
                    "blocked_sdr": 0
                },
                {
                    "marketing_mail": 5
                },
                {
                    "ims_spam_increment_over_case": 0
                },
                {
                    "total_mailbox_auto_remediated_recipients": 0
                },
                {
                    "detected_spam_certain": 35
                },
                {
                    "detected_spam_suspect": 0
                },
                {
                    "blocked_dmarc": 0
                },
                {
                    "total_threat_recipients": 3498
                },
                {
                    "total_recipients": 4069
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
                    "total_clean_recipients": 565
                },
                {
                    "detected_virus_per_msg": 0
                },
                {
                    "failed_spf": 0
                },
                {
                    "blocked_reputation": 3454
                }
            ],
            "type": "mail_incoming_traffic_summary",
            "uuid": "54db5cef-36a4-44a7-a121-37d9fb4e3971"
        }
    }
}
```

#### Human Readable Output

>### Report type: mail_incoming_traffic_summary
>Report UUID: 54db5cef-36a4-44a7-a121-37d9fb4e3971
>|Blocked Dmarc|Blocked Invalid Recipient|Blocked Reputation|Blocked Sdr|Bulk Mail|Detected Amp|Detected Spam|Detected Spam Certain|Detected Spam Suspect|Detected Virus|Detected Virus Per Msg|Failed Dkim|Failed Spf|Ims Spam Increment Over Case|Malicious Url|Marketing Mail|Social Mail|Threat Content Filter|Total Clean Recipients|Total Graymail Recipients|Total Mailbox Auto Remediated Recipients|Total Recipients|Total Spoofed Emails|Total Threat Recipients|Verif Decrypt Fail|Verif Decrypt Success|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0 | 6 | 3454 | 0 | 1 | 0 | 35 | 35 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 5 | 0 | 1 | 565 | 6 | 0 | 4069 | 0 | 3498 | 0 | 0 |
