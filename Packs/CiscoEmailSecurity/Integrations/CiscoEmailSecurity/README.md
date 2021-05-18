Cisco Email Security is an email security gateway . It detects and blocks a wide variety of email-borne threats, such as malware, spam and phishing.
This integration was integrated and tested with version 13 of CiscoEmailSecurity
## Configure CiscoEmailSecurity on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CiscoEmailSecurity.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| base_url | Server URL \(e.g. https://192.168.0.1\) | True |
| credentials | API Username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| timeout | request timeout | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cisco-email-security-report-get
***
Retrieves details of an email security report by counter type.


#### Base Command

`cisco-email-security-report-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| end_date | End datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| counter | Fetch data from a specific counter. Possible values are "reporting_system", "mail_incoming_traffic_summary", "mail_vof_threat_summary", "mail_vof_specific_threat_summary", and "mail_amp_threat_summary". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoEmailSecurity.Report.MailAmpThreatSummary.incoming_malicious | Number | The number of incoming malicious messages. | 
| CiscoEmailSecurity.Report.MailAmpThreatSummary.outgoing_malicious | Number | The number of outgoing malicious messages. | 
| CiscoEmailSecurity.Report.MailVofSpecificThreatSummary.threat_detected_virus_or_malware | Number | The number of the messages identified as a virus or malware. | 
| CiscoEmailSecurity.Report.MailVofThreatSummary.threat_detected | Number | The total number of messages identified as a threat. | 
| CiscoEmailSecurity.Report.ReportingSystem.heartbeat | Number | The reporting system heartbeat. | 
| CiscoEmailSecurity.Report.ReportingSystem.end_time | String | The reporting end time. | 
| CiscoEmailSecurity.Report.ReportingSystem.begin_time | String | The reporting start time. | 
| CiscoEmailSecurity.Report.ReportingSystem.centralized_reporting_expired | Number | The number of messages that centralized reporting expired. | 
| CiscoEmailSecurity.Report.ReportingSystem.centralized_reporting_enabled | Number | The number of messages that centralized reporting enabled. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.blocked_dmarc | Number | The number of blocked dmarc messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.blocked_invalid_recipient | Number | The number of blocked invalid recipient messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.blocked_reputation | Number | The number of blocked reputation messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.bulk_mail | Number | The number of bulk mail messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.detected_amp | Number | The number of detected amp messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.detected_spam | Number | The number of detected spam messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.detected_virus | Number | The number of detected virus messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.malicious_url | Number | The number of malicious URL messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.marketing_mail | Number | The number of blocked dmarc messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.social_mail | Number | The number of marketing mail messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.threat_content_filter | Number | The number of threat content filter messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.total_clean_recipients | Number | The total number of clean recipients. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.total_graymail_recipients | Number | The total number of graymail recipients. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.total_recipients | Number | The tota number of recipients. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.total_threat_recipients | Number | The total number of threat recipients. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.verif_decrypt_fail | Number | The number of verif decrypt fail messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.verif_decrypt_success | Number | The number of verif decrypt success messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.detected_spam_suspect | Number | The number of suspected spam messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.detected_spam_certain | Number | The number of certain spam certain messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.failed_spf | Number | The number of failed spf messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.failed_dkim | Number | The number of failed dkim messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.total_spoofed_emails | Number | The total number of spoofed email messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.total_mailbox_auto_remediated_recipients | Number | The total number of mailbox auto-remediated recipients. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.detected_virus_per_msg | Number | The number of detected virus per msg messages. | 
| CiscoEmailSecurity.Report.MailIncomingTrafficSummary.ims_spam_increment_over_case | Number | The number of ims spam increment over case messages. | 




### cisco-email-security-messages-search
***
Executes a search for messages in Cisco Email Security.


#### Base Command

`cisco-email-security-messages-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| end_date | End datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| limit | The maximum number of records to retrieve.<br/>If you set a limit you should also use an offset. | Optional | 
| offset | Specify an offset value to retrieve a subset of records starting with the offset value.<br/>If you use an offset you should also set a retrieval limit. | Optional | 
| attachment_name_operator | Attachment name operator to filter by.<br/>If you want to use attachment, you need to pass the following arguments: attachment_name_operator and attachment_name_value. Possible values are: "is", "begins_with", and "contains". | Optional | 
| attachment_name_value | Attachment name value to filter by.<br/>If you want to use attachment, you need to pass the following arguments: attachment_name_operator and attachment_name_value. | Optional | 
| file_hash | File SHA256 hash to filter by. | Optional | 
| recipient_filter_operator | Recipient filter operator to filter by.<br/>If you want to use recipient, you need to pass the following arguments: recipient_filter_operator and recipient_filter_value. Possible values are: "is", "begins_with", and "contains". | Optional | 
| recipient_filter_value | Recipient filter value to filter with.<br/>If you want to use recipient, you need to pass the following arguments: recipient_filter_operator and recipient_filter_value. | Optional | 
| sender_filter_operator | Sender filter operator to filter with.<br/>If you want to use sender, you need to pass the following arguments: sender_filter_operator and sender_filter_value. Possible values are: "is", "begins_with", and "contains". | Optional | 
| sender_filter_value | Sender filter value to filter by.<br/>If you want to use sender, you need to pass the following arguments: sender_filter_operator and sender_filter_value. | Optional | 
| subject_filter_operator | Subject filter operator to filter by<br/>If you want to use subject, you need to pass the following arguments: subject_filter_operator and subject_filter_value. Possible values are: "is", "begins_with", and "contains". | Optional | 
| subject_filter_value | Subject filter value to filter by.<br/>If you want to use subject, you need to pass the following arguments: subject_filter_operator and subject_filter_value. | Optional | 
| message_id | Message ID to filter with | Optional | 
| cisco_message_id | Cisco message ID to filter by. | Optional | 
| sender_ip | Sender IP address to filter by. | Optional | 
| message_direction | Message direction to filter by. Possible values are "incoming" and "outgoing". | Optional | 
| spam_positive | Whether to filter by positive spam positive. Possible values are: "True" and "False". | Optional | 
| quarantined_as_spam | Whether to filter by in spam quarantine. Possible values: are "True" and "False". | Optional | 
| quarantine_status | Quarantine status to filter. Possible values are: "POLICY", "AMP", "AV", "UNCLASSIFIED", "DLP", and "OUTBREAK". | Optional | 
| url_reputation | URL reputation to filter by. Possible values are: "Malicious" and "Suspicious". | Optional | 
| virus_positive | Virus positive to filter by. Possible values are: "True" and "False". | Optional | 
| domain_name_operator | Domain name operator to filter by.<br/>If you want to use domain filter, you need to pass the following arguments: domain_name_operator and domain_name_value. Possible values are: "is", "begins_with", and "contains". | Optional | 
| domain_name_value | Domain name value to filter by.<br/>If you want to use domain filter, you need to pass the following arguments: domain_name_operator and domain_name_value. | Optional | 
| contained_malicious_urls | Whether to filter by contained malicious URLs. Possible values are: "True" and "False". | Optional | 
| contained_neutral_urls | Whether to filter by is contained natural URLs. Possible values are: "True" and "False". | Optional | 
| macro_file_types_detected | Macro file types detected to filter by.<br/>temlate of macro_file_types_detected -  Microsoft%20Office%20Files,Adobe%20Portable%20Document%20Format<br/> | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoEmailSecurity.Messages.attributes.direction | String | The message direction. | 
| CiscoEmailSecurity.Messages.attributes.hostName | String | The message hostName. | 
| CiscoEmailSecurity.Messages.attributes.icid | Number | The message injection connection ID. | 
| CiscoEmailSecurity.Messages.attributes.isCompleteData | Boolean | Whether all data is in the message. | 
| CiscoEmailSecurity.Messages.attributes.mailPolicy | String | The message mail policy. | 
| CiscoEmailSecurity.Messages.attributes.messageStatus | String | The status of the message. | 
| CiscoEmailSecurity.Messages.attributes.mid | Number | The message ID. | 
| CiscoEmailSecurity.Messages.attributes.recipient | String | The recipient of the message. | 
| CiscoEmailSecurity.Messages.attributes.replyTo | String | Who the message is in reply to. | 
| CiscoEmailSecurity.Messages.attributes.sbrs | String | The message sender base score. | 
| CiscoEmailSecurity.Messages.attributes.sender | String | The message sender. | 
| CiscoEmailSecurity.Messages.attributes.senderDomain | String | The message sender domain. | 
| CiscoEmailSecurity.Messages.attributes.senderGroup | String | The message sender group. | 
| CiscoEmailSecurity.Messages.attributes.senderIp | String | The message sender IP address. | 
| CiscoEmailSecurity.Messages.attributes.serialNumber | String | The message serial number. | 
| CiscoEmailSecurity.Messages.attributes.subject | String | The message subject. | 
| CiscoEmailSecurity.Messages.attributes.timestamp | String | The message datetime. | 
| CiscoEmailSecurity.Messages.attributes.verdictChart | String | The message verdict chart. | 




### cisco-email-security-message-details-get
***
Retrieves details of a message.


#### Base Command

`cisco-email-security-message-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| end_date | End datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| cisco_id | Cisco message ID to filter with. | Required | 
| message_id | Message ID to filter with. | Required | 
| appliance_serial_number | Appliance serial number to filter with. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoEmailSecurity.Message.attachments | String | The attachments of the message. | 
| CiscoEmailSecurity.Message.direction | String | The message direction. | 
| CiscoEmailSecurity.Message.hostName | String | The message host name. | 
| CiscoEmailSecurity.Message.isCompleteData | Number | Is there in the message all the data. | 
| CiscoEmailSecurity.Message.mailPolicy | String | The message mail policy. | 
| CiscoEmailSecurity.Message.messageSize | String | The size of the message. | 
| CiscoEmailSecurity.Message.messageStatus | String | The status of the message. | 
| CiscoEmailSecurity.Message.mid | Number | Message ID. | 
| CiscoEmailSecurity.Message.midHeader | String | The header message ID of the message. | 
| CiscoEmailSecurity.Message.recipient | String | The recipient of the message. | 
| CiscoEmailSecurity.Message.sender | String | The sender of the message. | 
| CiscoEmailSecurity.Message.senderGroup | String | The sender group of the message. | 
| CiscoEmailSecurity.Message.sendingHostSummary.ipAddress | String | The IP address of the host message. | 
| CiscoEmailSecurity.Message.sendingHostSummary.reverseDnsHostname | String | The dns host name of the message. | 
| CiscoEmailSecurity.Message.sendingHostSummary.sbrsScore | String | The sender base score host of the message. | 
| CiscoEmailSecurity.Message.showAMP | Boolean | Is the AMP shown. | 
| CiscoEmailSecurity.Message.showDLP | Boolean | Wheter the DLP is shown. | 
| CiscoEmailSecurity.Message.showSummaryTimeBox | Boolean | Whether the summary time box is shown. | 
| CiscoEmailSecurity.Message.showURL | Boolean | Whether the URL is shown. | 
| CiscoEmailSecurity.Message.smtpAuthId | String | The SMTP auth ID of the message. | 
| CiscoEmailSecurity.Message.subject | String | The message date subject. | 
| CiscoEmailSecurity.Message.summary.description | String | The message summary description. | 
| CiscoEmailSecurity.Message.summary.lastEvent | Number | The message summary last event. | 
| CiscoEmailSecurity.Message.summary.timestamp | String | The message summary timestamp. | 
| CiscoEmailSecurity.Message.timestamp | String | The message timestamp. | 




### cisco-email-security-spam-quarantine-search
***
Executes a search for spam quarantine.


#### Base Command

`cisco-email-security-spam-quarantine-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| end_date | End datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| limit | Specify the number of records to retrieve.<br/>If you use a limit you should also use a offset. | Optional | 
| offset | Specify an offset value to retrieve a subset of records starting with the offset value.<br/>If you use an offset you should also set a retrieval limit. | Optional | 
| order_by_from_address | From address to filter by. | Optional | 
| order_by_to_address | To address to filter by. | Optional | 
| order_by_subject | Subject to filter by | Optional | 
| order_dir_from_address | From address order to filter by. Possible values are: "asc" and "desc". | Optional | 
| order_dir_to_address | To address order to filter by. Possible values are: "asc" and "desc". | Optional | 
| order_dir_subject | Subject order to filter by. Possible values are: "asc" and "desc". | Optional | 
| recipient_value | Recipient value to filter by. | Optional | 
| recipient_operator | Recipient operator to filter by. Possible values are: "is", "begins_with", and "contains". | Optional | 
| filter_value | Filter value to filter by. | Optional | 
| filter_operator | Filter operator to filter by. Possible values are: "is", "begins_with", and "contains". | Optional | 


#### Context Output

There is no context output for this command.



### cisco-email-security-spam-quarantine-message-details-get
***
Retrieves details for a quarantined message.


#### Base Command

`cisco-email-security-spam-quarantine-message-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | Message ID to filter by. | Required | 


#### Context Output

There is no context output for this command.



### cisco-email-security-dlp-details-get
***
Retrieves details on a DLP.


#### Base Command

`cisco-email-security-dlp-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| end_date | End datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| cisco_id | Cisco message ID to filter by. | Required | 
| message_id | Message ID to filter by. | Required | 
| appliance_serial_number | Appliance serial number to filter by. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoEmailSecurity.DLP.attachments | String | The attachments of the DLP. | 
| CiscoEmailSecurity.DLP.direction | String | The DLP direction. | 
| CiscoEmailSecurity.DLP.dlpDetails.dlpMatchedContent.messagePart | String | The message part of the DLP details. | 
| CiscoEmailSecurity.DLP.dlpDetails.dlpMatchedContent.messagePartMatch.classifier | String | The classifier of the DLP details. | 
| CiscoEmailSecurity.DLP.dlpDetails.dlpMatchedContent.messagePartMatch.classifierMatch | String | The classifier match of the DLP details. | 
| CiscoEmailSecurity.DLP.dlpDetails.dlpPolicy | String | The DLP policy. | 
| CiscoEmailSecurity.DLP.dlpDetails.mid | String | The message ID of the DLP details. | 
| CiscoEmailSecurity.DLP.dlpDetails.riskFactor | Number | The risk factor of the DLP. | 
| CiscoEmailSecurity.DLP.dlpDetails.violationSeverity | String | The violation severity of the DLP. | 
| CiscoEmailSecurity.DLP.hostName | String | The host name of the DLP. | 
| CiscoEmailSecurity.DLP.messageSize | String | The message size of the DLP. | 
| CiscoEmailSecurity.DLP.mid | Number | The message ID of the DLP. | 
| CiscoEmailSecurity.DLP.midHeader | String | The header message ID of the DLP. | 
| CiscoEmailSecurity.DLP.recipient | String | The recipient of the DLP. | 
| CiscoEmailSecurity.DLP.sender | String | The sender of the DLP. | 
| CiscoEmailSecurity.DLP.senderGroup | String | The sender group of the DLP. | 
| CiscoEmailSecurity.DLP.sendingHostSummary.ipAddress | String | The IP address of the host DLP. | 
| CiscoEmailSecurity.DLP.sendingHostSummary.reverseDnsHostname | String | The DNS host name of the DLP. | 
| CiscoEmailSecurity.DLP.sendingHostSummary.sbrsScore | String | The sender base score host of the DLP. | 
| CiscoEmailSecurity.DLP.showDLPDetails | Boolean | Whether the DLP details are shown. | 
| CiscoEmailSecurity.DLP.smtpAuthId | String | The SMTP auth ID of the DLP. | 
| CiscoEmailSecurity.DLP.subject | String | The subject of the DLP. | 
| CiscoEmailSecurity.DLP.timestamp | String | The datetime of the DLP. | 




### cisco-email-security-amp-details-get
***
Retrieves details of an AMP.


#### Base Command

`cisco-email-security-amp-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| end_date | End datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| cisco_id | Cisco message ID to filter by. | Required | 
| message_id | Message ID to filter by. | Required | 
| appliance_serial_number | Appliance serial number to filter by. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoEmailSecurity.AMP.ampDetails.description | String | The description of the AMP. | 
| CiscoEmailSecurity.AMP.ampDetails.lastEvent | Boolean | Whether this is the last event of the AMP. | 
| CiscoEmailSecurity.AMP.ampDetails.timestamp | String | The datetime of the AMP. | 
| CiscoEmailSecurity.AMP.attachments | String | The attachments of the AMP. | 
| CiscoEmailSecurity.AMP.direction | String | The direction of the AMP. | 
| CiscoEmailSecurity.AMP.hostName | String | The hostname of the AMP. | 
| CiscoEmailSecurity.AMP.messageSize | String | The message size of the AMP. | 
| CiscoEmailSecurity.AMP.mid | Number | The message ID of the AMP. | 
| CiscoEmailSecurity.AMP.midHeader | String | The header message ID of the AMP. | 
| CiscoEmailSecurity.AMP.recipient | String | The recipient of the AMP. | 
| CiscoEmailSecurity.AMP.sender | String | The sender of the AMP. | 
| CiscoEmailSecurity.AMP.senderGroup | String | The sender group of the AMP. | 
| CiscoEmailSecurity.AMP.sendingHostSummary.ipAddress | String | The IP address of the host AMP. | 
| CiscoEmailSecurity.AMP.sendingHostSummary.reverseDnsHostname | String | The DNS hostname of the AMP. | 
| CiscoEmailSecurity.AMP.sendingHostSummary.sbrsScore | String | The sender base score host of the AMP. | 
| CiscoEmailSecurity.AMP.showAMPDetails | Boolean | Whether AMP details are shown. | 
| CiscoEmailSecurity.AMP.smtpAuthId | String | The SMTP auth ID of the AMP. | 
| CiscoEmailSecurity.AMP.subject | String | The subject of the AMP. | 
| CiscoEmailSecurity.AMP.timestamp | String | The datetime of the AMP. | 




### cisco-email-security-url-details-get
***
Retrieves details of a URL.


#### Base Command

`cisco-email-security-url-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| end_date | End datetime for the search, in the following format: YYYY-MM-DD hh:mm:ss. The seconds must be 00, due to an API limitation. | Required | 
| cisco_id | Cisco message ID to filter by. | Required | 
| message_id | Message ID to filter by. | Required | 
| appliance_serial_number | Appliance serial number to filter by. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoEmailSecurity.URL.attachments | String | The attachments of the URL. | 
| CiscoEmailSecurity.URL.direction | String | The direction of the URL. | 
| CiscoEmailSecurity.URL.hostName | String | The hostName of the URL. | 
| CiscoEmailSecurity.URL.mid | Number | The message ID of the URL. | 
| CiscoEmailSecurity.URL.midHeader | String | The header message ID of the URL. | 
| CiscoEmailSecurity.URL.recipient | String | The recipient of the URL. | 
| CiscoEmailSecurity.URL.sdrAge | String | The software defined radio age of the URL. | 
| CiscoEmailSecurity.URL.sdrCategory | String | The software defined radio category of the URL. | 
| CiscoEmailSecurity.URL.sdrReputation | String | The software defined radio reputation of the URL. | 
| CiscoEmailSecurity.URL.sender | String | The URL of the sender. | 
| CiscoEmailSecurity.URL.senderGroup | String | The sender group of the URL. | 
| CiscoEmailSecurity.URL.sendingHostSummary.ipAddress | String | The IP address of the host URL. | 
| CiscoEmailSecurity.URL.sendingHostSummary.reverseDnsHostname | String | The DNS host name of the URL. | 
| CiscoEmailSecurity.URL.sendingHostSummary.sbrsScore | String | The sender base score host of the URL. | 
| CiscoEmailSecurity.URL.showURLDetails | Boolean | Whether the URL details are shown. | 
| CiscoEmailSecurity.URL.smtpAuthId | String | The SMTP auth ID of the URL. | 
| CiscoEmailSecurity.URL.subject | String | The URL subject. | 
| CiscoEmailSecurity.URL.urlDetails.description | String | The description of the URL. | 
| CiscoEmailSecurity.URL.urlDetails.lastEvent | Boolean | Whether this is the last event of the URL. | 
| CiscoEmailSecurity.URL.urlDetails.timestamp | String | The datetime of the URL details. | 




### cisco-email-security-spam-quarantine-messages-delete
***
Deletes quarantined messages.


#### Base Command

`cisco-email-security-spam-quarantine-messages-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| messages_ids | A list of ID's to delete, comma separated. | Required | 


#### Context Output

There is no context output for this command.



### cisco-email-security-spam-quarantine-messages-release
***
Releases quarantined messages.


#### Base Command

`cisco-email-security-spam-quarantine-messages-release`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| messages_ids | A comma-separated list of IDs to release. | Required | 


#### Context Output

There is no context output for this command.



### cisco-email-security-list-entries-get
***
Retrieves a list of entries.


#### Base Command

`cisco-email-security-list-entries-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | List type to filter by. Possible values are: "safelist" and "blocklist". | Required | 
| limit | Specify an offset value to retrieve a subset of records starting with the offset value.<br/>If you use an offset you should also set a retrieval limit. | Optional | 
| offset | Specify an offset value to retrieve a subset of records starting with the offset value.<br/>If you use a offset you should also use a limit. | Optional | 
| view_by | View by sender or recipient. | Required | 
| order_by | How to order the results. Possible values are: "sender" and "recipient". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoEmailSecurity.ListEntries.Safelist.senderList | String | The safelist sender list. | 
| CiscoEmailSecurity.ListEntries.Safelist.recipientAddresses | String | The safelist recipient addresses. | 
| CiscoEmailSecurity.ListEntries.Safelist.recipientList | String | The safelist recipient list. | 
| CiscoEmailSecurity.ListEntries.Safelist.senderAddresses | Number | The safelist sender addresses. | 
| CiscoEmailSecurity.ListEntries.Blocklist.senderList | String | The blocklist sender list. | 
| CiscoEmailSecurity.ListEntries.Blocklist.recipientAddresses | String | The blocklist recipient addresses. | 
| CiscoEmailSecurity.ListEntries.Blocklist.recipientList | String | The blocklist recipient list. | 
| CiscoEmailSecurity.ListEntries.Blocklist.senderAddresses | Number | The blocklist sender addresses. | 




### cisco-email-security-list-entry-add
***
Performs actions on list entries. Supports add, edit, and append.


#### Base Command

`cisco-email-security-list-entry-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | List type. Possible values are: "safelist" and "blocklist". | Required | 
| action | Select the action to perform on the list. Possible values are: "add", "edit", and "append". | Required | 
| recipient_addresses | A comma-separated list of recipient addresses on which to perform the action. separated) | Optional | 
| recipient_list | A comma-separated list of recipient lists on which to perform the action. | Optional | 
| sender_addresses | A comma-separated list of sender addresses on which to perform the action. | Optional | 
| sender_list | A comma-separated list of sender lists on which to perform the action. | Optional | 
| view_by | View by "sender" or "recipient". | Required | 


#### Context Output

There is no context output for this command.



### cisco-email-security-list-entry-delete
***
Deletes a list entry.


#### Base Command

`cisco-email-security-list-entry-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | List type | Required | 
| recipient_list | A comma-separated list of recipient lists to delete. | Optional | 
| sender_list | A comma-seaprated list of sender lists to delete. | Optional | 
| view_by | View by "sender" or "recipient". | Required | 


#### Context Output

There is no context output for this command.



