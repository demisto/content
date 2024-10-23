Symantec Email Security.cloud is a hosted service that filters email messages and helps protect organizations from malware (including targeted attacks and phishing), spam, and unwanted bulk email. The service offers encryption and data protection options to help control sensitive information sent by email and supports multiple mailbox types from various vendors.
This integration was integrated and tested with version xx of Symantec Email Security Cloud.

## Configure Symantec Email Security Cloud on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Symantec Email Security Cloud.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL - IOC |  |  |
    | Server URL - Data Feeds |  |  |
    | Server URL - Email Queue |  |  |
    | Server URL - Quarantine | The Quarantine API is available for United States \(us\) and European Union \(eu\). |  |
    | Username |  | False |
    | Password |  | False |
    | Quarantine Username |  | False |
    | Password |  | False |
    | Use system proxy settings |  |  |
    | Trust any certificate (not secure) |  |  |
    | Fetch incidents |  |  |
    | Maximum number of incidents per fetch | Maximum number of incidents per fetch. Default is 50. The maximum is 200. |  |
    | First Fetch Time |  |  |
    | Fetch Type | The API to fetch incidents from: Data Feeds, Quarantine or both. |  |
    | Severity - Email Data Feed | Filter the incidents by their severity. When left empty will fetch all. |  |
    | Type - Email Data Feed |  |  |
    | Include Delivery - Email Data Feed | Only relevant to \`all\` feed. Contains metadata that describes both inbound and outbound email delivery to provide visibility into email tracing, TLS compliance, and routing. |  |
    | Query - Email Quarantine | A search criterion that can be used to filter emails that match only certain conditions based on email metadata. |  |
    | Type - Email Quarantine | A string used to filter emails based on the quarantine type. |  |
    | Admin Domain - mail Quarantine | Returns the emails quarantined for users in a particular domain. If this parameter is present and has a valid domain name, then items from only that domain are returned. If it has a value of \`ALL\`, then all domains administered by the user are searched and emails quarantined for users in those domains are returned. Note: Can only be used by an administrator user. |  |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### symantec-email-security-ioc-list

***
List the IOCs that apply to a specific domain or to all domains.

#### Base Command

`symantec-email-security-ioc-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Run the command for a specific domain or all domains with 'global'. Use `symantec-email-security-email-queue-list` to get a list of available domains. Default is global. | Optional | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEmailSecurity.IOC.iocBlackListId | String | ID of the IOC. | 
| SymantecEmailSecurity.IOC.iocType | String | Type of the IOC value. | 
| SymantecEmailSecurity.IOC.iocValue | String | Value of the IOC. | 
| SymantecEmailSecurity.IOC.status | String | Wether the IOC is active. | 
| SymantecEmailSecurity.IOC.description | String | Description of the IOC. | 
| SymantecEmailSecurity.IOC.emailDirection | String | Email direction can be one of: I=Inbound, O=Outbound or B=Both. | 
| SymantecEmailSecurity.IOC.remediationAction | String | Remediation Action can be one of: B=Block and delete, Q=Quarantine, M=Redirect, T=Tag subject or H=Append header. | 
| SymantecEmailSecurity.IOC.expiryDate | String | Retention period for an IOC until it is removed from the system. | 

### symantec-email-security-ioc-action

***
Add, update, delete and renew multiple IOCs through the `entry_id` or a single through the rest of the parameters.

#### Base Command

`symantec-email-security-ioc-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Run the command for a specific domain or all domains with 'global'. Use `symantec-email-security-email-queue-list` to get a list of available domains. Default is global. | Optional | 
| action | Defines the action for IOCs: 'merge' to merge or update IOCs in the database by their type and value without inputting `ioc_id`; 'replace' to delete and replace all IOCs in the database without inputting `ioc_id`; 'ioc' to add, update, delete, or renew multiple IOCs each with their own action, use this only when entering an `entry_id`; 'add' to add an IOC without inputting `ioc_id`. Possible values are: merge, replace, upload_ioc_json, add, update, delete, renew. | Required | 
| entry_id | Entry ID of a JSON file to pass multiple IOCs. Only accepts `action=merge/replace/ioc`. Example value: [{"APIRowAction": "U", "IocBlacklistId": xxxx, "IocType": "url", "IocValue": "https://www.example.com", "Description": "Hello World!"}]. More about IOCs can be found in: https://techdocs.broadcom.com/content/dam/broadcom/techdocs/us/en/dita/symantec-security-software/email-security/email-security-cloud/content/Indicators-of-Compromise-(IOC)-Blacklist-API-Guide.pdf. | Optional | 
| ioc_id | ID of the IOC. Can't be used with action=`merge`\replace\`add`. | Optional | 
| ioc_type | Type of the IOC. Possible values are: attachmentname, md5attachment, sha2attachment, bodysenderdomain, bodysenderemail, bodysendertopleveldomain, envelopesenderdomain, envelopesenderemail, envelopesendertopleveldomain, senderipaddress, senderiprange, recipientdomain, recipientemail, subject, url. | Optional | 
| ioc_value | Value of the IOC. | Optional | 
| description | Description of the IOC. | Optional | 
| email_direction | Email direction to filter IOCs. Possible values are: inbound, outbound, both. | Optional | 
| remediation_action | Remediation action to be done on an IOC. Possible values are: block_and_delete, quarantine, redirect, tag_subject, append_header. | Optional | 

#### Context Output

There is no context output for this command.
### symantec-email-security-ioc-renew

***
Renew all IOCs previously uploaded and still in the database, whether active or inactive, for a specific domain or all domains. The default retention period for IOCs is 7 days and the maximum is 30 days. After 30 days IOCs are retained in an inactive state for another 14 days. If an organization receives new email containing previously block listed IOCs, then the IOCs can renewed in the block list within this grace period. Thereafter, IOCs are removed from the system and must be uploaded again to remain in the block list.

#### Base Command

`symantec-email-security-ioc-renew`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Run the command for a specific domain or all domains with 'global'. Use `symantec-email-security-email-queue-list` to get a list of available domains. Default is global. | Optional | 

#### Context Output

There is no context output for this command.
### symantec-email-security-data-list

***
Retrieves data feeds from Symantec Email Security.cloud. Available feeds: 'all' (metadata for all scanned email), 'malware' (malware-containing email data), 'threat-isolation' (events from URL and Attachment Isolation), 'clicktime' (metadata from end-user clicks on rewritten URLs), 'anti-spam' (spam detection metadata), and 'ec-reports' (contextual information about emails blocked by Anti-Malware service).

#### Base Command

`symantec-email-security-data-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed_type | The type of the email data feed to retrieve. Possible values are: all, malware, threat-isolation, clicktime, anti-spam, ec-reports. Default is all. | Optional | 
| start_from | Start time from for reading metadata. Accepted formats: any substring of yyyy-mm-ddThh:mm:ssZ, epoch 1720617001, relative 1 day 2h 3 minute. Max start time is 1095 days before current date. Default is 3 days. | Optional | 
| include_delivery | Only relevant to `all` feed. Contains metadata that describes both inbound and outbound email delivery to provide visibility into email tracing, TLS compliance, and routing. Possible values are: false, true. | Optional | 
| fetch_only_incidents | Whether to fetch only incident fields. Possible values are: true, false. | Optional | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEmailSecurity.Data.emailInfo.xMsgRef | String | Unique message reference identifier. | 
| SymantecEmailSecurity.Data.emailInfo.longMsgRef | String | Detailed message reference path. | 
| SymantecEmailSecurity.Data.emailInfo.messageId | String | Email's unique message identifier. | 
| SymantecEmailSecurity.Data.emailInfo.isOutbound | Number | Indicates if the email is outbound. | 
| SymantecEmailSecurity.Data.emailInfo.messageSize | Number | Size of the email message in bytes. | 
| SymantecEmailSecurity.Data.emailInfo.mailProcessingStartTime | Number | Start time of email processing. | 
| SymantecEmailSecurity.Data.emailInfo.subject | String | Subject line of the email. | 
| SymantecEmailSecurity.Data.emailInfo.envFrom | String | Envelope sender of the email. | 
| SymantecEmailSecurity.Data.emailInfo.envTo | String | Envelope receiver of the email. | 
| SymantecEmailSecurity.Data.emailInfo.headerFrom | String | Header sender of the email. | 
| SymantecEmailSecurity.Data.emailInfo.rawHeaderFrom | String | Raw header sender information. | 
| SymantecEmailSecurity.Data.emailInfo.headerReplyTo | String | Reply-to address in email header. | 
| SymantecEmailSecurity.Data.emailInfo.senderIp | String | IP address of the email sender. | 
| SymantecEmailSecurity.Data.emailInfo.senderMailserver | String | Mail server of the email sender. | 
| SymantecEmailSecurity.Data.emailInfo.country | String | Country of the email sender. | 
| SymantecEmailSecurity.Data.emailInfo.HELOString | String | HELO string from the mail server. | 
| SymantecEmailSecurity.Data.emailInfo.avQuarantinePenId | String | Quarantine pen ID for antivirus. | 
| SymantecEmailSecurity.Data.emailInfo.authResults | Unknown | Authentication results of the email. | 
| SymantecEmailSecurity.Data.emailInfo.filesAndLinks.nodeType | String | Type of node for files and links. | 
| SymantecEmailSecurity.Data.emailInfo.filesAndLinks.fileNameOrURL | String | File name or URL in the email. | 
| SymantecEmailSecurity.Data.emailInfo.filesAndLinks.fileSize | Number | Size of the file in the email. | 
| SymantecEmailSecurity.Data.emailInfo.filesAndLinks.fileType | String | Type of the file in the email. | 
| SymantecEmailSecurity.Data.emailInfo.filesAndLinks.md5 | String | MD5 hash of the file. | 
| SymantecEmailSecurity.Data.emailInfo.filesAndLinks.sha256 | String | SHA-256 hash of the file. | 
| SymantecEmailSecurity.Data.emailInfo.filesAndLinks.urlCategories | Unknown | Categories of URLs in the email. | 
| SymantecEmailSecurity.Data.emailInfo.filesAndLinks.urlRiskScore | Unknown | Risk score of URLs in the email. | 
| SymantecEmailSecurity.Data.emailInfo.filesAndLinks.index | Number | Index of the file/link in email. | 
| SymantecEmailSecurity.Data.emailInfo.filesAndLinks.parentIndex | Number | Parent index of the file/link in email. | 
| SymantecEmailSecurity.Data.emailInfo.filesAndLinks.linkSource | String | Source of the link in the email. | 
| SymantecEmailSecurity.Data.emailInfo.tlsInfo.tlsAdvertised | Number | Indicates if TLS was advertised. | 
| SymantecEmailSecurity.Data.emailInfo.tlsInfo.tlsUsed | Number | Indicates if TLS was used. | 
| SymantecEmailSecurity.Data.emailInfo.tlsInfo.tlsPolicy | String | Policy for using TLS. | 
| SymantecEmailSecurity.Data.emailInfo.tlsInfo.tlsProtocol | String | Protocol used for TLS. | 
| SymantecEmailSecurity.Data.emailInfo.tlsInfo.tlsCipher | String | Cipher used for TLS. | 
| SymantecEmailSecurity.Data.emailInfo.tlsInfo.tlsKeyLength | Number | Key length used for TLS. | 
| SymantecEmailSecurity.Data.emailInfo.tlsInfo.tlsFallbackReason | String | Reason for TLS fallback. | 
| SymantecEmailSecurity.Data.emailInfo.tlsInfo.tlsForwardSecrecy | Number | Indicates if forward secrecy was used. | 
| SymantecEmailSecurity.Data.emailInfo.tlsInfo.tlsNegotiationFailed | Number | Indicates if TLS negotiation failed. | 
| SymantecEmailSecurity.Data.emailInfo.newDomainAge | Unknown | Age of the new domain. | 
| SymantecEmailSecurity.Data.emailInfo.timeInCynicSandboxMs | Number | Time spent in Cynic sandbox in ms. | 
| SymantecEmailSecurity.Data.incidents | Unknown | Associated incidents. | 
| SymantecEmailSecurity.Data.clicktimeInfo.xMsgRef | String | Unique click message reference. | 
| SymantecEmailSecurity.Data.clicktimeInfo.squrlClickerIp | String | IP address of the URL clicker. | 
| SymantecEmailSecurity.Data.clicktimeInfo.squrlRecipient | String | Recipient of the clicked URL. | 
| SymantecEmailSecurity.Data.clicktimeInfo.url | String | Clicked URL. | 
| SymantecEmailSecurity.Data.clicktimeInfo.dateUrlAccess | Number | Timestamp of URL access. | 
| SymantecEmailSecurity.Data.clicktimeInfo.risk | Number | Risk level of the URL. | 
| SymantecEmailSecurity.Data.incident | Unknown | Associated incident details. | 
| SymantecEmailSecurity.Data.fireglass_log.timestamp | Date | Timestamp of the event. | 
| SymantecEmailSecurity.Data.fireglass_log.event | String | Type of event logged. | 
| SymantecEmailSecurity.Data.fireglass_log.source_ip | String | Source IP address of the event. | 
| SymantecEmailSecurity.Data.fireglass_log.url | String | URL involved in the event. | 
| SymantecEmailSecurity.Data.fireglass_log.referer_url | String | Referer URL of the event. | 
| SymantecEmailSecurity.Data.fireglass_log.request_method | String | HTTP request method used. | 
| SymantecEmailSecurity.Data.fireglass_log.user_agent | String | User agent string of the request. | 
| SymantecEmailSecurity.Data.fireglass_log.destination_ip | String | Destination IP address of the event. | 
| SymantecEmailSecurity.Data.fireglass_log.action | String | Action taken for the event. | 
| SymantecEmailSecurity.Data.fireglass_log.action_reason | String | Reason for the action taken. | 
| SymantecEmailSecurity.Data.fireglass_log.text | String | Text description of the event. | 
| SymantecEmailSecurity.Data.fireglass_log.rule_id | Number | ID of the rule applied. | 
| SymantecEmailSecurity.Data.fireglass_log.rule_name | String | Name of the rule applied. | 
| SymantecEmailSecurity.Data.fireglass_log.service | String | Service involved in the event. | 
| SymantecEmailSecurity.Data.fireglass_log.mime_type | String | MIME type of the event. | 
| SymantecEmailSecurity.Data.fireglass_log.password_supplied | String | Indicates if a password was supplied. | 
| SymantecEmailSecurity.Data.fireglass_log.file_type | String | Type of file involved. | 
| SymantecEmailSecurity.Data.fireglass_log.content_type | String | Content type of the event. | 
| SymantecEmailSecurity.Data.fireglass_log.host | String | Host involved in the event. | 
| SymantecEmailSecurity.Data.fireglass_log.geoip_country_name | String | Country name from GeoIP lookup. | 
| SymantecEmailSecurity.Data.fireglass_log.top_level_url | String | Top-level URL involved. | 
| SymantecEmailSecurity.Data.fireglass_log.response_status_code | Number | HTTP response status code. | 
| SymantecEmailSecurity.Data.fireglass_log.resource_type | String | Type of resource involved. | 
| SymantecEmailSecurity.Data.fireglass_log.total_bytes | Number | Total bytes transferred. | 
| SymantecEmailSecurity.Data.fireglass_log.total_bytes_sent | Number | Total bytes sent. | 
| SymantecEmailSecurity.Data.fireglass_log.md5 | String | MD5 hash of the content. | 
| SymantecEmailSecurity.Data.fireglass_log.sha256 | String | SHA-256 hash of the content. | 
| SymantecEmailSecurity.Data.fireglass_log.file_path | String | File path of the content. | 
| SymantecEmailSecurity.Data.fireglass_log.file_name | String | File name of the content. | 
| SymantecEmailSecurity.Data.fireglass_log.details | String | Details of the event. | 
| SymantecEmailSecurity.Data.fireglass_log.url_risk | Number | Risk score of the URL. | 
| SymantecEmailSecurity.Data.fireglass_log.tenant_id | String | Tenant ID associated with the event. | 
| SymantecEmailSecurity.Data.fireglass_log.xMsgRef | String | Unique Fireglass message reference. | 
| SymantecEmailSecurity.Data.emailInfo.authResults.raw_header | String | Raw authentication results header. | 
| SymantecEmailSecurity.Data.emailInfo.authResults.dkim | String | DKIM verification result. | 
| SymantecEmailSecurity.Data.emailInfo.authResults.dkim_signing_domain | String | Domain used for DKIM signing. | 
| SymantecEmailSecurity.Data.emailInfo.authResults.spf | String | SPF verification result. | 
| SymantecEmailSecurity.Data.emailInfo.authResults.dmarc | String | DMARC verification result. | 
| SymantecEmailSecurity.Data.emailInfo.authResults.dmarc_policy | String | DMARC policy applied. | 
| SymantecEmailSecurity.Data.emailInfo.authResults.dmarc_override_action | String | Action overridden by DMARC policy. | 
| SymantecEmailSecurity.Data.incidents.xMsgRef | String | Unique incident message reference. | 
| SymantecEmailSecurity.Data.incidents.addressContexts.name | String | Name in incident address context. | 
| SymantecEmailSecurity.Data.incidents.addressContexts.domain | String | Domain in incident address context. | 
| SymantecEmailSecurity.Data.incidents.addressContexts.isSender | Number | Indicates if address is sender. | 
| SymantecEmailSecurity.Data.incidents.severity | String | Severity level of the incident. | 
| SymantecEmailSecurity.Data.incidents.securityService | String | Security service involved. | 
| SymantecEmailSecurity.Data.incidents.detectionMethod | String | Method used for detection. | 
| SymantecEmailSecurity.Data.incidents.verdict | String | Verdict of the incident. | 
| SymantecEmailSecurity.Data.incidents.action | String | Action taken for the incident. | 
| SymantecEmailSecurity.Data.incidents.reason | String | Reason for the action. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.nodeType | String | Type of node in incident. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.fileNameOrURL | String | File name or URL in incident. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.fileSize | Number | Size of the file in incident. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.fileType | String | Type of file in incident. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.md5 | String | MD5 hash of the file. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.sha256 | String | SHA-256 hash of the file. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.malwareName | String | Name of the detected malware. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.malwareCategory | String | Category of the detected malware. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.urlCategories | Unknown | Categories of URLs in the incident. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.urlRiskScore | Unknown | Risk score of URLs in the incident. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.index | Number | Index of the file/link in incident. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.parentIndex | Number | Parent index of the file/link in incident. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.xMsgRef | String | Unique incident file message reference. | 
| SymantecEmailSecurity.Data.incidents.filesAndLinks.linkSource | String | Source of the link in incident. | 
| SymantecEmailSecurity.Data.incidents.dmasDelivered | Unknown | Indicates if DMAS was delivered. | 
| SymantecEmailSecurity.Data.incidents.dmasInfo | Unknown | DMAS information related to the incident. | 
| SymantecEmailSecurity.Data.attacks.affectedUsers.key | String | Affected user email address. | 
| SymantecEmailSecurity.Data.attacks.affectedUsers.value | Number | Number of affected users. | 
| SymantecEmailSecurity.Data.attacks.affectedUsers.type | String | Type of affected users. | 
| SymantecEmailSecurity.Data.attacks.affectedUsersByDomain.key | String | Domain of affected users. | 
| SymantecEmailSecurity.Data.attacks.affectedUsersByDomain.value | Number | Number of affected users by domain. | 
| SymantecEmailSecurity.Data.attacks.affectedUsersByDomain.type | String | Type of affected users by domain. | 
| SymantecEmailSecurity.Data.attacks.geoIpSources.key | String | GeoIP source country code. | 
| SymantecEmailSecurity.Data.attacks.geoIpSources.value | Number | Percentage of attacks from GeoIP source. | 
| SymantecEmailSecurity.Data.attacks.geoIpSources.type | String | Type of GeoIP source data. | 
| SymantecEmailSecurity.Data.attacks.globalTimeline.key | Date | Date in global attack timeline. | 
| SymantecEmailSecurity.Data.attacks.globalTimeline.value | Number | Number of global attacks on date. | 
| SymantecEmailSecurity.Data.attacks.globalTimeline.type | String | Type of global timeline data. | 
| SymantecEmailSecurity.Data.attacks.ipSources.key | String | IP address of attack source. | 
| SymantecEmailSecurity.Data.attacks.ipSources.value | Number | Percentage of attacks from IP source. | 
| SymantecEmailSecurity.Data.attacks.ipSources.type | String | Type of IP source data. | 
| SymantecEmailSecurity.Data.attacks.localTimeline.key | Date | Date in local attack timeline. | 
| SymantecEmailSecurity.Data.attacks.localTimeline.value | Number | Number of local attacks on date. | 
| SymantecEmailSecurity.Data.attacks.localTimeline.type | String | Type of local timeline data. | 
| SymantecEmailSecurity.Data.attacks.threatNames.key | String | Name of the detected threat. | 
| SymantecEmailSecurity.Data.attacks.threatNames.value | Number | Percentage of attacks with this threat. | 
| SymantecEmailSecurity.Data.attacks.threatNames.type | String | Type of threat data. | 
| SymantecEmailSecurity.Data.attacks.traitImportance.ioc | String | Indicator of compromise. | 
| SymantecEmailSecurity.Data.attacks.traitImportance.value | String | Value of the trait. | 
| SymantecEmailSecurity.Data.attacks.traitImportance.weight | Number | Weight of the trait. | 
| SymantecEmailSecurity.Data.attacks.traitImportance.type | String | Type of trait data. | 
| SymantecEmailSecurity.Data.attacks.avgMailboxesGlobal | Number | Average global mailboxes affected. | 
| SymantecEmailSecurity.Data.attacks.attackVolumeGlobal | Number | Global volume of attacks. | 
| SymantecEmailSecurity.Data.attacks.attackVolumeLocal | Number | Local volume of attacks. | 
| SymantecEmailSecurity.Data.attacks.attackedMailboxesGlobal | Number | Number of globally attacked mailboxes. | 
| SymantecEmailSecurity.Data.attacks.attackedMailboxesLocal | Number | Number of locally attacked mailboxes. | 
| SymantecEmailSecurity.Data.attacks.attackedOrgsGlobal | Number | Number of globally attacked organizations. | 
| SymantecEmailSecurity.Data.attacks.attackDescription | String | Description of the attack. | 
| SymantecEmailSecurity.Data.attacks.attackType | String | Type of attack. | 
| SymantecEmailSecurity.Data.attacks.cluster | String | Cluster identifier for the attack. | 
| SymantecEmailSecurity.Data.topAttacked.key | String | Email address of top attacked user. | 
| SymantecEmailSecurity.Data.topAttacked.value | Number | Number of attacks on top user. | 
| SymantecEmailSecurity.Data.topAttacked.type | String | Type of attack count data. | 
| SymantecEmailSecurity.Data.reportWindowStartTime | Number | Start time of the report window. | 
| SymantecEmailSecurity.Data.reportWindowEndTime | Number | End time of the report window. | 

### symantec-email-security-email-queue-list

***
Returns a list of domains owned by the customer, with queue statistics for each domain.

#### Base Command

`symantec-email-security-email-queue-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domains | Comma-separated list of domains to retrieve. Leave empty to retrieve all domains. | Optional | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEmailSecurity.EmailQueue.TotalMessagesInbound | Number | Total number inbound messages in queue, for all domains. | 
| SymantecEmailSecurity.EmailQueue.TotalMessagesOutbound | Number | Total number of outbound messages in queue, for all domains. | 
| SymantecEmailSecurity.EmailQueue.MeanTimeInQueueInbound | Number | Average \(mean\) queue wait for inbound messages, for all domains. Measured in seconds. | 
| SymantecEmailSecurity.EmailQueue.MeanTimeInQueueOutbound | Number | Average \(mean\) queue wait for outbound messages, for all domains. Measured in seconds. | 
| SymantecEmailSecurity.EmailQueue.LongestTimeInInbound | Number | How long the oldest message in the inbound queue has been queue, across all domains. Measured in seconds. | 
| SymantecEmailSecurity.EmailQueue.LongestTimeInOutbound | Number | How long the oldest message in the outbound queue has been queue, across all domains. Measured in seconds. | 
| SymantecEmailSecurity.EmailQueue.Domains.Name | String | Name of the domain. | 
| SymantecEmailSecurity.EmailQueue.Domains.ReceiveQueueCountInbound | Number | Number of inbound messages waiting to be processed. | 
| SymantecEmailSecurity.EmailQueue.Domains.ReceiveQueueCountOutbound | Number | Number of outbound messages waiting to be processed. | 
| SymantecEmailSecurity.EmailQueue.Domains.DeliveryQueueCountInbound | Number | Number of inbound messages that have been processed and are waiting to be delivered. | 
| SymantecEmailSecurity.EmailQueue.Domains.DeliveryQueueCountOutbound | Number | Number of outbound messages that have been processed and are waiting to be delivered. | 
| SymantecEmailSecurity.EmailQueue.Domains.LongestTimeInReceiveQueueInbound | Number | Oldest inbound message in queue waiting to be processed. Measured in seconds. | 
| SymantecEmailSecurity.EmailQueue.Domains.LongestTimeInReceiveQueueOutbound | Number | Oldest outbound message in queue waiting to be processed. Measured in seconds. | 
| SymantecEmailSecurity.EmailQueue.Domains.LongestTimeInDeliveryQueueInbound | Number | Oldest inbound message waiting to be delivered after processing. Measured in seconds. | 
| SymantecEmailSecurity.EmailQueue.Domains.LongestTimeInDeliveryQueueOutbound | Number | Oldest outbound message waiting to be delivered after processing. Measured in seconds. | 
| SymantecEmailSecurity.EmailQueue.Domains.MeanTimeInReceiveQueueInbound | Number | Average \(mean\) wait time for inbound messages waiting to be processed. Measured in seconds. | 
| SymantecEmailSecurity.EmailQueue.Domains.MeanTimeInReceiveQueueOutbound | Number | Average \(mean\) wait time for outbound messages waiting to be processed. Measured in seconds. | 
| SymantecEmailSecurity.EmailQueue.Domains.MeanTimeInDeliveryQueueInbound | Number | Average \(mean\) wait time for inbound messages waiting to be delivered after processing. Measured in seconds. | 
| SymantecEmailSecurity.EmailQueue.Domains.MeanTimeInDeliveryQueueOutbound | Number | Average \(mean\) wait time for outbound messages waiting to be delivered after processing. Measured in seconds. | 

### symantec-email-security-quarantine-email-list

***
Retrieves the metadata for quarantined emails belonging to the authenticated user. If the user is an administrator, the API provides options to retrieve the metadata for emails quarantined for another user under his administration.

#### Base Command

`symantec-email-security-quarantine-email-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | A search criterion that can be used to filter emails that match only certain conditions based on email metadata. The search syntax is built by a field name and search value enclosed by parenthesis and the operators: 'OR', 'AND' to combine multiple search criteria's or values, example: (email_subject:test). Acceptable field names are: 'dlp_message_id', 'email_envelope_sender', 'email_envelope_sender.raw', 'email_sender', 'email_envelope_recipient', 'email_envelope_recipient.raw', 'email_subject', 'email_subject.raw'. See the section called “Search String Syntax” on page 16 in: https://techdocs.broadcom.com/content/dam/broadcom/techdocs/us/en/dita/symantec-security-software/email-security/email-security-cloud/content/EmailQuarantineAPIGuide.pdf. | Optional | 
| sort_column | Specifies the column to use for sorting. Defaults to `email_date_received`. | Optional | 
| sort_order | Specifies the order in which to sort. Possible values are: desc, asc. Default is desc. | Optional | 
| after | A time stamp value used to select only SUDULS items that were created after this time. Accepted formats: any substring of yyyy-mm-ddThh:mm:ssZ, epoch 1720617001, relative 1 day 2h 3 minute. | Optional | 
| before | A time stamp value used to select only SUDULS items that were created before this time. Accepted formats: any substring of yyyy-mm-ddThh:mm:ssZ, epoch 1720617001, relative 1 day 2h 3 minute. | Optional | 
| filter_type | A string used to filter emails based on the quarantine type. By default includes the emails quarantined for all types. COMPLIANCE: Includes Content control, DLP and Image control emails. DLP: Includes only DLP emails. Possible values are: SPAM, NEWSLETTER, CI, CO, II, IO, COMPLIANCE, DLP. | Optional | 
| include_deleted | Specifies whether to include items marked as deleted in the search results. Possible values are: true, false. | Optional | 
| user_email | Return only the quarantined emails of the user whose email address is specified. Note: Can only be used by an administrator user. | Optional | 
| admin_domain | Returns the emails quarantined for users in a particular domain. If this parameter is present and has a valid domain name, then items from only that domain are returned. If it has a value of `ALL`, then all domains administered by the user are searched and emails quarantined for users in those domains are returned. Note: Can only be used by an administrator user. | Optional | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| page | The page number to retrieve records from. | Optional | 
| page_size | The maximum number of records to return per page. Default is 50. Max is 10,000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEmailSecurity.QuarantineEmail.id | String | ID of the item. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.email_date_received | Date | Date the email was received. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.quarantine_info.direction | String | Direction of the email. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.quarantine_info.quarantine_type | String | Quarantine type of the email, can be one of: SPAM, NEWSLETTER, CI, CO, II, IO, COMPLIANCE, DLP. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.email_is_viewed | Bool | Whether the email was viewed. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.email_is_released | Bool | Whether the email was released. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.quarantine_reason | String | Reason why the email was quarantined. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.email_sender | String | Sender of the email. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.service_type | String | Service type used for the email. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.master_recipient | String | Recipient of the email. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.user_id | Number | ID of the user. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.email_envelope_sender | String | Address to respond in the case of bounce messages or errors. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.email_subject | String | Subject of the email. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.email_size | Number | Size of the email. | 
| SymantecEmailSecurity.QuarantineEmail.metadata.email_envelope_recipient | String | The RCPT TO address. | 
| SymantecEmailSecurity.QuarantineEmail.actions.view_subject | Bool | Whether the subject can be viewed. | 
| SymantecEmailSecurity.QuarantineEmail.actions.delete_message | Bool | Whether the email can be deleted. | 
| SymantecEmailSecurity.QuarantineEmail.actions.preview_message | Bool | Whether the email can be previewed. | 
| SymantecEmailSecurity.QuarantineEmail.actions.release_message | Bool | Whether the email can be released. | 

### symantec-email-security-quarantine-email-preview

***
Retrieves the contents of the email specified in the request. To preview an email the compliance policy must allow it.

#### Base Command

`symantec-email-security-quarantine-email-preview`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The message ID of the email to preview. Use `symantec-email-security-email-queue-list` to get a list of message IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEmailSecurity.QuarantineEmailPreview.message_id | String | ID of the message. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.authentication-results | String | Authentication status of the email. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.content-type | String | The MIME type of the email content, defining how the content is structured. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.date | Date | The date and time when the email was sent. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.dkim-signature | String | The DKIM signature used to verify the authenticity of the email. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.feedback-id | String | A unique identifier used for tracking feedback and reporting issues related to the email. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.from | String | The sender's email address and name. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.mailfrom | String | The envelope sender email address. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.message-id | String | Unique identifier for the email message. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.mime-version | String | The MIME version used for the email. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.received | String | Information about the servers the email passed through. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.reply-to | String | The email address where replies to the message should be sent. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.subject | String | The subject line of the email. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.to | String | The recipient's email address. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.x-brightmail-tracker | String | Tracking data for Brightmail filtering. | 
| SymantecEmailSecurity.QuarantineEmailPreview.headers.x-originating-ip | String | IP address of the original sender. | 
| SymantecEmailSecurity.QuarantineEmailPreview.attachments.name | String | The name of the file attached to the email. | 
| SymantecEmailSecurity.QuarantineEmailPreview.attachments.type | String | The type of the file attached to the email. | 
| SymantecEmailSecurity.QuarantineEmailPreview.bodypart.type | String | The type of the email's body part. | 
| SymantecEmailSecurity.QuarantineEmailPreview.bodypart.content | String | The content of the email's body part. | 

### symantec-email-security-quarantine-email-release

***
Releases the set of quarantined emails specified in the request.

#### Base Command

`symantec-email-security-quarantine-email-release`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_ids | Comma-separated list of emails message IDs to release. Use `symantec-email-security-quarantine-email-list` to get a list of message IDs. | Required | 
| recipient | An email address to which the mails have to be released instead of the recipient users address. | Optional | 
| headers | Comma-separated list of x-headers that will be added to the message on release. | Optional | 
| encrypt | If true adds an 'x-encrypted-quarantine-release: true' to the released email. Customers have to configure a corresponding DP rule that triggers encryption. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### symantec-email-security-quarantine-email-delete

***
Deletes the set of quarantined emails specified in the request. The items are marked as deleted in the backend data store, but are not physically deleted.

#### Base Command

`symantec-email-security-quarantine-email-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_ids | Comma-separated list of quarantined emails message IDs to delete. Use `symantec-email-security-quarantine-email-list` to get a list of message IDs. | Required | 

#### Context Output

There is no context output for this command.
### symantec-email-security-item-allow-list

***
Retrieve the allow list items.

#### Base Command

`symantec-email-security-item-allow-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | A string that at least some part of the allow list item must contain. | Optional | 
| sort_column | Specifies the column to use for sorting. Possible values are: date, type, description. Default is date. | Optional | 
| sort_order | Specifies the order in which to sort. Possible values are: desc, asc. Default is desc. | Optional | 
| after | A time stamp value used to select only SUDULS items that were created after this time. Accepted formats: any substring of yyyy-mm-ddThh:mm:ssZ, epoch 1720617001, relative 1 day 2h 3 minute. | Optional | 
| before | A time stamp value used to select only SUDULS items that were created before this time. Accepted formats: any substring of yyyy-mm-ddThh:mm:ssZ, epoch 1720617001, relative 1 day 2h 3 minute. | Optional | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| page | The page number to retrieve records from. | Optional | 
| page_size | The maximum number of records to return per page. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEmailSecurity.AllowList.id | String | ID of the item. | 
| SymantecEmailSecurity.AllowList.value | String | An email address or a domain name. | 
| SymantecEmailSecurity.AllowList.description | String | Description of the item. | 
| SymantecEmailSecurity.AllowList.type | String | Email or domain. | 
| SymantecEmailSecurity.AllowList.date_created | Date | Date at which the item was created. | 
| SymantecEmailSecurity.AllowList.date_amended | Date | Date at which the item was amended. | 

### symantec-email-security-item-allow-list-update

***
Allows a SUDULS (allow quarantine users to maintain their own lists of email addresses or domains) user to add or update an item to the allow list.

#### Base Command

`symantec-email-security-item-allow-list-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| suduls_user | Email address of the user for whom the entry should be added in the allow list. | Required | 
| item_id | ID of SUDULS item to be added/updated. Only required when updating an existing item. Use `symantec-email-security-item-allow-list` to get a list of items. | Optional | 
| email_or_domain | Email address or domain to be added in the allow list. | Required | 
| description | Description of the item to be added to the allow list. | Required | 

#### Context Output

There is no context output for this command.
### symantec-email-security-item-allow-list-delete

***
Allows a SUDULS (allow quarantine users to maintain their own lists of email addresses or domains) user to delete an item from the allow list.

#### Base Command

`symantec-email-security-item-allow-list-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | ID of SUDULS item to be deleted. Use `symantec-email-security-item-allow-list` to get a list of items. | Required | 

#### Context Output

There is no context output for this command.
### symantec-email-security-item-block-list

***
Retrieve the block list items.

#### Base Command

`symantec-email-security-item-block-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | A string that at least some part of the block list item must contain. | Optional | 
| sort_column | Specifies the column to use for sorting. Default is date. | Optional | 
| sort_order | Specifies the order in which to sort. Default is desc. | Optional | 
| after | A time stamp value used to select only SUDULS items that were created after this time. Accepted formats: any substring of yyyy-mm-ddThh:mm:ssZ, epoch 1720617001, relative 1 day 2h 3 minute. | Optional | 
| before | A time stamp value used to select only SUDULS items that were created before this time. Accepted formats: any substring of yyyy-mm-ddThh:mm:ssZ, epoch 1720617001, relative 1 day 2h 3 minute. | Optional | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| page | The page number to retrieve records from. | Optional | 
| page_size | The maximum number of records to return per page. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEmailSecurity.BlockList.id | String | ID of the item. | 
| SymantecEmailSecurity.BlockList.value | String | An email address or a domain name. | 
| SymantecEmailSecurity.BlockList.description | String | Description of the item. | 
| SymantecEmailSecurity.BlockList.type | String | Email or domain. | 
| SymantecEmailSecurity.BlockList.date_created | Date | Date at which the item was created. | 
| SymantecEmailSecurity.BlockList.date_amended | Date | Date at which the item was amended. | 

### symantec-email-security-item-block-list-update

***
Allows a SUDULS (allow quarantine users to maintain their own lists of email addresses or domains) user to add or update an item to the block list.

#### Base Command

`symantec-email-security-item-block-list-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| suduls_user | Email address of the user for whom the entry should be added in the block list. | Required | 
| item_id | ID of SUDULS item to be added/updated. Only required when updating an existing item. Use `symantec-email-security-item-block-list` to get a list of items. | Optional | 
| email_or_domain | Email address or domain to be added in the block list. | Required | 
| description | Description of the item to be added to the block list. | Required | 

#### Context Output

There is no context output for this command.
### symantec-email-security-item-block-list-delete

***
Allows a SUDULS (allow quarantine users to maintain their own lists of email addresses or domains) user to delete an item from the block list.

#### Base Command

`symantec-email-security-item-block-list-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | ID of SUDULS item to be deleted. Use `symantec-email-security-item-block-list` to get a list of items. | Required | 

#### Context Output

There is no context output for this command.
