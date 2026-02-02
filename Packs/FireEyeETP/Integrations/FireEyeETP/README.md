# Trellix Email Security - Cloud

## Overview

Use the Trellix Email Security - Cloud integration to import messages as incidents, search for messages with specific attributes, and retrieve alert data.

## Use Cases

* Search for messages using specific message attributes as indicators.
* Import messages as Cortex incidents/issues, using the message status as indicator.

## Authentication and Authorization

### Configuring API Keys

If the IAM domain you use to access the Trellix UI ends in **fireeye.com**, follow these steps to configure API keys:

1. Log in to the **Email Security — Cloud Web Portal** or **IAM console**.
2. Click **My Settings** in the top navigation bar.
3. Click the **API Keys** tab in the IAM console.
4. Click **Create API Key**.
5. On the **Manage API Key** page, specify the following:

* **API key name**
* **Expiration time** for the API key.
The expiration time should be set as `"100d"` for 100 days or `"1y"` for 1 year, for example.
* **Products**  
Select both **Email Threat Prevention** and **Identity Access Management**.

6. Select all required entitlements. For any API access, the following entitlements are mandatory:

    * `iam.users.browse`
    * `iam.orgs.self.read`

   #### Alerts APIs

    For accessing alerts APIs, the following additional entitlements are required:

    * `etp.alerts.read`

   #### Trace APIs

    For accessing trace APIs, the following additional entitlements are required:

    * `etp.email_trace.read`

   #### Quarantine APIs

    For accessing quarantine APIs, the following additional entitlements are required:

    * `etp.quarantine.update`
    * `etp.quar`

## Authentication Prerequisites

To ensure a successful connection, select the authentication method that matches the Server URL (Instance URL) you are configuring.

### Dual Authentication Methods

We support two different authentication methods depending on the endpoint domain:

| Domain Used in Server URL | Authentication Method | Required Parameters |
| :--- | :--- | :--- |
| **Ends in `trellix.com`** | **OAuth 2.0** | **Client ID**, **Client Secret**, and **OAuth Scopes** |
| **Ends in `fireeye.com`** | **API Key** | **API Key** (only) |

### Authentication Setup (Choose One)

**You must configure only one of the two authentication approaches below** based on your Server URL domain.

* **1. API Key Method (For `fireeye.com` URLs):**
  * **Configure an API key** on the ETP Web portal. Select the product as both *Email Threat Prevention* and *Identity Access Management*. Select all entitlements.

* **2. OAuth 2.0 Method (For `trellix.com` URLs):**
  * When creating the Client ID and Client Secret, ensure the corresponding user/role has **explicit permission to access the API**.
  * **Note:** If API access permissions are not properly set for the user/role, the authentication attempt will fail with a **`400 Client Error: Bad Request`** even if the Client ID and Secret are correct.

* Contact Trellix Email Security - Cloud Technical Support to let them know the IP address of your Cortex Server and the URL you are accessing, e.g. `https://etp.us.fireeye.com`. Trellix will add these details to their Firewall rules so that the bidirectional traffic can be allowed between Cortex and Trellix Email Security - Cloud.

## Configure Trellix Email Security - Cloud in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Valid URLs \(US, EMEA, USGOV\): https://us.etp.trellix.com / https://etp.us.fireeye.com, https://eu.etp.trellix.com / https://etp.eu.fireeye.com, https://etp.us.fireeyegov.com | True |
| Client ID (OAuth) | Use the Client ID and Client Secret for the Trellix base URL. |  |
| Client Secret (OAuth) |  |  |
| OAuth Scopes (OAuth) | Space-separated list of OAuth scopes. Note: Only include scopes that your application's Client ID has already been authorized to use. | False |
| API Key | Use the Api key for the FireEye base URL. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| First fetch timestamp. |  | False |
| Max incidents per fetch | Input a value between 1 and 59. Values above 59 will be internally capped to avoid exceeding API rate limits. | False |
| Incident type |  | False |
| Alerts statuses to import | All alerts with a status specified here will be imported as incidents. Valid values are: accepted, deleted, delivered, delivered (retroactive), dropped, dropped oob, dropped (oob retroactive), permanent failure, processing quarantined, rejected, temporary failure | False |

## Fetched Incidents Data

To use Fetch incidents:

1. Configure a new instance.
2. Navigate to *instance settings*, and specify the *message status* (using the valid values).
3. Select *Fetch incidents* option.

The integration will fetch alerts as incidents. It is possible to filter alerts using the specified message status.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fireeye-etp-search-messages

Search for messages using specific message attributes as indicators.

***
Search for messages that include specified message attributes that are accessible in the ETP portal.

#### Base Command

`fireeye-etp-search-messages`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_email | List of 'From' email-addresses, max limit of entries is 10. | Optional |
| from_email_not_in | List of 'From' email-addresses not to be included, max limit of entries is 10. | Optional |
| recipients | List of 'To'/'Cc' email-addresses, max limit of entries is 10. | Optional |
| recipients_not_in | list of 'To'/'Cc' email-addresses not to be included, max limit of entries is 10. | Optional |
| subject | List of strings, max limit of entries is 10. | Optional |
| from_accepted_date_time |  The time stamp of the email-accepted date to specify the beginning of the date range to search, e.g. 2017-10-24T10:48:51.000Z . Specify 'to_accepted_date_time'  as well to set the complete date range for the search. | Optional |
| to_accepted_date_time |  The time stamp of the email-accepted date to specify the end of the date range to search, e.g. 2017-10-24T10:48:51.000Z . Specify 'from_accepted_date_time'  as well to set the complete date range for the search. | Optional |
| rejection_reason | List of ETP rejection reason codes ( "ETP102", "ETP103", "ETP104", "ETP200", "ETP201", "ETP203", "ETP204", "ETP205", "ETP300", "ETP301", "ETP302", "ETP401", "ETP402", "ETP403", "ETP404", "ETP405"). | Optional |
| sender_ip | List of sender IP addresses, max limit of entries is 10. | Optional |
| status | List of email status values( "accepted", "deleted", "delivered", "delivered (retroactive)", "dropped", "dropped oob", "dropped (oob retroactive)", "permanent failure", "processing", "quarantined", "rejected", "temporary failure"). | Optional |
| status_not_in | List of email status values not to include( "accepted", "deleted", "delivered", "delivered (retroactive)", "dropped", "dropped oob", "dropped (oob retroactive)", "permanent failure", "processing", "quarantined", "rejected", "temporary failure"). | Optional |
| last_modified_date_time | Date corresponding to last modified date, along with one of the following operators: "&gt;", "&lt;", "&gt;=", "&lt;=".  E.g. use value "&lt;2017-10-24T18:00:00.000Z" to search for messages that were last modified after the specified time stamp. | Optional |
| domain | List of domain names. | Optional |
| has_attachments | Boolean value to indicate if the message has attachments. Possible values are: true, false. | Optional |
| max_message_size | The default value is 20kb and maximum value is 100kb. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeETP.Message.acceptedDateTime | unknown | Message accepted date. |
| FireEyeETP.Message.countryCode | unknown | Sender country code. |
| FireEyeETP.Message.domain | unknown | Domain. |
| FireEyeETP.Message.emailSize | unknown | Email size in kb. |
| FireEyeETP.Message.lastModifiedDateTime | unknown | Message last modified date. |
| FireEyeETP.Message.recipientHeader | unknown | List of message recipients header \(includes the display name of the user\). |
| FireEyeETP.Message.recipients | unknown | List of message recipients. |
| FireEyeETP.Message.senderHeader | unknown | Message sender header \(includes the display name of the user\). |
| FireEyeETP.Message.sender | unknown | Message sender address. |
| FireEyeETP.Message.senderSMTP | unknown | Message sender SMTP. |
| FireEyeETP.Message.senderIP | unknown | Message sender IP. |
| FireEyeETP.Message.status | unknown | Message status. |
| FireEyeETP.Message.subject | unknown | Message subject. |
| FireEyeETP.Message.verdicts.AS | unknown | pass/fail verdict for AS. |
| FireEyeETP.Message.verdicts.AV | unknown | pass/fail verdict for AV. |
| FireEyeETP.Message.verdicts.AT | unknown | pass/fail verdict for AT. |
| FireEyeETP.Message.verdicts.PV | unknown | pass/fail verdict for PV. |
| FireEyeETP.Message.id | unknown | Message ID. |

##### Command example 1

`!fireeye-etp-search-messages to_accepted_date_time=2017-10-24T10:00:00.000Z from_accepted_date_time=2017-10-24T10:30:00.000Z`

##### Command example 2

`!fireeye-etp-search-messages from_email=diana@corp.com,charles@corp.com`

##### Raw Output

```json
{  
   "data": [  
      {  
         "attributes": {  
            "acceptedDateTime": "2018-06-09T10:49:32.000Z",
            "countryCode": "US",
            "domain": "test.com",
            "downStreamMsgID": "250 2.0.0 OK 100041373 d14-v6si970000qtb.70 - gsmtp",
            "emailSize": 9.89,
            "lastModifiedDateTime": "2018-06-09T10:49:33.329Z",
            "recipientHeader": [  
               "Security Operations Center <SOC@corp.com>"
            ],
            "recipientSMTP": [  
               "jason@demisto.com"
            ],
            "senderHeader": "\"soc@demisto.com\" <bot@demisto.com >",
            "senderSMTP": "prvs=691a94fds62a=demisto@demisto.com ",
            "senderIP": "***.***.***.***",
            "status": "delivered",
            "subject": "Attack TCP: SYN Host Sweep (Medium)",
            "verdicts": {  
               "AS": "",
               "AV": "",
               "AT": "pass",
               "PV": ""
            }
         },
         "included": [  
            {  
               "type": "domain",
               "id": 29074,
               "attributes": {  
                  "name": "test.com "
               }
            }
         ],
         "id": "C88B18749AAAAB1B55fc0fa78",
         "type": "trace"
      }
   ],
   "meta": {  
      "total": 85347,
      "copyright": "Copyright 2018 Fireeye Inc",
      "fromLastModifiedOn": {  
         "start": "2018-06-09T10:49:33.329Z",
         "end": "2018-06-09T10:50:59.034Z"
      }
   }
}
```

### fireeye-etp-get-message

***
Get the data of a specific message.

#### Base Command

`fireeye-etp-get-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The message ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeETP.Message.acceptedDateTime | unknown | Message accepted date. |
| FireEyeETP.Message.countryCode | unknown | Sender country code. |
| FireEyeETP.Message.domain | unknown | Domain. |
| FireEyeETP.Message.emailSize | unknown | Email size in kb. |
| FireEyeETP.Message.lastModifiedDateTime | unknown | Message last modified date. |
| FireEyeETP.Message.recipientHeader | unknown | List of message recipients header \(includes the display name of the user\). |
| FireEyeETP.Message.recipients | unknown | List of message recipients. |
| FireEyeETP.Message.senderHeader | unknown | Message sender header \(includes the display name of the user\). |
| FireEyeETP.Message.sender | unknown | Message sender address. |
| FireEyeETP.Message.senderSMTP | unknown | Message sender SMTP. |
| FireEyeETP.Message.senderIP | unknown | Message sender IP. |
| FireEyeETP.Message.status | unknown | Message status. |
| FireEyeETP.Message.subject | unknown | Message subject. |
| FireEyeETP.Message.verdicts.AS | unknown | pass/fail verdict for AS. |
| FireEyeETP.Message.verdicts.AV | unknown | pass/fail verdict for AV. |
| FireEyeETP.Message.verdicts.AT | unknown | pass/fail verdict for AT. |
| FireEyeETP.Message.verdicts.PV | unknown | pass/fail verdict for PV. |
| FireEyeETP.Message.id | unknown | Message ID. |

##### Command example

`!fireeye-etp-get-message message_id= C88B18749AAAAB1B55fc0fa78`

##### Raw Output

There is no raw output for this command.

### fireeye-etp-list-alerts

***
Get summary format information about the alerts.

#### Base Command

`fireeye-etp-list-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID. | Optional |
| date_from | Supports ISO format (e.g., 2025-09-02T06:45:01Z) or natural language ("7 days ago", "now"). | Optional |
| date_to | Supports ISO format (e.g., 2025-09-02T06:45:01Z) or natural language ("7 days ago", "now"). | Optional |
| domain | List of domain names. | Optional |
| domain_group | List of domain groups names. | Optional |
| email_header_subject | List of message subject headers. | Optional |
| is_read | is_read flag. | Optional |
| is_retro | is_retro flag. | Optional |
| malwarename | List of malware names. | Optional |
| malwarestype | List of malware types. | Optional |
| md5 | List of md5. | Optional |
| mta_msg_id | List of mta_msg_id. | Optional |
| traffic_type | Traffic type defaults to inbound. To handle outbound traffic, set the traffic_type parameter to outbound. Possible values are: inbound, outbound. | Optional |
| verdict | List of verdicts. | Optional |
| limit | Number of alerts to include in response. Valid range: 1-200. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeETP.Alerts.domain | unknown | Domain. |
| FireEyeETP.Alerts.report_id | unknown | Report_id. |
| FireEyeETP.Alerts.id | unknown | The alert unique ID. |
| FireEyeETP.Alerts.alert_date | unknown | The alert date. |

### fireeye-etp-download-alert-case-files

***
Downloads all case files for the specified alert ID as a ZIP file. You can obtain the alert ID from the Alert Summary response, for example: "id": "AV7zzRy7kvIwrKcfu0I".
The downloaded zip is password protected, and the password is "infected".

#### Base Command

`fireeye-etp-download-alert-case-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID. | Required |

#### Context Output

There is no context output for this command.

### fireeye-etp-list-yara-rulesets

***
Fetch the list of YARA rulesets and return a list with all the rules.

#### Base Command

`fireeye-etp-list-yara-rulesets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_uuid | Universally unique identifier (UUID) of the policy. (Can be found in the URL of the ETP Policies). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeETP.Policy | unknown | The policy id. |

### fireeye-etp-download-yara-file

***
Downloads a YARA file.

#### Base Command

`fireeye-etp-download-yara-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_uuid | Universally unique identifier (UUID) of the policy. (Can be found in the URL of the ETP Policies). | Required |
| ruleset_uuid | Universally unique identifier (UUID) of the ruleset. | Required |

#### Context Output

There is no context output for this command.

### fireeye-etp-upload-yara-file

***
Update or replace the YARA rule file in the existing ruleset.

#### Base Command

`fireeye-etp-upload-yara-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_uuid | Universally unique identifier (UUID) of the policy. (Can be found in the URL of the ETP Policies). | Required |
| ruleset_uuid | Universally unique identifier (UUID) of the ruleset. | Required |
| entryID | Entry ID of yara file to upload. | Required |

#### Context Output

There is no context output for this command.

### fireeye-etp-get-events-data

***
Returns all events of the alert by the alert ID.

#### Base Command

`fireeye-etp-get-events-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | Message ID of alert. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeETP.Events | unknown | The events of the alert. |
| FireEyeETP.Events.Delivered_msg | unknown | Display if event is delivered successfully or not. |
| FireEyeETP.Events.Delivered_status | unknown | The status of the message. |
| FireEyeETP.Events.InternetMessageId | unknown | The internet message ID of the alert. |
| FireEyeETP.Events.Logs | unknown | The logs of the alert. |

### fireeye-etp-quarantine-release

***
Releases the email file present in the quarantine for the given email. Cloud message ID.

#### Base Command

`fireeye-etp-quarantine-release`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The message ID. | Optional |

#### Context Output

There is no context output for this command.
