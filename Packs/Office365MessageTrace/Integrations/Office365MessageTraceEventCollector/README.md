Office 365 Message Trace integration allows you to retrieve email message tracking information from the Office 365 reporting web service. You can search for message traces by date range, sender, recipient, message ID, and status to troubleshoot email delivery issues.
This integration was integrated and tested with version xx of Office 365 Message Trace Event Collector.

## Configure Office 365 Message Trace Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| URL | The URL for the reporting web service. | False |
| Tenant ID | Azure AD tenant ID | True |
| Client ID | Azure AD application client ID | True |
| Client Secret | Azure AD application client secret | True |
| Certificate Thumbprint | X.509 certificate thumbprint for certificate-based authentication \(optional\) | False |
| Private Key | Private key for certificate-based authentication \(optional\) | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| First fetch time |  | True |
| Processing Delay (minutes) | Office 365 can take up to 24 hours to process message trace events. Specify how many minutes to delay event processing \(1440 minutes = 24 hours\). Higher values ensure events are fully processed but increase latency. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### office365-mt-get-events

***
Retrieve message trace data from Office 365 for troubleshooting email delivery issues.

#### Base Command

`office365-mt-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start date for the search in ISO format (YYYY-MM-DDTHH:MM:SSZ). If not provided, defaults to 48 hours ago. | Optional |
| end_date | End date for the search in ISO format (YYYY-MM-DDTHH:MM:SSZ). If not provided, defaults to current time. | Optional |
| date_range | Date range for the search (e.g., "24 hours", "7 days"). Only used if start_date and end_date are not provided. | Optional |
| sender_address | Email address of the sender to filter results. | Optional |
| recipient_address | Email address of the recipient to filter results. | Optional |
| message_trace_id | Specific message trace ID to search for. | Optional |
| status | Message status to filter results (e.g., Delivered, Failed, Pending). | Optional |
| top | Number of results to return, will impact paging. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Office365.MessageTrace.MessageTraceId | String | Unique identifier for the message trace. |
| Office365.MessageTrace.Organization | String | The organization domain that processed the message. |
| Office365.MessageTrace.MessageId | String | The Internet MessageID header of the message. |
| Office365.MessageTrace.Received | Date | Date and time when the message was received. |
| Office365.MessageTrace.SenderAddress | String | SMTP email address of the sender. |
| Office365.MessageTrace.RecipientAddress | String | SMTP email address of the recipient. |
| Office365.MessageTrace.Subject | String | Subject line of the message. |
| Office365.MessageTrace.Status | String | Status of the message \(e.g., Delivered, Failed\). |
| Office365.MessageTrace.FromIP | String | IP address that transmitted the message to Office 365. |
| Office365.MessageTrace.ToIP | String | IP address that Office 365 sent the message to. |
| Office365.MessageTrace.Size | Number | Size of the message in bytes. |

#### Command Example

```!office365-mt-get-events date_range="1 hour ago" top=1```

```json
{
    "Office365": {
        "MessageTrace": {
            "FromIP": "1.1.1.1",
            "MessageId": "<33413B52-EF7D-4738-9204-789E079AAB45@example.com>",
            "MessageTraceId": "a3f2b8c1-4d7e-4a92-9b3c-8e6f1d2a5c9b",
            "Organization": "contoso.onmicrosoft.com",
            "Received": "2025-11-20T00:18:45.943144",
            "RecipientAddress": "ABC124@contoso.com",
            "SenderAddress": "user1@example.com",
            "Size": 34102,
            "Status": "GettingStatus",
            "Subject": "Re: Example Email Subject",
            "ToIP": null
        }
    }
}
```
