Use this integration to fetch email security incidents from Trellix Email Security - Cloud as XSIAM events.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Trellix Email Security - Cloud Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://etp.us.fireeye.com) |  | True |
| API Secret Key | The API Key allows you to integrate with the Trellix Email Security - Cloud. | False |
| Maximum number of Alerts to fetch. | The maximum number of Alert events to fetch from Trellix Email Security - Cloud. |  |
| Maximum number of Email Trace to fetch. | The maximum number of Email Trace events to fetch from Trellix Email Security - Cloud. |  |
| Maximum number of Activity Log fetch. | The maximum number of Activity Log events to fetch from Trellix Email Security - Cloud. |  |
| Trust any certificate (not secure) |  |  |
| Use system proxy settings |  |  |
| Fetch outbound traffic | Outbound traffic will be fetched in addition to inbound traffic. |  |
| Hide sensitive details from email | Hide subject and attachments details from emails. |  |

## Access control

All the API requests follow the domain and domain group restrictions of the user. For example, if a user has access to only a few domains in their organization, the response to the APIs will be based on only those domains and domain groups.

## REST API Limitation

Email Security — Cloud REST APIs have a rate limit of 60 requests per minute per API route (/trace, /alert, and /quarantine) for every customer.

This means, in 1 minute, a customer can make:

- 60 requests to Trace APIs (parallel or sequential)  
- 60 requests to Alert APIs (parallel or sequential)  
- 60 requests to Quarantine APIs (parallel or sequential)

Within the minute, the 61st request to any of these APIs would throw a rate limit exceeded error.

The rate limit applies to the customer as a whole. This means that if the customer has multiple admin users who have generated API Keys, the rate limit is applicable at the customer level and not per API key.

## Event Direction & “Shared Content” Across Event Types

### What you may see

In XSIAM you may notice that the *same email content* (e.g., subject/message-ID) appears as multiple events, sometimes with different directions (inbound vs outbound) or even in different event types (e.g., both **Email Trace** and **Alert**). This is expected:

- **Inbound vs Outbound of the same conversation**  
  A user receives an email (inbound) and later forwards/replies externally (outbound). Trellix generates two **separate** events—one per transaction—so both appear in XSIAM.
- **Distribution lists / group expansion**  
  An inbound message to a list can fan-out and create **outbound** traffic to external members, yielding additional outbound events.
- **Internal mail**  
  Some environments also produce “internal/domain-internal” transactions scanned by the gateway. (See note below about the `direction_source` field.)

### How this collector annotates direction

To make the direction explicit in XSIAM, the collector adds a synthetic field:

| Field | Applies to | Values | Notes |
| --- | --- | --- | --- |
| `direction_source` | **Alerts** and **Email Trace** events | `inbound` or `outbound` | Derived from the API route being fetched. |
| *(not set)* | **Activity Log** events | — | Activity logs are user activity, not message transit, so no direction is attached. |

> **Important:** `direction_source` reflects the *collector source* (inbound vs outbound feeds). If your tenant emits “internal” email_trace transactions, that native notion of “internal” is not surfaced via `direction_source` and should be inferred from the raw payload fields (e.g., sender/recipient domains) if required.

### “Shared content” across event types

A single email can legitimately produce:

- An **Email Trace** record (transport/flow metadata), and
- An **Alert** record (security finding on that message).

These are **different event types** describing different aspects of the same email. The collector **does not deduplicate across event types**; it only deduplicates within each type per fetch window. Plan downstream correlation accordingly (e.g., join by message identifiers, subject, envelope addresses, and timestamp buckets, plus `direction_source`).

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fireeye-etp-get-events

***
Gets events from Trellix Email Security - Cloud.

#### Base Command

`fireeye-etp-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of events to return. Default is 10. | Optional |
| since_time | The start time by which to filter events. Date format will be the same as in the first_fetch parameter. Default is 3 days. | Optional |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required |

#### Output Notes

- **Additional Fields Added by Collector**
  - `direction_source` (for **Alerts** and **Email Trace** only): `"inbound"` or `"outbound"`.
  - Not present for **Activity Log** events.

- **Correlation Guidance**
  - Expect multiple events representing the same email content across directions and/or event types. Correlate using message identifiers (when present), subject, envelope sender/recipient, time window, and `direction_source`.
