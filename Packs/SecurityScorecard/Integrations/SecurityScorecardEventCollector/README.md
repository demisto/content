## Overview

SecurityScorecard provides security ratings and risk assessments for organizations by continuously monitoring their external attack surface. It evaluates domains across multiple security factors including network security, DNS health, patching cadence, endpoint security, and more.

This integration collects history events from SecurityScorecard for security monitoring and compliance purposes in your Cortex XSIAM environment. Each event is enriched with detailed information from the event's detail URL.

## Authentication

This integration uses API token-based authentication.

### Creating an API Token

1. In SecurityScorecard, click your profile avatar and select **My Settings**.
2. Select the **API** tab in the left settings pane and then click **Generate New API Token**.
3. Click **Confirm** to generate the token.
4. Copy the token and store it securely.

> **Important**: API Keys do not expire on their own. Creating a new token invalidates any previously created token. You will need to replace the older API key with the new one for your integrations to continue working with SecurityScorecard.

## Before You Start

Before configuring the integration, ensure you have:

1. A valid SecurityScorecard account with API access.
2. An API token generated from your SecurityScorecard account settings.
3. The domain identifier (scorecard identifier) you want to monitor (e.g., `google.com`).

## Configure SecurityScorecard Event Collector in Cortex

1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for **SecurityScorecard Event Collector**.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The SecurityScorecard API base URL.<br/>Default: `https://api.securityscorecard.io` | True |
| API Token | The API token for authenticating with SecurityScorecard.<br/>Generated from **My Settings** > **API** tab. | True |
| Scorecard Identifier | The domain identifier for the scorecard to monitor.<br/>Example: `google.com` | True |
| Fetch events | Whether to automatically fetch events. | False |
| Maximum number of events per fetch | Maximum number of events to fetch per cycle.<br/>Default: `1000` | False |
| First fetch time | How far back to fetch events on the first run.<br/>Example: `3 days`, `7 days`, `1 day`<br/>Default: `3 days` | False |
| Trust any certificate (not secure) | When selected, the integration will not verify SSL certificates. | False |
| Use system proxy settings | When selected, the integration will use the system proxy settings. | False |

4. Click **Test** to validate the connection.
5. Click **Save & exit**.

## Rate Limits

The SecurityScorecard API enforces rate limits to ensure system stability and prevent abuse:

- Each client can make up to **5,000 requests per hour** over a rolling 60-minute window.
- If the rate limit is exceeded, the API returns a **429 Too Many Requests** response with a `Retry-After` header specifying the number of seconds to wait.

### How the Integration Handles Rate Limits

The integration handles rate limits gracefully in two scenarios:

1. **Rate limit on history events API**: If the rate limit is hit when fetching the list of events, the integration skips the current fetch cycle and waits for the next one.

2. **Rate limit on detail URL enrichment**: Each event includes a `detail_url` that provides additional information. If the rate limit is hit while fetching these details, the integration:
   - Sends all events that were successfully enriched to XSIAM.
   - Updates the last run checkpoint based on the last enriched event.
   - Defers remaining events to the next fetch cycle.

## Event Structure

Each collected event contains the following fields:

| **Field** | **Description** |
| --- | --- |
| `id` | Unique identifier of the event. |
| `date` | Timestamp of the event (ISO 8601 format). |
| `event_type` | Type of the event (e.g., `issues`). |
| `group_status` | Status of the issue group (`active` or `resolved`). |
| `issue_count` | Number of issues in the event. |
| `total_score_impact` | Total score impact of the event. |
| `issue_type` | The type of issue (e.g., `outdated_browser`, `unsafe_sri_v2`). |
| `severity` | Severity level (`low`, `medium`, `high`, `critical`). |
| `factor` | The security factor (e.g., `endpoint_security`, `application_security`). |
| `detail_url` | URL for detailed event information. |
| `detail_url_response` | Enriched response from the detail URL API call. |

### XSIAM Mapping

- **`_time`** field is mapped from the event's `date` field.
- **Vendor**: `SecurityScorecard`
- **Product**: `SecurityScorecard`

## Deduplication

The integration uses a high-water mark deduplication strategy:

- After each fetch cycle, the integration saves the most recent event date and the IDs of all events sharing that date.
- On the next fetch cycle, events with those IDs are filtered out to prevent duplicates.
- This ensures no events are missed even when multiple events share the same timestamp.

## Commands

You can execute these commands from the Cortex CLI, as part of an automation, or in a playbook.

### securityscorecard-get-events

***

Gets history events from SecurityScorecard. This command is used for developing/debugging and should be used with caution, as it can create duplicate events and exceed API rate limits.

#### Base Command

`securityscorecard-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date_from | The start time to fetch events from. Supports relative time (e.g., "3 days ago", "1 week") or specific absolute dates (ISO 8601 format). | Optional |
| date_to | The end time to fetch events until. Supports relative time (e.g., "now", "1 hour ago") or specific absolute dates (ISO 8601 format). | Optional |
| limit | Maximum number of events to retrieve. Default is 1000. | Optional |
| should_push_events | Set to true to push events to XSIAM. Use with caution to avoid duplicates. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Event.id | Number | Unique identifier of the event. |
| SecurityScorecard.Event.date | Date | Timestamp of the event. |
| SecurityScorecard.Event.event_type | String | Type of the event. |
| SecurityScorecard.Event.factor | String | The security factor associated with the event. |
| SecurityScorecard.Event.severity | String | Severity level of the event. |
| SecurityScorecard.Event.issue_type | String | The type of issue. |
| SecurityScorecard.Event.group_status | String | Status of the issue group (active/resolved). |
| SecurityScorecard.Event.issue_count | Number | Number of issues in the event. |
| SecurityScorecard.Event.total_score_impact | Number | Total score impact of the event. |
| SecurityScorecard.Event.detail_url | String | URL for detailed event information. |
| SecurityScorecard.Event.detail_url_response | Unknown | Response from the detail URL API call. |

#### Command Example

```
!securityscorecard-get-events date_from="3 days ago" limit=10
```

#### Human Readable Output

>### SecurityScorecard Event Collector Events
>|id|date|event_type|factor|severity|issue_type|group_status|
>|---|---|---|---|---|---|---|
>| 23751008 | 2026-03-18T15:06:17.467Z | issues | endpoint_security | high | outdated_browser | resolved |
>| 37991923 | 2026-03-18T15:06:17.467Z | issues | application_security | low | unsafe_sri_v2 | active |
