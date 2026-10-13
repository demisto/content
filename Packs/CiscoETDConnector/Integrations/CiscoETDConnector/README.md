# Cisco ETD Connector

The Cisco ETD Connector ingests Cisco Secure Email Threat Defense (ETD) message, audit, and blocked connection logs into Cortex XSIAM for security analytics, monitoring, and threat investigation.

This integration uses the Cisco Secure Email Threat Defense [Log Export API](https://developer.cisco.com/docs/message-search-api/log-export-api/).

## How Collection Works

Cisco ETD does not return events directly. Each API request returns pre-signed download links to hourly export files, which the collector then downloads and parses. This has a few consequences worth knowing:

- Events become available on an hourly basis, and export files for a given hour continue to be generated for up to 20 minutes after that hour ends. The collector therefore re-reads the two most recent hours and skips export files it has already downloaded.
- The hour currently in progress cannot be retrieved. Expect events to appear in Cortex XSIAM with a delay of up to roughly 90 minutes after they occur in Cisco ETD.
- Log retention in Cisco ETD is 30 days. Events older than that cannot be recovered.
- On the first fetch, only the most recent completed hour is collected. Historical data is not backfilled; use `cisco-etd-get-events` to retrieve a specific past time range.

## Prerequisites

Log export must be enabled in the Cisco ETD UI before any events are returned. Navigate to **Administration > Business > Export Log Preferences** and select the log types you want to collect. Export begins 15 minutes after enabling connection and audit logs, and 20 minutes after enabling message event logs.

Blocked connection logs require Inline Mode and an ETD Advantage license.

## Configure Cisco Email Threat Defense Connector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| ETD API Base URL | Regional base URL of the Cisco ETD API, for example `https://api.us.etd.cisco.com`. | Yes |
| ETD API Key | API key used to authenticate requests to Cisco ETD. | Yes |
| Client ID | Cisco ETD OAuth Client ID. | Yes |
| Client Secret | Cisco ETD OAuth Client Secret. | Yes |
| Trust any certificate (not secure) | Skips verification of the server TLS certificate. | No |
| Use system proxy settings | Routes requests through the system proxy. | No |
| Fetch events | Enables continuous event collection into Cortex XSIAM. | No |
| Event Types | Cisco ETD log types to collect (`message`, `audit`, `connection`). If none are selected, all types are collected. | No |
| Max fetch | Maximum number of events to collect per fetch cycle. Any remainder is collected on the following cycle. Default is `5000`. | No |
| Events Fetch Interval | Interval, in minutes, between fetch cycles. Default is `60`, matching the hourly publication of ETD export files. | No |

### Regional Base URLs

| Region | Base URL |
| --- | --- |
| Americas | `https://api.us.etd.cisco.com` |
| Europe | `https://api.de.etd.cisco.com` |
| Australia | `https://api.au.etd.cisco.com` |
| India | `https://api.in.etd.cisco.com` |
| UAE | `https://api.ae.etd.cisco.com` |

## Commands

### cisco-etd-get-events

Retrieves Cisco ETD logs for an explicit time range.

> **Warning:** Use this command for development and debugging only, as it may produce duplicate events, exceed API rate limits, or disrupt the fetch mechanism.

#### Base Command

`cisco-etd-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | Start of the time range. Accepts a date, a timestamp, or a relative expression such as `3 hours ago`. Rounded down to the start of the hour. Default is `1 hour ago`. | No |
| end_time | End of the time range. Accepts a date, a timestamp, or a relative expression such as `now`. Rounded down to the start of the hour. The hour currently in progress cannot be retrieved. Default is `now`. | No |
| log_type | One or more log types to retrieve (`message`, `audit`, `connection`). If not provided, all types are retrieved. | No |
| limit | Maximum number of events to return. Default is `100`. | No |
| should_push_events | If `true`, sends the retrieved events to Cortex XSIAM. Default is `false`. | No |

#### Context Output

There is no context output for this command. Retrieved events are displayed in the war room as a summary table, and are only ingested when `should_push_events` is set to `true`.

## Troubleshooting

| Symptom | Cause and resolution |
| --- | --- |
| Test succeeds but no events are collected | Log export is likely not enabled in the ETD UI. Enable the relevant log types under **Administration > Business > Export Log Preferences** and wait 15 to 20 minutes for the first export files to be generated. |
| `Cisco ETD denied the request. Verify the API Key...` | The `x-api-key` header was rejected. Confirm the API Key is correct and belongs to the same tenant as the Client ID and Client Secret. |
| `The Cisco ETD access token expired and could not be refreshed...` | The Client ID or Client Secret is invalid or was rotated. Generate new API credentials in the ETD UI and update the instance. |
| `The Cisco ETD API rate limit or daily quota was exceeded...` | The tenant exceeded its API quota. Increase the Events Fetch Interval, avoid running `cisco-etd-get-events` repeatedly, and contact Cisco support to request a quota increase. |
| `Cisco ETD rejected the request. Verify the configured time range...` | The requested range extended into the current hour, exceeded 3 hours, or was older than the 30 day retention period. |
| `The Cisco ETD API is temporarily unavailable...` | A transient service error. The affected hours are retried automatically on the next fetch cycle. |
| Warning about truncated download links in the logs | Cisco ETD returns at most 200 download links per request and discards the rest, meaning some events for that hour cannot be collected. Contact Cisco support if the tenant consistently exceeds this volume. |
| Events appear with a delay | Expected. Export files are published hourly and continue to be generated for up to 20 minutes after an hour ends. |
| Events are missing after an outage | Use `cisco-etd-get-events` with `should_push_events=true` to recover a specific time range, as long as it falls within the 30 day retention period. |
