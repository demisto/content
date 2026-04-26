# Menlo Security

The cloud-based Menlo Security Isolation Platform (MSIP) eliminates the possibility of malware reaching user devices via compromised or malicious Web sites, Email or documents.

This integration collects logs from the MSIP Logging API and sends them to Cortex.

## Configure Menlo Security on Cortex

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**.
2. Search for **Menlo Security**.
3. Click **Add instance** to create and configure a new integration instance.

| Parameter | Description | Required |
| --- | --- | --- |
| Server URL | The Menlo Security logging API base URL. Default: `https://logs.menlosecurity.com` | True |
| Auth Token | The API authentication token with Log Export API permission. | True |
| Log types | The log types to collect. Select one or more from: web, safemail, audit, smtp, attachment, dlp, isoc. | True |
| Fetch events | Enable event fetching. | False |
| Maximum number of events per fetch | Maximum events to collect per log type per fetch cycle. Default: 5000. | False |
| Trust any certificate (not secure) | Disable SSL certificate verification. | False |
| Use system proxy settings | Use the system proxy for API requests. | False |

1. Click **Test** to validate the connection.

## Commands

### menlo-security-get-events

Manually fetch events from the Menlo Security Isolation Platform.

#### Base Command

`menlo-security-get-events`

#### Input

| Argument Name | Description | Required |
| --- | --- | --- |
| start_time | Start time for the event query (e.g., `1 hour`, `2024-01-01T00:00:00Z`). Default: `1 hour`. | Optional |
| end_time | End time for the event query (e.g., `now`, `2024-01-02T00:00:00Z`). Default: `now`. | Optional |
| log_types | Comma-separated list of log types to fetch (e.g., `web,audit`). Defaults to all configured log types. | Optional |
| limit | Maximum number of events to return per log type. Default: `5000`. | Optional |
| should_push_events | Set to `True` to push the fetched events to XSIAM. Set to `False` to only display them. | Required |

#### Context Output

There is no context output for this command.

## Notes

- The API token must have the **Log Export API** permission.
