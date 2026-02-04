# Halcyon

Halcyon is a device management platform that helps organizations monitor, control, and secure their network of devices. It provides centralized tools for overseeing hardware and software inventory, deploying updates, enforcing security policies, and ensuring compliance across device environments.

This integration fetches alerts and events from the Halcyon platform and ingests them into Cortex XSIAM.

## Configure Halcyon on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automation & Feed Integrations**.
2. Search for **Halcyon**.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Halcyon API server URL. Default: https://api.halcyon.ai | True |
| Username | Username associated with your Halcyon account. | True |
| Password | Password associated with your Halcyon account. | True |
| Trust any certificate (not secure) | When selected, certificates are not checked. | False |
| Use system proxy settings | Runs the integration instance using the proxy server configured for the server. | False |
| Log types to fetch | Select which log types to fetch from Halcyon. Options: Alerts, Events. Default: Both. | True |
| Fetch events | When selected, the integration will fetch events. | False |
| Maximum number of alerts per fetch | Maximum number of alerts to fetch per fetch cycle. Default: 1000. | False |
| Maximum number of events per fetch | Maximum number of events to fetch per fetch cycle. Default: 1000. | False |
| Events Fetch Interval | How often to fetch events (in minutes). Default: 1 minute. | False |

4. Click **Test** to validate the connection.

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.

### halcyon-get-events

***
This command is used for developing/debugging and is to be used with caution, as it can create events, leading to events duplication and API request limitation exceeding.

#### Base Command

`halcyon-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events to return. Default is 1000. | Optional |
| start_time | Filter events that occurred after this time. Supports ISO 8601 format or relative time expressions (e.g., "3 days ago", "2024-01-01T00:00:00Z"). | Optional |
| end_time | Filter events that occurred before this time. Supports ISO 8601 format or relative time expressions (e.g., "now", "2024-01-01T00:00:00Z"). | Optional |
| should_push_events | If true, the command creates events in XSIAM; otherwise, it only displays them. Possible values are: true, false. Default is false. | Optional |

#### Context Output

There is no context output for this command.

#### Human Readable Output

The command returns a table with the fetched events.

## Fetched Event Types

The integration fetches the following event types:

### Alerts
- **API Endpoint**: `/v2/alerts`
- **Time Field**: `lastOccurredAt`
- **Source Log Type**: `alerts`

Alerts represent security-related notifications from the Halcyon platform, including threat detections, policy violations, and other security events.

### Events
- **API Endpoint**: `/v2/events`
- **Time Field**: `occurredAt`
- **Source Log Type**: `events`

Events represent general activity logs from the Halcyon platform, including device activities, system events, and operational logs.

## Dataset

The data is stored in the `halcyon_halcyon_raw` dataset in Cortex XSIAM.

## Troubleshooting

### Authentication Issues

If you encounter authentication errors:
1. Verify that the username and password are correct.
2. Ensure the account has the necessary permissions to access the Halcyon API.
3. Check if the account is locked or disabled.

### Rate Limiting

If you encounter rate limiting errors:
1. Reduce the maximum number of events per fetch.
2. Increase the fetch interval.
3. Contact Halcyon support if the issue persists.

### Connection Issues

If you encounter connection errors:
1. Verify the Server URL is correct.
2. Check network connectivity to the Halcyon API.
3. If using a proxy, ensure the proxy settings are configured correctly.
4. If SSL certificate errors occur, you may need to enable "Trust any certificate" (not recommended for production).

### Missing Events

If events are not being fetched:
1. Verify that the "Fetch events" checkbox is enabled.
2. Check that the correct log types are selected.
3. Ensure the account has permissions to access the selected log types.
4. Review the integration logs for any error messages.
