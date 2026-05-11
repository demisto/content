# BeyondTrust Privilege Management Cloud

## Overview

BeyondTrust Privilege Management Cloud (PM Cloud) integration for retrieving audit events and activity logs from the BeyondTrust PM Cloud Management API v3.

This integration supports:

- Fetching Activity Audits (audit logs of configuration changes and administrative actions)
- Fetching Events (endpoint privilege management events)
- Event collection for XSIAM

## Configure BeyondTrust Privilege Management Cloud on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for BeyondTrust Privilege Management Cloud.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | The server URL in the format: https://[yourProductionSub-domainName]-services.pm.beyondtrustcloud.com | True |
    | Client ID | The OAuth client ID from the API account created in PM Cloud. | True |
    | Client Secret | The OAuth client secret from the API account created in PM Cloud. | True |
    | Events types to fetch | Select which event types to fetch: Activity Audits, Events, or both. | False |
    | Trust any certificate (not secure) | When selected, certificates are not verified. | False |
    | Use system proxy settings | Use the system proxy settings. | False |
    | Fetch events | Enable event fetching for XSIAM. | False |
    | Maximum number of audit events (per type) | Maximum number of events to fetch per fetch cycle (default: 6000). | False |
    | First fetch timestamp | The time from which to start fetching events (e.g., "3 days", "1 week"). | False |

4. Click **Test** to validate the URLs, token, and connection.

## Prerequisites

To create an API account in BeyondTrust PM Cloud:

1. Sign into app.beyondtrust.io.
2. From the top left of the page, click > **Endpoint Privilege Management for Windows and Mac** > **Configuration**.
3. Click the **Configuration** menu, and then click **API Settings**.
4. Click **Create an API Account**.
5. Enter a name and description.
6. The Client ID and Client Secret are automatically generated. The secret is only visible when initially generated for security reasons.
7. Copy the Client ID and Client Secret values to use in the integration configuration.

**Important Notes:**

- The instance URL can be found at the top of the API Settings page.
- The client secret cannot be modified, but it can be regenerated on the Configuration > Settings > API Settings page.
- Regenerating a client secret immediately invalidates any OAuth tokens associated with the account.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### beyondtrust-pm-cloud-get-events

***
Retrieves events or activity audits from BeyondTrust PM Cloud. Use the `event_type` argument to switch between Events and Activity Audits.

#### Base Command

`beyondtrust-pm-cloud-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_type | The type of events to retrieve. Possible values are: Events, Activity Audits. Default is Events. | Optional |
| start_date | Start Date (UTC) to search events from (Elastic Ingestion Timestamp in UTC). Format: 2022-08-12T17:34:28.694Z. If not provided, defaults to 1 hour ago. | Optional |
| limit | Maximum records that can be returned. For Events: max 1000. For Activity Audits: max 200. Default is 50. | Optional |
| should_push_events | Set to true to push events to XSIAM. Used for debugging. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BeyondTrust.Event.id | String | The ID of the event. |
| BeyondTrust.Event.created | Date | The creation time of the event. |
| BeyondTrust.Event.@timestamp | Date | The timestamp of the event. |
| BeyondTrust.Event.auditType | String | Audit type name (Activity Audits only). |
| BeyondTrust.Event.details | String | Details of the activity (Activity Audits only). |
| BeyondTrust.Event.entity | String | Name of Activity Audit entity (Activity Audits only). |
| BeyondTrust.Event.user | String | Initiated user email or API client identifier (Activity Audits only). |
| BeyondTrust.Event.changedBy | String | Audit ChangedBy - API or Portal (Activity Audits only). |

#### Command example (Events)

```!beyondtrust-pm-cloud-get-events event_type="Events" start_date="2025-01-01T00:00:00.000Z" limit="10"```

#### Context Example (Events)

```json
{
    "BeyondTrust": {
        "Event": [
            {
                "id": "event-123",
                "created": "2025-01-01T00:00:00.000Z",
                "@timestamp": "2025-01-01T00:00:00.000Z"
            }
        ]
    }
}
```

#### Command example (Activity Audits)

```!beyondtrust-pm-cloud-get-events event_type="Activity Audits" limit="10"```

#### Context Example (Activity Audits)

```json
{
    "BeyondTrust": {
        "Event": [
            {
                "id": 123,
                "created": "2025-01-01T00:00:00.000Z",
                "details": "User created",
                "user": "admin@example.com",
                "entity": "User",
                "auditType": "Create",
                "changedBy": "Portal"
            }
        ]
    }
}
```

## Event Collection

This integration supports event collection for XSIAM. When configured with **Fetch events** enabled, the integration will:

1. Fetch Activity Audits and/or Events based on the **Events types to fetch** configuration.
2. Add required XSIAM fields to each event:
   - `_time`: Set from the event's `created` or `@timestamp` field
   - `source_log_type`: Set to `activity_audits` or `events` depending on the event type
   - `vendor`: Set to `beyondtrust`
   - `product`: Set to `pm_cloud`

### Continuous Event Coverage

**Important**: The integration uses a **continuous coverage** approach to prevent event gaps:

- Each fetch cycle stores the fetch start time (not the last event's timestamp) as the next run's start time
- This ensures events created between fetch cycles are never missed
- Example: If Fetch 1 runs at 12:00 and finds events up to 11:50, it stores 12:00 as the next start time
- When Fetch 2 runs at 12:05, it fetches from 12:00 to 12:05, capturing any events created in that window
- Deduplication is performed based on event IDs to handle any overlapping events

### Event Types

#### Activity Audits

Activity Audits track configuration changes and administrative actions in PM Cloud, including:

- User management (create, modify, disable)
- Group management
- Policy changes
- Computer management
- API client changes
- Installation key changes
- Settings modifications

**Dataset**: `beyondtrust_pm_cloud_raw`  
**Source Log Type**: `activity_audits`

#### Events

Events track endpoint privilege management activities, including:

- Application execution events
- Privilege elevation events
- Authorization requests
- Policy enforcement events
- Security events

**Dataset**: `beyondtrust_pm_cloud_raw`  
**Source Log Type**: `events`

## API Documentation

This integration uses the BeyondTrust PM Cloud Management API v3. For more information, refer to:

- [BeyondTrust PM Cloud API Documentation](https://docs.beyondtrust.com/epm-wm/reference)
- Activity Audits endpoint: `GET /management-api/v3/ActivityAudits/Details`
- Events endpoint: `GET /management-api/v3/Events/FromStartDate`

## Known Limitations

- The Events endpoint (`FromStartDate`) has a maximum record size of 1000 per request.
- The Activity Audits endpoint has a maximum page size of 200 records.
- This integration is developed for blind deployment and will be tested in the customer's environment.

## Troubleshooting

### Authentication Issues

- Verify the Client ID and Client Secret are correct.
- Ensure the API account has the necessary permissions in PM Cloud.
- Check that the Server URL is in the correct format: `https://[yourProductionSub-domainName]-services.pm.beyondtrustcloud.com`

### No Events Fetched

- Verify the **First fetch timestamp** is set appropriately.
- Check that events exist in the specified time range.
- Ensure **Events types to fetch** is configured correctly.
- Review the integration logs for any API errors.

### Token Expiration

- OAuth tokens expire after 3600 seconds (1 hour).
- The integration automatically refreshes tokens as needed.
- If you regenerate the client secret in PM Cloud, update the integration configuration immediately.
