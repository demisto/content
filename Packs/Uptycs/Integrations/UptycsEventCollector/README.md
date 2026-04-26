This integration is currently in Beta, allowing you to test pre-release software. Note that it may contain bugs, and future updates could include changes that are not backward compatible. We welcome your feedback to help us identify issues and improve the integration.

## Overview

Uptycs is a cloud-native security analytics platform that provides unified visibility across endpoints, cloud workloads, and containers. It leverages Osquery-based telemetry and threat intelligence to detect threats, monitor compliance, and investigate security incidents across hybrid environments.

This integration collects security alerts from the Uptycs platform and ingests them into Cortex XSIAM for centralized security monitoring and case (incident) response.

## Authentication

This integration uses JWT-based authentication (HS256) to connect to the Uptycs alertsReporting API. The JWT token is generated using the API Key (as the issuer) and API Secret (as the signing key) from the Uptycs API Client Management page.

## Before You Start

Before configuring the integration, you must obtain API credentials from your Uptycs console:

### Step 1: Generate API Credentials in Uptycs

1. Log in to your Uptycs console.
2. Navigate to **Configuration** > **Users** > **API Key**.
3. Click **Create** to generate a new API key.
4. Download the JSON file containing the API credentials. The file includes:
   - **key** — Your API Key
   - **secret** — Your API Secret
   - **customerId** — Your Customer ID
   - **domain** — Your Uptycs domain (used to construct the Server URL)

### Step 2: Construct the Server URL

The Server URL follows the format: `https://<domain>.uptycs.io`

For example, if your domain is `mycompany`, the Server URL would be `https://mycompany.uptycs.io`.

### Step 3: (Optional) Obtain Role ID and Security Zone ID

If your Uptycs environment uses role-based access control or security zones:

1. Navigate to **Configuration** > **Roles** to find the Role ID.
2. Navigate to **Configuration** > **Security Zones** to find the Security Zone ID.

These are optional and only needed if your API access requires specific role or zone scoping.

## Integration Parameters

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Uptycs API base URL.<br/>Format: `https://<domain>.uptycs.io` | True |
| API Key | The API Key from the Uptycs API Client Management page. Used for JWT authentication. | True |
| API Secret | The API Secret from the Uptycs API Client Management page. Used for JWT signing. | True |
| Customer ID | The Uptycs Customer ID (UUID). Found in the API key JSON file or the Uptycs console URL. | True |
| Role ID | Optional Role ID to include in the JWT token for role-based access control. | False |
| Security Zone ID | Optional Security Zone ID to include in the JWT token for zone-scoped access. | False |
| Trust any certificate (not secure) | When selected, the integration will not verify SSL certificates. | False |
| Use system proxy settings | When selected, the integration will use the system proxy settings. | False |
| Maximum number of alerts per fetch | Maximum number of alerts to fetch per collection cycle.<br/>Default: 10000<br/>Note: The API returns a maximum of 1000 alerts per page. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### uptycs-get-events

***
Gets alerts from Uptycs. This command is intended for developing and debugging and should be used with caution, as it can create duplicate events and exceed API rate limits.

**Note**: This command is not supported in XSOAR.

#### Base Command

`uptycs-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start time to fetch alerts from. Supports relative time (e.g., "3 days ago", "2 hours ago", "now") or absolute dates (ISO 8601 format, e.g., "2024-12-01" or "2024-12-01T10:00:00Z"). | Optional |
| end_time | The end time to fetch alerts until. Supports relative time (e.g., "1 hour ago", "now") or absolute dates (ISO 8601 format, e.g., "2024-12-01" or "2024-12-01T10:00:00Z"). If not specified, fetches until now. | Optional |
| limit | Maximum number of alerts to retrieve. Default is 10000. | Optional |
| should_push_events | Set to true to push events to XSIAM (use with caution to avoid duplicates), false to only return them in the War Room. Default is false. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.Alert.id | String | Unique identifier of the alert. |
| Uptycs.Alert.agentType | String | Type of agent associated with the alert (e.g., asset). |
| Uptycs.Alert.alertId | String | Alert identifier. |
| Uptycs.Alert.alertRuleId | String | Identifier of the alert rule that triggered this alert. |
| Uptycs.Alert.alertRuleName | String | Name of the alert rule that triggered this alert. |
| Uptycs.Alert.alertStatusReasonId | String | Identifier for the alert status reason. |
| Uptycs.Alert.alertTags | Unknown | Tags associated with the alert (e.g., MITRE ATT&CK techniques). |
| Uptycs.Alert.alertTime | Date | Timestamp when the alert was triggered. |
| Uptycs.Alert.alertTimeSuppresionDuration | String | Duration of alert time suppression. |
| Uptycs.Alert.alertTimeSuppresionStart | String | Start time of alert time suppression. |
| Uptycs.Alert.assetCityId | String | City identifier of the asset. |
| Uptycs.Alert.assetCores | Number | Number of CPU cores on the asset. |
| Uptycs.Alert.assetCpuBrand | String | CPU brand of the asset. |
| Uptycs.Alert.assetDescription | String | Description of the asset. |
| Uptycs.Alert.assetDisabled | Boolean | Whether the asset is disabled. |
| Uptycs.Alert.assetGateway | String | Gateway IP address of the asset. |
| Uptycs.Alert.assetHardwareModel | String | Hardware model of the asset. |
| Uptycs.Alert.assetHardwareSerial | String | Hardware serial number of the asset. |
| Uptycs.Alert.assetHardwareVendor | String | Hardware vendor of the asset. |
| Uptycs.Alert.assetHostName | String | Hostname of the asset associated with the alert. |
| Uptycs.Alert.assetId | String | Unique identifier of the asset. |
| Uptycs.Alert.assetLastActivityAt | Date | Timestamp of the asset's last activity. |
| Uptycs.Alert.assetLastEnrolledAt | Date | Timestamp when the asset was last enrolled. |
| Uptycs.Alert.assetLatitude | Number | Latitude of the asset's location. |
| Uptycs.Alert.assetLive | Boolean | Whether the asset is currently live. |
| Uptycs.Alert.assetLocation | String | Geographic location of the asset. |
| Uptycs.Alert.assetLogicalCores | Number | Number of logical CPU cores on the asset. |
| Uptycs.Alert.assetLongitude | Number | Longitude of the asset's location. |
| Uptycs.Alert.assetManualSlackAssignment | Boolean | Whether the asset has manual Slack assignment. |
| Uptycs.Alert.assetMemoryMb | Number | Memory in MB of the asset. |
| Uptycs.Alert.assetObjectGroupId | String | Object group identifier of the asset. |
| Uptycs.Alert.assetOs | String | Operating system of the asset. |
| Uptycs.Alert.assetOsFlavor | String | OS flavor of the asset (e.g., debian). |
| Uptycs.Alert.assetOsKey | String | OS key identifier of the asset. |
| Uptycs.Alert.assetOsVersion | String | OS version of the asset. |
| Uptycs.Alert.assetOsqueryVersion | String | Osquery version installed on the asset. |
| Uptycs.Alert.assetSlackUserId | String | Slack user ID associated with the asset. |
| Uptycs.Alert.assetStatus | String | Status of the asset (e.g., active). |
| Uptycs.Alert.assignedTo | String | User the alert is assigned to. |
| Uptycs.Alert.attackType | String | Type of attack associated with the alert. |
| Uptycs.Alert.cloudRegionCode | String | Cloud region code of the resource. |
| Uptycs.Alert.cloudResourceId | String | Cloud resource identifier. |
| Uptycs.Alert.cloudTenantId | String | Cloud tenant identifier. |
| Uptycs.Alert.cloudType | String | Cloud provider type. |
| Uptycs.Alert.code | String | Alert code identifier. |
| Uptycs.Alert.createdAt | Date | Timestamp when the alert was created. |
| Uptycs.Alert.custom | Boolean | Whether this is a custom alert rule. |
| Uptycs.Alert.customerId | String | Customer identifier. |
| Uptycs.Alert.description | String | Description of the alert. |
| Uptycs.Alert.displayName | String | Display name of the alert. |
| Uptycs.Alert.eventId | String | Event identifier associated with the alert. |
| Uptycs.Alert.exceptionMetadata | Unknown | Exception metadata containing detailed event information. |
| Uptycs.Alert.groupId | String | Group identifier. |
| Uptycs.Alert.groupName | String | Group name. |
| Uptycs.Alert.grouping | String | Alert grouping category (e.g., ATTACK). |
| Uptycs.Alert.groupingL2 | String | Second-level grouping (e.g., MITRE tactic). |
| Uptycs.Alert.groupingL3 | String | Third-level grouping (e.g., MITRE technique). |
| Uptycs.Alert.groupingL4 | String | Fourth-level grouping. |
| Uptycs.Alert.hashKey | String | Hash key of the alert. |
| Uptycs.Alert.isContainer | Boolean | Whether the alert is related to a container. |
| Uptycs.Alert.isTask | Boolean | Whether the alert is a task. |
| Uptycs.Alert.key | String | Key field of the alert. |
| Uptycs.Alert.lastActiveAt | Date | Timestamp when the alert was last active. |
| Uptycs.Alert.lastOccurredAt | Date | Timestamp when the alert last occurred. |
| Uptycs.Alert.metadata | Unknown | Alert metadata containing detailed event information. |
| Uptycs.Alert.noisy | Boolean | Whether the alert is marked as noisy. |
| Uptycs.Alert.note | String | Note attached to the alert. |
| Uptycs.Alert.noteCreatedAt | Date | Timestamp when the note was created. |
| Uptycs.Alert.noteCreatedBy | String | User who created the note. |
| Uptycs.Alert.noteId | String | Identifier of the note. |
| Uptycs.Alert.remediationActions | String | Remediation actions for the alert. |
| Uptycs.Alert.resolutionDays | Number | Number of days to resolve the alert. |
| Uptycs.Alert.resolvedAt | Date | Timestamp when the alert was resolved. |
| Uptycs.Alert.rowCount | Number | Number of rows associated with the alert. |
| Uptycs.Alert.ruleId | String | Rule identifier that triggered the alert. |
| Uptycs.Alert.severity | String | Severity level of the alert (e.g., low, medium, high, critical). |
| Uptycs.Alert.status | String | Current status of the alert (e.g., open, closed). |
| Uptycs.Alert.updatedAt | Date | Timestamp when the alert was last updated. |
| Uptycs.Alert.updatedBy | String | User who last updated the alert. |
| Uptycs.Alert.value | String | Value associated with the alert key. |
| Uptycs.Alert.source | String | Source of the alert (e.g., host). |
