## Overview

SAP Enterprise Threat Detection (ETD) helps identify, analyze, and neutralize cyberattacks in SAP applications.
This integration fetches alerts from SAP ETD and ingests them as events into Cortex XSIAM for security monitoring and threat analysis.

### Prerequisites

- An SAP Enterprise Threat Detection (ETD) instance with API access enabled.
- A user account with the following application privileges:
  - **AlertRead** – Required to read alert data from the ETD system.
  - **EventRead** – Required to read triggering events associated with alerts.
- Network connectivity from the Cortex XSIAM instance to the SAP ETD server (ensure firewall rules allow HTTPS traffic on the configured port).

### Configuration

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **SAP Enterprise Threat Detection**.
3. Click **Add instance** and configure the following parameters:

| Parameter | Description | Required |
| --- | --- | --- |
| Server URL | The base URL of your SAP ETD server (e.g., `https://<Server_Host>:<Port>`). | True |
| Username and Password | Credentials for a user with the required application privileges. | True |
| Trust any certificate (not secure) | Select if the server uses a self-signed certificate (not recommended for production). | False |
| Use system proxy settings | Select to route traffic through the system proxy. | False |
| Maximum alerts per fetch | Maximum number of alerts to retrieve per fetch cycle (default: 10000). | False |

4. Click **Test** to verify connectivity.
5. Click **Save & exit**.

### Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.

#### sap-etd-get-events

***
Gets alerts from SAP Enterprise Threat Detection. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to event duplication and API request limitation exceeding.

##### Base Command

`sap-etd-get-events`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | The start date/time to fetch alerts from. Supports relative time (e.g., "3 days ago", "2 hours ago") or specific ISO 8601 dates (e.g., "2026-01-15T15:00:00.00Z"). Default is 3 days ago. | Optional |
| limit | Maximum number of alerts to retrieve. Default is 50. | Optional |
| should_push_events | Set to true to push events to XSIAM (use with caution to avoid duplicates). Possible values are: true, false. Default is false. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SAPETD.Alert.AlertId | Number | Unique identifier of the alert. |
| SAPETD.Alert.AlertSeverity | String | Severity level of the alert (e.g., LOW, MEDIUM, HIGH). |
| SAPETD.Alert.AlertStatus | String | Current status of the alert (e.g., OPEN, CLOSED). |
| SAPETD.Alert.Category | String | Category of the alert (e.g., Brute Force Attack). |
| SAPETD.Alert.PatternName | String | Name of the detection pattern that triggered the alert. |
| SAPETD.Alert.AlertCreationTimestamp | String | Timestamp when the alert was created (ISO 8601). |
| SAPETD.Alert.Text | String | Human-readable description of the alert. |
| SAPETD.Alert.Score | Number | Alert score value. |
