## Overview

SAP Enterprise Threat Detection (ETD) helps identify, analyze, and neutralize cyberattacks in SAP applications.
This integration fetches alerts from SAP ETD and ingests them as events into Cortex XSIAM for security monitoring and threat analysis.

The integration supports both SAP ETD editions. Select the edition in the **SAP ETD Edition** parameter:

| Edition | API | Authentication |
| --- | --- | --- |
| On-Premise | `/sap/secmon/services/Alerts.xsjs` | Basic (user name and password). X.509 is not supported. |
| Cloud Edition | Data Retriever service, `/alerts/v1/Alerts` | OAuth2 client credentials (service binding). |

### Prerequisites: On-Premise

- A user with the following application privileges:
  - `sap.secmon::Execute`
  - `sap.secmon.ui::Execute`
  - `sap.secmon::AlertRead`
  - `sap.secmon::NormalizedLogRead`
  - `sap.secmon::ResolveUserOnAlertService` (shows real user names instead of pseudonyms)
- The alert publishing job `sap.secmon.framework.pattern.publishalerts.jobs::alertPublishingJob` is active. Without it, no alerts are published to external systems.
- Network connectivity from Cortex XSIAM to the SAP ETD server (HTTPS on the configured port).

### Prerequisites: Cloud Edition

- In the SAP BTP subaccount, the entitlement **SAP Enterprise Threat Detection, Cloud Edition, Data Retriever** is assigned.
- An instance of the Data Retriever service with a service binding (key). The binding grants the `AlertsInformationRead` scope.

### Configuration

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **SAP Enterprise Threat Detection**.
3. Click **Add instance** and configure the following parameters:

| Parameter | Description | Required |
| --- | --- | --- |
| SAP ETD Edition | On-Premise or Cloud Edition. Default is On-Premise. | True |
| Server URL | On-Premise: `https://<Server_Host>:<Port>`. Cloud Edition: the `url` value of the service binding. | True |
| Username / Client ID, Password / Client Secret | On-Premise: the user name and password. Cloud Edition: the `uaa.clientid` and `uaa.clientsecret` values of the service binding. | True |
| Token URL (Cloud Edition only) | The `uaa.url` value of the service binding. `/oauth/token` is appended when missing. | False |
| Trust any certificate (not secure) | Select if the server uses a self-signed certificate (not recommended for production). | False |
| Use system proxy settings | Select to route traffic through the system proxy. | False |
| Maximum number of Threat Detection Alerts per fetch | Maximum number of alerts to retrieve per fetch cycle (default: 10000). | False |

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
| from_date | The start date/time to fetch alerts from. Supports relative time (e.g., "5 minutes ago", "2 hours ago") or specific ISO 8601 dates (e.g., "2026-01-15T15:00:00.00Z"). Default is 5 minutes ago. | Optional |
| limit | Maximum number of alerts to retrieve. Default is 50. | Optional |
| should_push_events | Set to true to push events to XSIAM (use with caution to avoid duplicates). Possible values are: true, false. Default is false. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SAPETD.Alert.AlertId | Number | The unique identifier of the alert. |
| SAPETD.Alert.AlertSeverity | String | On-Premise only: the severity level of the alert. Can be LOW, MEDIUM, or HIGH. |
| SAPETD.Alert.AlertStatus | String | On-Premise only: the current status of the alert. Can be OPEN or CLOSED. |
| SAPETD.Alert.Category | String | On-Premise only: the category of the alert, such as Brute Force Attack. |
| SAPETD.Alert.PatternName | String | The name of the detection pattern that triggered the alert. |
| SAPETD.Alert.AlertCreationTimestamp | String | On-Premise only: the date and time the alert was created (ISO 8601). |
| SAPETD.Alert.Text | String | On-Premise only: a human-readable description of the alert. |
| SAPETD.Alert.Score | Number | The alert score value. |
| SAPETD.Alert.Status | String | Cloud Edition only: the current status of the alert, such as OPEN, NO_REACTION_NEEDED_T, INVESTIG_TRIGGERED, or EXEMPTED. |
| SAPETD.Alert.CreationTimestamp | String | Cloud Edition only: the date and time the alert was created (ISO 8601). |
| SAPETD.Alert.MinTimestamp | String | The time of the first event that triggered the alert (ISO 8601). |
| SAPETD.Alert.MaxTimestamp | String | The time of the last event that triggered the alert (ISO 8601). |
