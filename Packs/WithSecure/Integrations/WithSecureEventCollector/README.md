WithSecure event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 1.0 of WithSecure Elements API

## Configure WithSecure Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | WithSecure API endpoint (e.g., https://api.connect.withsecure.com) | True |
| Client ID | Client ID for OAuth2 authentication | True |
| Client Secret | Client Secret for OAuth2 authentication | True |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | How far back to fetch events on first run | False |
| Maximum number of events per fetch, Max 1000 | Maximum events to fetch per interval | False |
| Incident statuses to fetch | Comma-separated statuses that should be ingested as Cortex XSOAR incidents | False |
| Incident risk levels to fetch | Optional risk levels to filter fetched incidents | False |
| Incident sources to fetch | Optional sources (endpoint, cloud, etc.) for the fetched incidents | False |
| Maximum number of incidents per fetch. Max 50 | Caps the amount of WithSecure incidents ingested per cycle | False |
| Incident type | Incident type that will be assigned to fetched incidents | False |
| Trust any certificate (not secure) | Skip SSL certificate verification | False |
| Use system proxy settings | Use system proxy for API calls | False |

## Incident Fetching

- Incident fetching is optional; enable *Fetch Incidents* in the integration instance to start ingesting WithSecure incidents.
- The integration deduplicates incidents by `createdTimestamp` and `incidentId`, ensuring incidents are fetched once.
- Default filters ingest incidents with statuses `new`, `acknowledged`, or `inProgress`. Adjust the configuration parameters to match your workflow (status, risk level, sources, and maximum per fetch).
- Fetched incidents are assigned Cortex XSOAR severities based on the WithSecure severity/risk level (`info` → 0, `low` → 1, `medium` → 2, `high` → 3, `severe` → 4).

## Authentication Process

To create API credentials (Client ID and Client Secret):

1. Login to [Elements Security Center](https://elements.withsecure.com/) as EPP administrator
2. Navigate to **Management > API Clients**
3. Change scope to the target organization
4. Click **Add new**
5. Enter description and configure permissions:
   - **Read-only**: For event collection and querying (recommended for most use cases)
   - **Read-write**: For incident management and response actions (isolation, scan, etc.)
6. **Important**: Save the Client Secret immediately (shown only once)
7. Note the Client ID

For detailed instructions, see [WithSecure API Documentation](https://connect.withsecure.com/getting-started/elements).

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### with-secure-get-events

***
Manual command used to fetch security events and display them.

#### Base Command

`with-secure-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fetch_from | The date to start collecting the events from. | Optional |
| limit | The maximum amount of events to return. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!with-secure-get-events limit=10 fetch_from="7 days"```

---

### with-secure-get-incidents

***
List EDR incidents (Broad Context Detections) from WithSecure.

#### Base Command

`with-secure-get-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Comma-separated list of incident IDs to retrieve. Leave empty to get all incidents. | Optional |
| status | Filter by incident status. Possible values are: new, acknowledged, inProgress, monitoring, closed, waitingForCustomer. | Optional |
| risk_level | Filter by risk level. Possible values are: info, low, medium, high, severe. | Optional |
| limit | Maximum number of incidents to return. Default is 20, maximum is 50. | Optional |
| source | Filter by incident source. Possible values are: endpoint, cloud, customer, endpointExpert, identityAzure, workloadAzure, workloadAws. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.Incident.incidentId | String | Unique identifier of the incident (BCD). |
| WithSecure.Incident.incidentPublicId | String | Public ID visible in the portal. |
| WithSecure.Incident.status | String | Status of the incident. |
| WithSecure.Incident.severity | String | Severity level of the incident. |
| WithSecure.Incident.riskLevel | String | Risk level of the incident. |
| WithSecure.Incident.riskScore | Number | Risk score of the incident. |
| WithSecure.Incident.categories | Unknown | List of incident categories. |
| WithSecure.Incident.name | String | Name related to the incident. |

#### Command example

```!with-secure-get-incidents status=new risk_level=high limit=10```

---

### with-secure-update-incident-status

***
Update the status of a WithSecure EDR incident (BCD).

#### Base Command

`with-secure-update-incident-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID to update. | Required |
| status | New status for the incident. Possible values are: new, acknowledged, inProgress, monitoring, closed, waitingForCustomer. | Required |
| resolution | Resolution of the incident (required if status is closed). Possible values are: unconfirmed, confirmed, falsePositive, merged, securityTest, acceptedRisk, acceptedBehavior. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.IncidentUpdate.incidentId | String | ID of the updated incident. |
| WithSecure.IncidentUpdate.status | Number | HTTP status of the update operation. |

#### Command example

```!with-secure-update-incident-status incident_id="2c902c73-e2a6-40fd-9532-257ee102e1c1" status=acknowledged```

---

### with-secure-add-incident-comment

***
Add a comment to one or more WithSecure EDR incidents.

#### Base Command

`with-secure-add-incident-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_ids | Comma-separated list of incident IDs to add comment to. | Required |
| comment | Comment to add to the incidents. | Required |

#### Command example

```!with-secure-add-incident-comment incident_ids="2c902c73-e2a6-40fd-9532-257ee102e1c1" comment="Investigated and confirmed as malware"```

---

### with-secure-get-incident-detections

***
List detections for a given EDR incident (BCD).

#### Base Command

`with-secure-get-incident-detections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID to get detections for. | Required |
| limit | Maximum number of detections to return. Default is 100, maximum is 100. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.Detection.detectionId | String | Unique identifier of the detection. |
| WithSecure.Detection.incidentId | String | ID of the incident to which the detection belongs. |
| WithSecure.Detection.deviceId | String | ID of the device on which the incident was detected. |
| WithSecure.Detection.name | String | Name related to the detection. |
| WithSecure.Detection.severity | String | Severity level of the detection. |

#### Command example

```!with-secure-get-incident-detections incident_id="2c902c73-e2a6-40fd-9532-257ee102e1c1" limit=50```

---

### with-secure-get-devices

***
Query and list devices from WithSecure Elements.

#### Base Command

`with-secure-get-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | Filter by device ID (UUID format). | Optional |
| name | Filter by device name. | Optional |
| type | Filter by device type. Possible values are: computer, connector, mobile. | Optional |
| state | Filter by device state. Possible values are: active, blocked, inactive. | Optional |
| online | Filter devices by online status. Possible values are: true, false. | Optional |
| protection_status | Filter by protection status. Possible values are: isolated, inactive, critical, warning, allOk. | Optional |
| limit | Maximum number of devices to return. Default is 50, maximum is 200. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.Device.id | String | Device ID. |
| WithSecure.Device.name | String | Device name. |
| WithSecure.Device.type | String | Device type (computer, connector, mobile). |
| WithSecure.Device.state | String | Device state (active, blocked, inactive). |
| WithSecure.Device.online | Boolean | Whether the device is online. |
| WithSecure.Device.protectionStatusOverview | String | Protection status overview. |

#### Command example

```!with-secure-get-devices protection_status=isolated limit=20```

---

### with-secure-isolate-endpoint

***
Isolate one or more endpoints from the network to contain threats.

**Note**: This operation requires devices to be Windows computers in active state with valid subscription.

#### Base Command

`with-secure-isolate-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | Comma-separated list of device IDs to isolate (max 5). | Required |
| message | Message to display on isolated endpoint before isolation. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.IsolationAction.deviceId | String | ID of the device being isolated. |
| WithSecure.IsolationAction.status | Number | HTTP status of the isolation operation. |
| WithSecure.IsolationAction.operationId | String | ID of the isolation operation for tracking. |

#### Command example

```!with-secure-isolate-endpoint device_ids="ec8a0100-d313-4896-b3cb-02188e060bf3" message="Your computer is being isolated due to security threat"```

---

### with-secure-release-endpoint

***
Release one or more endpoints from network isolation.

#### Base Command

`with-secure-release-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | Comma-separated list of device IDs to release from isolation (max 5). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.IsolationAction.deviceId | String | ID of the device being released. |
| WithSecure.IsolationAction.status | Number | HTTP status of the release operation. |
| WithSecure.IsolationAction.operationId | String | ID of the release operation for tracking. |

#### Command example

```!with-secure-release-endpoint device_ids="ec8a0100-d313-4896-b3cb-02188e060bf3"```

---

### with-secure-scan-endpoint

***
Trigger a malware scan on one or more endpoints.

#### Base Command

`with-secure-scan-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | Comma-separated list of device IDs to scan (max 5). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.ScanAction.deviceId | String | ID of the device being scanned. |
| WithSecure.ScanAction.status | Number | HTTP status of the scan operation. |
| WithSecure.ScanAction.operationId | String | ID of the scan operation for tracking. |

#### Command example

```!with-secure-scan-endpoint device_ids="ec8a0100-d313-4896-b3cb-02188e060bf3,01898f1e-d32d-40fe-b3c5-9f039c1eac04"```

---

### with-secure-get-device-operations

***
List all operations triggered on a specific device.

#### Base Command

`with-secure-get-device-operations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | Device ID to query operations for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.DeviceOperation.id | String | Operation ID. |
| WithSecure.DeviceOperation.status | String | Operation status (pending, finished, ongoing, failed). |
| WithSecure.DeviceOperation.operationName | String | Operation name. |

#### Command example

```!with-secure-get-device-operations device_id="ec8a0100-d313-4896-b3cb-02188e060bf3"```

---

## Supported Event Types

The integration collects security events from multiple engines:

### Endpoint Protection (EPP)
- Real-time and manual file scanning
- DeepGuard behavioral analysis
- Application Control
- Device Control
- DataGuard
- Firewall
- Browsing Protection
- Web Traffic Scanning
- Connection Control
- Tamper Protection
- Integrity Checker
- AMSI (Antimalware Scan Interface)
- System Events Log

### Endpoint Detection and Response (EDR)
- Broad Context Detections (BCDs)
- Incident lifecycle (created, updated, closed, merged)
- Lateral movement detection
- Credential theft detection
- Malware and PUP detection
- Advanced threat behaviors

### Collaboration Protection (ECP)
- Email scanning (malware, phishing)
- Microsoft Teams scanning
- SharePoint scanning
- OneDrive scanning
- Inbox rule monitoring
- Breached account detection

### Exposure Management (XM)
- Security recommendations
- Vulnerability assessments
- Risk scoring

## Use Cases

### 1. Automated Threat Response
Use the isolation commands to automatically isolate compromised endpoints when critical EDR incidents are detected.

**Example Workflow:**
1. Fetch EDR incident events
2. Check incident severity and risk level
3. Get device details
4. Isolate endpoint if risk is severe
5. Add comment to incident
6. Update incident status

### 2. Incident Investigation
Query incidents, get detailed detections, and track investigation progress.

**Example Commands:**
```
!with-secure-get-incidents status=new risk_level=high
!with-secure-get-incident-detections incident_id=<incident_id>
!with-secure-add-incident-comment incident_ids=<incident_id> comment="Under investigation"
!with-secure-update-incident-status incident_id=<incident_id> status=inProgress
```

### 3. Endpoint Management
Monitor and manage endpoint protection status across your organization.

**Example Commands:**
```
!with-secure-get-devices protection_status=isolated
!with-secure-get-devices online=false limit=50
!with-secure-release-endpoint device_ids=<device_id>
```

### 4. Malware Containment
Trigger on-demand scans when suspicious activity is detected.

**Example Command:**
```
!with-secure-scan-endpoint device_ids=<device_id1>,<device_id2>
!with-secure-get-device-operations device_id=<device_id>
```

## Important Notes

### API Limitations
- Maximum 200 security events per API request
- Maximum 50 incidents per request
- Maximum 200 devices per request
- Maximum 5 devices for isolation/scan operations at once
- Maximum 10 incidents for bulk comment operations

### OAuth2 Authentication
- Tokens are automatically renewed before expiration
- Token expiration time is managed by the integration
- Requires `connect.api.read` scope for read operations
- Requires `connect.api.write` scope for write operations (isolation, updates, etc.)

### Response Actions
- Isolation requires Windows computers in active state
- Operations are asynchronous - use `with-secure-get-device-operations` to check status
- Operation status: pending, finished, ongoing, failed, internalError, unknownError

### Best Practices
- Use `persistenceTimestamp` for event collection (more reliable than `serverTimestamp`)
- Filter incidents by `archived=false` for better performance
- Monitor isolated endpoints and release them after threat remediation
- Close incidents with appropriate resolution after investigation

## Additional Resources

- [WithSecure Elements API Reference](https://connect.withsecure.com/api-reference/elements)
- [WithSecure Security Events Documentation](https://connect.withsecure.com/api-reference/security-events)
- [WithSecure API Cookbook](https://connect.withsecure.com/getting-started/elements-cookbook)
