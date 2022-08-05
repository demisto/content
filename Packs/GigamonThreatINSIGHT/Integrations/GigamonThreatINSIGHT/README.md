# Gigamon ThreatINSIGHT Integration for Cortex XSOAR

## Insight Overview

The Gigamon ThreatINSIGHT Cortex XSOAR integration enables security teams to utilize the features and functionality of the ThreatINSIGHT solution with their existing Cortex deployment. The integration leverages ThreatINSIGHT RESTful APIs to interact with the back end to introduce specific data sets into Cortex XSOAR. This document contains all the necessary information to configure, install, and use the integration.

## Integration Overview

The Gigamon ThreatINSIGHT Cortex XSOAR integration enables security teams to utilize the features and functionality of the Insight solution with their existing Cortex XSOAR deployment. The integration leverages Insight’s fully RESTful APIs to interact with the Insight backend to introduce specific data sets into Cortex XSOAR. This document contains all the necessary information to configure, install, and use the integration.
For more information about the Cortex XSOAR integration visit the Insight help documentation here: https://insight.gigamon.com/help/api/apidocs-demisto

## Configure Gigamon ThreatINSIGHT on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Instances**.
2. Search for **Gigamon ThreatINSIGHT**.
3. Click the Add Instance link to create a new instance of the add-on.
In the settings, enter a Name for the instance, and a valid Insight API Key. (in the Insight portal, navigate to the Profile Settings page to create a new API key).
Optional - Select the Fetches Incidents option to have the integration periodically pull new detections from Insight into Cortex XSOAR. Note: This will pull ALL events your portal account has access to unless you specify a specific account UUID.
4. Choose either Use Single Engine or Use Load-Balancing Group depending on your Cortex XSOAR deployment.
5. Click the Test button to test the instance. If the instance can connect to the Insight APIs, you should see a successful message like the one above.
6. Lastly, click the Done button to complete the installation of the integration.

![Gigamon settings](https://images.ctfassets.net/yjhod2jd8xdy/1DYzrZ4Ffcv0qmrF4Y0hvB/13f9fdc6808160e19961540ee9d4bea1/image.png)

## Commands

The integration includes several commands available to execute within Cortex XSOAR to interact with Gigamon ThreatINSIGHT. Below is a list of all the commands and the following sections detail the arguments for each command.

| Command | Description |
| ------- | ----------- |
| insight-get-events | Perform a search for network events from ThreatINSIGHT |
| insight-get-history | Get user's query history |
| insight-get-saved-searches | Get user's saved searches |
| insight-get-sensors | Get a list of all sensors |
| insight-get-devices | Get the number of unique IPs observed over the last 24  hours |
| insight-get-tasks | Get a list of all the PCAP tasks |
| insight-create-task | Create a new PCAP task |
| insight-get-detections | Get a list of detections |
| insight-get-detection-rules | Get a list of detection rules |
| insight-resolve-detection | Resolve a specific detection |
| insight-get-detection-rule-events | Get a list of the events that matched on a specific rule |
| insight-create-detection-rule | Create a new detection rule |
| insight-get-entity-summary | Get entity summary information about an IP or  domain |
| insight-get-entity-pdns | Get passive DNS information about an IP or domain |
| insight-get-entity-dhcp | Get DHCP information about an IP address |
| insight-get-entity-file | Get entity information about a file |
| insight-get-telemetry-events | Get event telemetry data grouped by time |
| insight-get-telemetry-network | Get network telemetry data grouped by time |
| insight-get-telemetry-packetstats | Get network metrics to a given sensor's interfaces |

### Insight-get-events

Perform a search for network events.

Example Command
`!insight-get-events query="dns:dst.internal=false" limit=100 start_date=2019-01-01T00:00:00.000Z end_date=2019-01-31T23:59:59.999Z`

Example Command
`!insight-get-events query="event_type='http' AND src.ip='10.1.1.20' AND dst.ip='1.2.3.4'"`

#### Arguments

| Name | Description | Example |
| ---- | ----------- | ------- |
| query* | The query string or entity for which to search. | `dns:dst.internal=false` |
| start_date | The beginning of the temporal extent by which to restrict filter results, inclusive. | `2019-01-01T00:00:00.000Z` |
| end_date | The end of the temporal extent by which to restrict filter results, exclusive. | `2019-01-31T23:59:59.999Z` |
| limit | A limit on the number of events returned in filter results. Default is 100. Max is 10000 | `1000` |
| order_by | The event property by which to order results. Default is timestamp. | `timestamp` |
| order | The order of results, either asc or desc. Default is desc. | `asc` |
| customer_id | The customer ID by which to restrict filter results. Default is user account. | `abc` |
| history | When true, save this query in user Query History and include up to the last 50 queries from users Query History. Default is false. | `false` |
| service_traffic | When true, the service will include the service_traffic aggregation. Default is false. | `false` |

### Insight-get-history

Get user's query history.

Example Command
`!insight-get-history`

#### Arguments

None

### Insight-get-saved-searches

Get user's saved searches.

Example Command
`!insight-get-saved-searches`

#### Arguments

None

### Insight-get-sensors

Get a list of all sensors.

Example Command
`!insight-get-sensors account_uuid=0a7dae9g-6f74-4c75-78ef-856483763e1d4`

#### Arguments

| Name | Description | Example |
| ---- | ----------- | ------- |
| account_uuid | UUID of account to filter by. | `0a7dae9g-6f74-4c75-78ef-856483763e1d4` |
| account_code | Account code to fiilter by. | `abc` |
| sensor_id | ID of the sensor to filter by. | `abc1` |

### Insight-get-devices

Get a list of all devices.

Example Command
`!insight-get-devices start_date=2019-01-01T00:00:00.000Z end_date=2019-01-31T23:59:59.999Z`

#### Arguments

| Name | Description | Example |
| ---- | ----------- | ------- |
| start_date | Filter devices based on when they were seen. | `2019-01-01T00:00:00.000Z` |
| end_date | Filter devices based on when they were seen. | `2019-01-31T23:59:59.999Z` |
| cidr | Filter devices that are under a specific CIDR. | `10.1.1.0/24` |
| sensor_id | Filter devices that were observed by a specific sensor. | `abc1` |
| traffic_direction | Filter devices that have been noted to only have a certain directionality of traffic ("external" vs "internal"). | `external` |
| sort_by | Sort output by: "ip", "internal", "external". | `created` |
| sort_direction | Sort direction ("asc" vs "desc"). | `asc` |

### Insight-get-tasks

Get a list of all the PCAP tasks.

Example Command
`!insight-get-tasks task_uuid=8d7ryg9b-3fh2-2k10-11tn-32g502302r1d2`

#### Arguments

| Name | Description | Example |
| ---- | ----------- | ------- |
| task_uuid | Filter to a specific task | `8d7ryg9b-3fh2-2k10-11tn-32g502302r1d2` |

### Insight-create-task

Create a new PCAP task.

Example Command
`!insight-create-task name="Possible Exfiltration via FTP" account_uuid=0a7dae9g-6f74-4c75-78ef-856483763e1d4 description="Capture possible exfiltration via FTP" bpf="host 1.2.3.4 and port 21" requested_start_date=2019-01-01T00:00:00.000Z requested_end_date=2019-01-31T23:59:59.999Z`

#### Arguments
| Name | Description | Example |
| ---- | ----------- | ------- |
| name* | The name of the task. | `"Possible Exfiltration via FTP"` |
| account_uuid* | Account where the task will be created. | `0a7dae9g-6f74-4c75-78ef-856483763e1d4` |
| description* | A description for the task. | `"Capture possible exfiltration via ftp"` |
| bpf* | The Berkeley Packet Filter for capture filtering. | `"host 1.2.3.4 and port 21"` |
| requested_start_date* | The date the task will become active. (2019-01-30T00:00:00.000Z) | `2019-01-01T00:00:00.000Z` |
| requested_end_date* | The date the task will become inactive. (2019-12-31T23:59:59.000Z) | `2019-01-31T23:59:59.999Z` |
| sensor_ids* | Sensor IDs on which this task will run (separate multiple accounts by comma). | `abc1,abc2,abc3` |

*Denotes a required argument

### Insight-get-detections

Get a list of detections.

Example Command
`!insight-get-detections status=active include=rules created_or_shared_start_date=2019-01-01T00:00:00.000Z`

#### Arguments

| Name | Description | Example |
| ---- | ----------- | ------- |
| rule_uuid | Filter to a specific rule. | `451rtg2b-1yh3-88e1-21re-09y542301g7t1` |
| account_uuid | For those with access to multiple accounts, specify a single account to return results from. | `0a7dae9g-6f74-4c75-78ef-856483763e1d4` |
| status | Filter by detection status: active / resolved. | `active` |
| device_ip | Device IP to filter by. | `10.1.1.2` |
| sensor_id | Sensor ID to filter by. | `abc1` |
| muted | List detections that a user muted: true / false. | `false` |
| muted_device | List detections for muted devices: true / false. | `true` |
| muted_rule | List detections for muted rules. | `true` |
| include | Include additional information in the response (rules). | `rules` |
| created_or_shared_start_date | Created or shared start date to filter by (inclusive). | `2019-01-01T00:00:00.000Z` |
| created_or_shared_end_date | Created or shared start date to filter by (exclusive). | `2019-01-31T23:59:59.999Z` |
| sort_by | Sort output by: "ip", "internal", "external". | `ip` |
| sort_order | Sort direction ("asc" vs "desc"). | `asc` |
| offset | The number of records to skip past. | `10` |
| limit | The number of records to return, default: 100, max: 1000. | `100` |

### Insight-get-detection-rules

Get a list of detection rules.

Example Command
`!insight-get-detection-rules has_detections=true sort_by=last_seen`
#### Arguments

| Name | Description | Example |
| ---- | ----------- | ------- |
| search | String to search in the name or category fields | `agent` |
| account_uuid | For those with access to multiple accounts, specify a single account to return results from. | `0a7dae9g-6f74-4c75-78ef-856483763e1d4` |
| has_detections | Include rules that have unmuted, unresolved detections. | `true` |
| severity | Filter by severity: high, moderate, low. | `high` |
| confidence | Filter by confidence: high, moderate, low. | `moderate` |
| category | Category to filter by. | `"Attack:Lateral Movement"` |
| rule_account_muted | Include muted rules: true / false. | `false` |
| enabled | Enabled rules only true / false | `true` |
| sort_by | Field to sort output by. | `last_seen` |
| sort_order | Sort direction ("asc" vs "desc"). | `desc` |
| offset | The number of records to skip past. | `10` |
| limit | The number of records to return, default: 100, max: 1000. | `100` |

### Insight-resolve-detection

Resolve a specific detection.

Example Command
`!insight-resolve-detection detection_uuid=8d7ryg9b-3fh2-2k10-11tn-32g502302r1d2 resolution=true_positive resolution_comment="detection has been mitigated"`
#### Arguments

| Name | Description | Example |
| ---- | ----------- | ------- |
| detection_uuid* | Detection UUID to resolve | `8d7ryg9b-3fh2-2k10-11tn-32g502302r1d2` |
| resolution* | Resolution state. Options: true_positive_mitigated, true_positive_no_action, false_positive, unknown | `true_positive` |
| resolution_comment | Optional comment for the resolution. | `"detection has been mitigated"` |

*Denotes a required argument

### Insight-get-detection-rule-events

Get a list of the events that matched on a specific rule.

Example Command
`!insight-get-detection-rule-events rule_uuid=1a7rye9g-5f74-7c75-38ng-82z583782e1d7`
#### Arguments

| Name | Description | Example |
| ---- | ----------- | ------- |
| rule_uuid* | Rule UUID to get events for | `1a7rye9g-5f74-7c75-38ng-82z583782e1d7` |
| offset | The number of records to skip past | `10` |
| limit | The number of records to return, default: 100, max: 1000. | `100` |

*Denotes a required argument

### Insight-create-detection-rule

Create a new detection rule.

Example Command
`!insight-create-detection-rule account_uuid=0a7dae9g-6f74-4c75-78ef-856483763e1d4 name="Test Rule" category="Posture:Anomalous Activity" query_signature="ip=1.2.3.4" description="Test rule" severity=high confidence=moderate run_account_uuids=0a7dae9g-6f74-4c75-78ef-856483763e1d4`
#### Arguments

| Name | Description | Example |
| ---- | ----------- | ------- |
| account_uuid* | Your account ID (not your user ID). | `0a7dae9g-6f74-4c75-78ef-856483763e1d4` |
| name* | The name of the rule. | `"ABC Custom Detection 1"` |
| category* | The category of the rule. | `"Posture:Anomalous Activity"` |
| query_signature* | The IQL query for the rule. | `"src.internal=true and dst.ip=10.1.1.100 and port!=80"` |
| description* | A description for the rule. | `"Traffic on unexpected ports to internal asset"` |
| severity* | The severity of the rule. | `high` |
| confidence* | The confidence of the rule. | `high` |
| run_account_uuids* | Account UUIDs on which this rule will run. This will usually be just your own account UUID. (separate multiple accounts by comma) | `0a7dae9g-6f74-4c75-78ef-856483763e1d4` |
| auto_resolution_minutes | The number of minutes after which detections will be auto-resolved. If 0 then detections have to be manually resolved. | `30240` |

*Denotes a required argument

### Insight-get-entity-summary

Get summary information about an IP or domain.

Example Command
`!insight-get-entity-summary entity=8.8.8.8`
#### Arguments

| Name | Description | Example |
| ---- | ----------- | ------- |
| entity* | IP or domain to get entity data for. | `8.8.8.8` |

*Denotes a required argument

### Insight-get-entity-pdns

Get passive DNS information about an IP or domain.

Example Command
`!insight-get-entity-pdns entity=google.com`
#### Arguments

| Name | Description | Example |
| ---- | ----------- | ------- |
| entity* | IP or domain to get passive DNS data for. | `google.com` |

*Denotes a required argument

### Insight-get-entity-dhcp

Get DHCP information about an IP or domain.

Example Command
`!insight-get-entity-dhcp entity=10.1.2.3`
#### Arguments

| Name | Description | Example |
| ---- | ----------- | ------- |
| entity* | IP or domain to get DHCP data for. | `10.1.2.3` |

*Denotes a required argument

### Insight-get-entity-file

Get entity information about a file

Example Command
`!insight-get-entity-file hash=2b7a609371b2a844181c2f79f1b45cf7`
#### Arguments

| Name | Description | Example |
| ---- | ----------- | ------- |
| hash* | File hash. Can be an MD5, SHA1, or SHA256 hash of the file | `2b7a609371b2a844181c2f79f1b45cf7` |

*Denotes a required argument
