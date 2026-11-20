Pushes Cortex XSOAR 6 or Cortex XSOAR 8 incidents to Cortex XSIAM as parsed alerts using the Insert Parsed Alerts API.

## Configure Xporter in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Cortex XSOAR Server URL | The URL of the Cortex XSOAR server. For XSOAR 6 use the server IP/hostname \(e.g., https://192.168.1.215\). For XSOAR 8 use the API URL \(e.g., https://api-\{tenant\}.xdr.us.paloaltonetworks.com\). | True |
| Cortex XSOAR API Key |  | True |
| Cortex XSOAR API Key ID (XSOAR 8 only) | Required for Cortex XSOAR 8. Leave blank for XSOAR 6. The numeric API Key ID from XSOAR 8 Settings &gt; API Keys. | False |
| Cortex XSIAM API URL | The Cortex XSIAM API URL \(e.g., https://api-\{tenant\}.xdr.us.paloaltonetworks.com\). | True |
| Cortex XSIAM API Key |  | True |
| Cortex XSIAM API Key ID | The numeric API Key ID from Cortex XSIAM Settings &gt; API Keys. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Maximum incidents per push | The maximum number of incidents to push in a single command execution. | False |
| Incident query filter | A Cortex XSOAR incident query to filter which incidents to push \(e.g., type:Phishing\). | False |
| Elevate Low severity to Medium | Whether to map Low severity incidents to Medium so they create cases in Cortex XSIAM instead of issues. Only Medium or higher severity alerts automatically trigger playbooks. | False |
| Timestamp offset (minutes) | Minutes to add to the original Cortex XSOAR incident timestamp. The event timestamp defaults to the Cortex XSOAR occurred/created time. Use a positive offset to shift forward. Cortex XSIAM drops alerts with timestamps too far in the past. | False |
| Sync War Room entries on push | Whether to automatically sync War Room entries from Cortex XSOAR to the matching Cortex XSIAM issue when pushing incidents. Entries are deduplicated so re-pushes do not create duplicates. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### xsoar-exporter-push-incidents

***
Pushes Cortex XSOAR incidents matching a query to Cortex XSIAM as parsed alerts.

#### Base Command

`xsoar-exporter-push-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The incident query filter to override the configured one. | Optional |
| max_incidents | The maximum number of incidents to push. | Optional |
| from_date | The start date for incident search in ISO 8601 format (e.g., 2024-01-01T00:00:00Z). | Optional |
| to_date | The end date for incident search in ISO 8601 format (e.g., 2024-01-01T00:00:00Z). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XSOARExporter.Push.PushedCount | Number | The number of incidents pushed. |
| XSOARExporter.Push.Incidents | Unknown | The list of pushed incident IDs and names. |

### xsoar-exporter-push-incident

***
Pushes a single Cortex XSOAR incident to Cortex XSIAM as a parsed alert.

#### Base Command

`xsoar-exporter-push-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The Cortex XSOAR incident ID to push. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XSOARExporter.Push.PushedIncident | Unknown | The details of the pushed incident. |

### xsoar-exporter-sync-new-incidents

***
Finds and pushes only new Cortex XSOAR incidents that have not been synced yet.

#### Base Command

`xsoar-exporter-sync-new-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The incident query filter to override the configured one. | Optional |
| max_incidents | The maximum number of incidents to sync. | Optional |
| from_date | The sync timestamp override in ISO 8601 format (e.g., 2024-01-01T00:00:00Z). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XSOARExporter.Sync.SyncedCount | Number | The number of new incidents synced. |
| XSOARExporter.Sync.Incidents | Unknown | The list of synced incident IDs and names. |
| XSOARExporter.Sync.LastSyncedID | Number | The highest incident ID that has been synced. |

### xsoar-exporter-reset-sync

***
Resets the sync state so the next sync will send all incidents.

#### Base Command

`xsoar-exporter-reset-sync`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### xsoar-exporter-sync-close-status

***
Queries Cortex XSIAM for open XSOAR-sourced alerts and resolves those whose XSOAR incidents are closed.

#### Base Command

`xsoar-exporter-sync-close-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_alerts | The maximum number of alerts to process per run. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XSOARExporter.CloseSync.ClosedCount | Number | The number of alerts closed. |
| XSOARExporter.CloseSync.SkippedCount | Number | The number of open alerts skipped. |
| XSOARExporter.CloseSync.ClosedAlerts | Unknown | The details of closed alerts. |

### xsoar-exporter-sync-war-room

***
Syncs War Room entries from a Cortex XSOAR incident to the matching Cortex XSIAM issue.

#### Base Command

`xsoar-exporter-sync-war-room`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The Cortex XSOAR incident ID whose War Room entries to sync. | Required |
| xsiam_alert_id | The Cortex XSIAM alert external ID to sync entries to. If not provided, automatically looks up the matching alert by Cortex XSOAR incident ID. | Optional |
| categories | A comma-separated list of War Room entry categories to sync. If not provided, all non-empty entries are synced. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XSOARExporter.WarRoom.IncidentID | String | The Cortex XSOAR incident ID. |
| XSOARExporter.WarRoom.XSIAMAlertID | String | The Cortex XSIAM alert ID entries were synced to. |
| XSOARExporter.WarRoom.SyncedCount | Number | The number of War Room entries synced. |
| XSOARExporter.WarRoom.SkippedCount | Number | The number of entries skipped because they were already synced. |
| XSOARExporter.WarRoom.ErrorCount | Number | The number of entries that failed to sync. |
| XSOARExporter.WarRoom.TotalEntries | Number | The total number of War Room entries in the Cortex XSOAR incident. |
| XSOARExporter.WarRoom.FilteredEntries | Number | The number of entries after filtering empty and category filters. |

#### Command example

```!xsoar-exporter-sync-war-room incident_id="100"```

#### Context Example

```json
{
    "XSOARExporter": {
        "WarRoom": {
            "ErrorCount": 0,
            "FilteredEntries": 3,
            "IncidentID": "100",
            "SkippedCount": 0,
            "SyncedCount": 3,
            "TotalEntries": 5,
            "XSIAMAlertID": "199895"
        }
    }
}
```

#### Human Readable Output

>### Synced 3 War Room entries from XSOAR incident 100 to XSIAM alert 199895
