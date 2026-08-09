Integrate with Cohesity Helios services to fetch alerts and take remedial action.
This integration was integrated and tested with version 08.01 of CohesityHelios.

## Configure CohesityHelios in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| API Key | The API Key to use for connection | True |
| Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
| Use system proxy settings | Use system proxy settings. | False |
| Incident type |  | False |
| Maximum number of incidents to fetch every time |  | True |
| First fetch timestamp |  | False |
| Fetch incidents |  | False |
| Incidents Fetch Interval |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cohesity-helios-get-ransomware-alerts

***
Get Cohesity Helios ransomware alerts.

#### Base Command

`cohesity-helios-get-ransomware-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| created_after | Returns only alerts created after the provided timestamp (ISO8601 format YYYY-MM-DDTHH:MM:SSZ). | Optional |
| created_before | Returns only alerts created before the provided timestamp (ISO8601 format YYYY-MM-DDTHH:MM:SSZ). | Optional |
| limit | Limits the number of alerts to return. Default is 200. | Optional |
| alert_id_list | List of comma-separated alert identifiers to filter alerts. | Optional |
| cluster_id_list | List of comma-separated cluster identifiers to filter alerts. | Optional |
| region_id_list | List of comma-separated region identifiers to filter alerts. | Optional |
| alert_state_list | One or more state values. Possible values are: kOpen, kSuppressed, kResolved, kNote. Default is kOpen. | Optional |
| alert_severity_list | One or more severity levels. Possible values are: kCritical, kWarning, kInfo. Default is kCritical,kWarning. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CohesityHelios.RansomwareAlert.alert_id | String | The identifier for the ransomware alert. |
| CohesityHelios.RansomwareAlert.occurrence_time | Date | The timestamp when the alert occurred \(for example, 2020-01-01T00:11:22Z\). |
| CohesityHelios.RansomwareAlert.severity | String | The severity of the ransomware alert. |
| CohesityHelios.RansomwareAlert.alert_description | String | The description for the ransomware alert. |
| CohesityHelios.RansomwareAlert.alert_cause | String | The cause for the ransomware alert. |
| CohesityHelios.RansomwareAlert.cluster_id | Number | The cluster ID where the alert originated. |
| CohesityHelios.RansomwareAlert.cluster_name | String | The cluster name where the alert originated. |
| CohesityHelios.RansomwareAlert.entity_id | String | The entity ID \(object ID\) from the alert propertyList. |
| CohesityHelios.RansomwareAlert.job_id | String | The job ID from the alert propertyList. |

### cohesity-helios-ignore-anomalous-object

***
Ignore detected anomalous object by suppressing the alert.

#### Base Command

`cohesity-helios-ignore-anomalous-object`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID to suppress. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!cohesity-helios-ignore-anomalous-object alert_id=9346668452014081:1632849269030240```

#### Human Readable Output

>Ignored alert 9346668452014081:1632849269030240.

### cohesity-helios-restore-latest-clean-snapshot

***
Restore the latest clean snapshot for the given object using incidence details.

#### Base Command

`cohesity-helios-restore-latest-clean-snapshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID to restore the latest clean snapshot for. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!cohesity-helios-restore-latest-clean-snapshot alert_id=2122491972847952:1632848348897740```

#### Human Readable Output

>Restored vm-ubuntu-05 \(id=object-1002\) from latest clean snapshot.
