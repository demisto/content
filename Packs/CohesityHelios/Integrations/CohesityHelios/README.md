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
| CohesityHelios.RansomwareAlert.alert_id | String | Identifier for the ransomware alert. |
| CohesityHelios.RansomwareAlert.occurrence_time | Date | Timestamp when the alert occurred. |
| CohesityHelios.RansomwareAlert.severity | String | Severity of the ransomware alert. |
| CohesityHelios.RansomwareAlert.alert_description | String | Description for the ransomware alert. |
| CohesityHelios.RansomwareAlert.alert_cause | String | Cause for the ransomware alert. |
| CohesityHelios.RansomwareAlert.cluster_id | Number | Cluster ID where the alert originated. |
| CohesityHelios.RansomwareAlert.cluster_name | String | Cluster name where the alert originated. |
| CohesityHelios.RansomwareAlert.entity_id | String | Entity ID \(object ID\) from the alert propertyList. |
| CohesityHelios.RansomwareAlert.job_id | String | Job ID from the alert propertyList. |

#### Command Example

```!cohesity-helios-get-ransomware-alerts created_after=2021-09-26T created_before=2021-09-230T limit=2 alert_severity_list=kCritical,kInfo```

#### Context Example

```json
{
    "CohesityHelios": {
        "RansomwareAlert": [
            {
                "alert_cause": "The recent protection run of Protection Group testSimJobCWWMwith job id 24248 has dramatic changes in the composition of files, which is a significant deviation from the previously observed protection runs",
                "alert_description": "Anomalous change in file system detected on pankajk-ubuntu18-06, a symptom of potential ransomware attack on your primary environment",
                "alert_id": "9346668452014081:1632849269030240",
                "cluster_id": 12345678,
                "cluster_name": "cluster-primary",
                "entity_id": "object-1001",
                "job_id": "24248",
                "occurrence_time": "2021-09-28T17:14:29Z",
                "severity": "kCritical"
            },
            {
                "alert_cause": "The recent protection run of Protection Group testSimJobBTYAwith job id 24229 has dramatic changes in the composition of files, which is a significant deviation from the previously observed protection runs",
                "alert_description": "Anomalous change in file system detected on pankajk-ubuntu18-05, a symptom of potential ransomware attack on your primary environment",
                "alert_id": "2122491972847952:1632848348897740",
                "cluster_id": 12345678,
                "cluster_name": "cluster-primary",
                "entity_id": "object-1002",
                "job_id": "24229",
                "occurrence_time": "2021-09-28T16:59:08Z",
                "severity": "kCritical"
            }
        ]
    }
}
```

#### Human Readable Output

>### Cohesity Helios Ransomware Alerts
>
>|Alert Id|Severity|Cluster Name|Entity Id|Alert Description|Alert Cause|
>|---|---|---|---|---|---|
>| 9346668452014081:1632849269030240 | kCritical | cluster-primary | object-1001 | Anomalous change in file system detected on pankajk-ubuntu18-06, a symptom of potential ransomware attack on your primary environment | The recent protection run of Protection Group testSimJobCWWMwith job id 24248 has dramatic changes in the composition of files, which is a significant deviation from the previously observed protection runs |
>| 2122491972847952:1632848348897740 | kCritical | cluster-primary | object-1002 | Anomalous change in file system detected on pankajk-ubuntu18-05, a symptom of potential ransomware attack on your primary environment | The recent protection run of Protection Group testSimJobBTYAwith job id 24229 has dramatic changes in the composition of files, which is a significant deviation from the previously observed protection runs |

### cohesity-helios-ignore-anomalous-object

***
Ignore detected anomalous object by suppressing the alert.

#### Base Command

`cohesity-helios-ignore-anomalous-object`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID to suppress. | Optional |

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
| alert_id | The alert ID to restore the latest clean snapshot for. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!cohesity-helios-restore-latest-clean-snapshot alert_id=2122491972847952:1632848348897740```

#### Human Readable Output

>Restored vm-ubuntu-05 \(id=object-1002\) from latest clean snapshot.
