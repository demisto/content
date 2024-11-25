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
| CohesityHelios.RansomwareAlert.occurrence_time | Date | Name of the detected anomalous object. | 
| CohesityHelios.RansomwareAlert.severity | String | Severity of the ransomware alert. | 
| CohesityHelios.RansomwareAlert.alert_description | String | Description for the ransomware alert. | 
| CohesityHelios.RansomwareAlert.alert_cause | String | Cause for the ransomware alert. | 
| CohesityHelios.RansomwareAlert.anomalous_object_name | String | Name of the detected anomalous object. | 
| CohesityHelios.RansomwareAlert.anomalous_object_env | String | Env of the detected anomalous object. | 
| CohesityHelios.RansomwareAlert.anomaly_strength | Number | Strength of the detected ransomware alert. | 


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
                "anomalous_object_env": "kVMware",
                "anomalous_object_name": "pankajk-ubuntu18-06",
                "anomaly_strength": "66",
                "occurrence_time": "2021-09-28T17:14:29Z",
                "severity": "kCritical"
            },
            {
                "alert_cause": "The recent protection run of Protection Group testSimJobBTYAwith job id 24229 has dramatic changes in the composition of files, which is a significant deviation from the previously observed protection runs",
                "alert_description": "Anomalous change in file system detected on pankajk-ubuntu18-05, a symptom of potential ransomware attack on your primary environment",
                "alert_id": "2122491972847952:1632848348897740",
                "anomalous_object_env": "kVMware",
                "anomalous_object_name": "pankajk-ubuntu18-05",
                "anomaly_strength": "63",
                "occurrence_time": "2021-09-28T16:59:08Z",
                "severity": "kCritical"
            }
        ]
    }
}
```

#### Human Readable Output

>### Cohesity Helios Ransomware Alerts
>|Alert Id|Alert Description|Alert Cause|Anomalous Object Env|Anomalous Object Name|Anomaly Strength|
>|---|---|---|---|---|---|
>| 9346668452014081:1632849269030240 | Anomalous change in file system detected on pankajk-ubuntu18-06, a symptom of potential ransomware attack on your primary environment | The recent protection run of Protection Group testSimJobCWWMwith job id 24248 has dramatic changes in the composition of files, which is a significant deviation from the previously observed protection runs | kVMware | pankajk-ubuntu18-06 | 66 |
>| 2122491972847952:1632848348897740 | Anomalous change in file system detected on pankajk-ubuntu18-05, a symptom of potential ransomware attack on your primary environment | The recent protection run of Protection Group testSimJobBTYAwith job id 24229 has dramatic changes in the composition of files, which is a significant deviation from the previously observed protection runs | kVMware | pankajk-ubuntu18-05 | 63 |

### cohesity-helios-ignore-anomalous-object
***
Ignore detected anomalous object.


#### Base Command

`cohesity-helios-ignore-anomalous-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_name | Anomalous object name to be ignored. Can be retrieved by running the command cohesity-helios-get-ransomware-alerts. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cohesity-helios-ignore-anomalous-object  object_name=pankajk-ubuntu18-02```

#### Human Readable Output

>Ignored object pankajk-ubuntu18-02


### cohesity-helios-restore-latest-clean-snapshot
***
Restore the latest clean snapshot for the given object.


#### Base Command

`cohesity-helios-restore-latest-clean-snapshot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_name | Anomalous object name to be restored. Can be retrieved by running the command cohesity-helios-get-ransomware-alerts. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cohesity-helios-restore-latest-clean-snapshot  object_name=pankajk-ubuntu18-05```

#### Human Readable Output

>Restored object pankajk-ubuntu18-05.