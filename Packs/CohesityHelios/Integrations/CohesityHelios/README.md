Integrate with Cohesity Helios services to fetch alerts and take remedial action.
This integration was integrated and tested with version 08.01 of CohesityHelios.

## Configure CohesityHelios on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CohesityHelios.
3. Click **Add instance** to create and configure a new integration instance.

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

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cohesity-helios-get-ransomware-alerts
***
Get Cohesity Helios ransomware Alerts command.


#### Base Command

`cohesity-helios-get-ransomware-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| created_after | Returns only alerts created after the provided timestamp (ISO8601 format YYYY-MM-DDTHH:MM:SSZ). | Optional | 
| created_before | Returns only alerts created before the provided timestamp (ISO8601 format YYYY-MM-DDTHH:MM:SSZ). | Optional | 
| limit | Limits the number of alerts to return. Default is 20. | Optional | 
| alert_id_list | List of comma-separated alert ids to filter alerts. | Optional | 
| cluster_identifiers | List of comma-separated cluster identifiers to filter alerts. | Optional | 
| region_ids | List of comma-separated region identifiers to filter alerts. | Optional | 
| alert_severity_list | List of comma separted alert severities filter. Possible values are: kCritical, kWarning, kInfo. Default is kCritical. | Optional | 


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
```!cohesity-helios-get-ransomware-alerts created_after=2021-09-21T created_before=2021-09-25T limit=2 alert_severity_list=kCritical,kInfo```

#### Context Example
```json
{
    "CohesityHelios": {
        "RansomwareAlert": [
            {
                "alert_cause": "The recent protection run of Protection Group testSimJob98LLwith job id 20548 has dramatic changes in the composition of files, which is a significant deviation from the previously observed protection runs",
                "alert_description": "Anomalous change in file system detected on pankajk-ubuntu18-04, a symptom of potential ransomware attack on your primary environment",
                "alert_id": "8757180793808645:1632484721485079",
                "anomalous_object_env": "kVMware",
                "anomalous_object_name": "pankajk-ubuntu18-04",
                "anomaly_strength": "86",
                "occurrence_time": "2021-09-24T11:58:41Z",
                "severity": "kCritical"
            },
            {
                "alert_cause": "The recent protection run of Protection Group testSimJobGLW3with job id 20536 has dramatic changes in the composition of files, which is a significant deviation from the previously observed protection runs",
                "alert_description": "Anomalous change in file system detected on pankajk-ubuntu18-03, a symptom of potential ransomware attack on your primary environment",
                "alert_id": "2810156198598750:1632484334435401",
                "anomalous_object_env": "kVMware",
                "anomalous_object_name": "pankajk-ubuntu18-03",
                "anomaly_strength": "88",
                "occurrence_time": "2021-09-24T11:52:14Z",
                "severity": "kCritical"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|alert_cause|alert_description|alert_id|anomalous_object_env|anomalous_object_name|anomaly_strength|occurrence_time|severity|
>|---|---|---|---|---|---|---|---|
>| The recent protection run of Protection Group testSimJob98LLwith job id 20548 has dramatic changes in the composition of files, which is a significant deviation from the previously observed protection runs | Anomalous change in file system detected on pankajk-ubuntu18-04, a symptom of potential ransomware attack on your primary environment | 8757180793808645:1632484721485079 | kVMware | pankajk-ubuntu18-04 | 86 | 2021-09-24T11:58:41Z | kCritical |
>| The recent protection run of Protection Group testSimJobGLW3with job id 20536 has dramatic changes in the composition of files, which is a significant deviation from the previously observed protection runs | Anomalous change in file system detected on pankajk-ubuntu18-03, a symptom of potential ransomware attack on your primary environment | 2810156198598750:1632484334435401 | kVMware | pankajk-ubuntu18-03 | 88 | 2021-09-24T11:52:14Z | kCritical |


### cohesity-helios-ignore-anomalous-object
***
Ignore detected anomalous object.


#### Base Command

`cohesity-helios-ignore-anomalous-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_name | Anomalous object name to be ignored. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cohesity-helios-ignore-anomalous-object  object_name=pankajk-ubuntu18-02```

#### Human Readable Output

>Ignored object pankajk-ubuntu18-02

### cohesity-helios-restore-latest-clean-snapshot
***
Restore latest clean snapshot for given object.


#### Base Command

`cohesity-helios-restore-latest-clean-snapshot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_name | Anomalous object name to be restored. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cohesity-helios-restore-latest-clean-snapshot  object_name=pankajk-ubuntu18-02```

#### Human Readable Output

>Restored object pankajk-ubuntu18-02
