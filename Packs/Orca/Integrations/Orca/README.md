Agentless, Workload-Deep, Context-Aware Security and Compliance for AWS, Azure, and GCP.
This integration was integrated and tested with Orca
## Configure Orca in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| apitoken | API Token | True |
| api_host | API Host without schema. Default: `api.orcasecurity.io` | False
| first_fetch | First fetch timestamp \(`<number>` `<time unit>`, e.g., 12 hours, 7 days\) | False |
| incidentType | Incident type | False |
| isFetch | Fetch incidents | False |
| max_fetch | Max fetch | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### orca-get-alerts
***
Get the alerts on cloud assets


#### Base Command

`orca-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_type | Type of alert to get. | Optional | 
| asset_unique_id | Get alerts of asset_unique_id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Orca.Manager.Alerts | String | All alerts | 


#### Command Example
``` ```

### orca-get-asset
***
Get Description of An asset


#### Base Command

`orca-get-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_unique_id | Asset unique id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Orca.Manager.Asset | String | Asset description | 


#### Command Example
``` ```

#### Base Command

`orca-set-alert-severity`
#### Input

| **Argument Name** | **Description**                | **Required** |
|-------------------|--------------------------------|--------------|
| alert_id          | Id of the alert.               | Required     | 
| score             | New score value. From 0 to 10. | Required     | 


#### Context Output

| **Path**                      | **Type** | **Description**   |
|-------------------------------| --- |-------------------|
| Orca.Alert    | String | Alert description | 


#### Command Example
``` !orca-set-alert-severity alert_id=orca1 score=5 ```

`orca-get-alert-event-log`
#### Input

| **Argument Name** | **Description**                | **Required** |
|-------------------|--------------------------------|--------------|
| alert_id          | Id of the alert.               | Required     | 
| limit             | Limit of the event logs | Optional     | 
| start_at_index             | Start at index | Optional     | 
| type             | Type of the event logs | Optional     | 


#### Context Output

| **Path**                       | **Type** | **Description**     |
|--------------------------------| --- |---------------------|
| Orca.Manager.EventLog      | String | Event log           | 


#### Command Example
``` !orca-get-alert-event-log alert_id=orca1 limit=10 ```

`orca-set-alert-status`
#### Input

| **Argument Name** | **Description**  | **Required** |
|-------------------|------------------|--------------|
| alert_id          | Id of the alert. | Required     | 
| status            | New alert status | Required     | 


#### Context Output

| **Path**            | **Type** | **Description**  |
|---------------------| --- |------------------|
| Orca.SetAlertStatus | String | Operation result | 


#### Command Example
``` !orca-set-alert-status alert_id=orca1 status=open ```

`orca-verify-alert`
#### Input

| **Argument Name** | **Description**  | **Required** |
|-------------------|------------------|--------------|
| alert_id          | Id of the alert. | Required     | 


#### Context Output

| **Path**         | **Type** | **Description**  |
|------------------| --- |------------------|
| Orca.VerifyAlert | String | Operation result | 


#### Command Example
``` !orca-verify-alert alert_id=orca1 ```

`orca-download-malicious-file`
#### Input

| **Argument Name** | **Description**  | **Required** |
|-------------------|------------------|--------------|
| alert_id          | Id of the alert. | Required     | 


#### Context Output

| **Path**  | **Type** | **Description** |
|-----------| --- |-----------------|
| Orca.File | unknown | Malicious File  | 


#### Command Example
``` !orca-download-malicious-file alert_id=orca1```