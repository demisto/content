Concentric’s Semantic Intelligence™ solution discovers and protects business critical, unstructured data. We use deep learning to identify risky sharing, inappropriate third party access, assets in the wrong location, mis-classified documents, or lateral movement of data – all without rules or complex upfront configuration.

## Configure ConcentricAI in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Minimum severity of alerts to fetch |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Client ID |  | False |
| Client Secret |  | False |
| Domain |  | False |
| Maximum no. of incidents to fetch. | max -&amp;gt; 200 | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| First Fetch Time of Risks |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### concentricai-get-file-details

***
Get's file information

#### Base Command

`concentricai-get-file-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | Path of the file. | Required | 
| file-name | Name of File. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ConcentricAI.FileInfo.risk_names | String | Risk names. | 
| ConcentricAI.FileInfo.ownerDetails | String | owner Details. | 
| ConcentricAI.FileInfo.pii | String | PII present in file or not | 
| ConcentricAI.FileInfo.cid | String | File ID | 

### concentricai-get-users-overview

***
Get overview of Users involved

#### Base Command

`concentricai-get-users-overview`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_users | Maximum no. of users fetched per category. Default is 50. | Optional | 

#### Context Output

There is no context output for this command.
### concentricai-get-user-details

***
Get's user details

#### Base Command

`concentricai-get-user-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | Enter user name. | Required | 

#### Context Output

There is no context output for this command.
### concentricai-get-file-sharing-details

***
Get's file sharing details

#### Base Command

`concentricai-get-file-sharing-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cid | File ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ConcentricAI.FileSharingInfo.type | Array | Sharing type. | 
| ConcentricAI.FileSharingInfo.user_name | Array | User name. | 