This API lets you fetch incidents from Symantec Cloud EDR platform. Take actions such as updating deny list based on sha256 value, quarantine/unquarantine devices, initiate device scan.
This integration was integrated and tested with version xx of Symantec Endpoint Detection and Response - Cloud.

## Configure Symantec Endpoint Detection and Response - Cloud on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Symantec Endpoint Detection and Response - Cloud.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://api.sep.securitycloud.symantec.com) | True |
    | Password | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### symantec-edr-cloud-get-specific-incident

***
Get a specific incident from Symantec EDR Cloud.

#### Base Command

`symantec-edr-cloud-get-specific-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token | Bearer token gained after authenticaiton. | Required | 
| incidentid | Incident id of an incident on the Symantec Cloud EDR. | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-auth

***
Initial authentication to gather bearer token. Bearer token is an essential argument to execute any other command on Symantec EDR Cloud.

#### Base Command

`symantec-edr-cloud-auth`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| authtoken | Authentication token is required argument to get the bearer token. | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-get-devices-using-file-hash

***
Find Devices on the Cloud EDR platform that the queried file hash exists.

#### Base Command

`symantec-edr-cloud-get-devices-using-file-hash`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token | Bearer token. | Required | 
| filehash | File hash to be queried through endpoints. | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-get-file-details

***
Retrieve the details of a file based on hash value.

#### Base Command

`symantec-edr-cloud-get-file-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token | Bearer token. | Required | 
| filehash | SHA256 is of the file to search for. . | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-get-incidents

***
Get incidents from symantec platform based on the provided time range. 

#### Base Command

`symantec-edr-cloud-get-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start date of query. Default is 2024-04-09T14:36:56.938340Z. | Required | 
| end_date | End date of query. Default is  2024-04-19T13:36:56.938206Z. | Required | 
| token | Bearer token. | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-threat-intel-data-related

***
This API provides related IOC information for a given a file. Related IOC values and types (domain,ip,file) with this hash will be returned.

#### Base Command

`symantec-edr-cloud-threat-intel-data-related`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token | Bearer token that must be gathered after authentication. | Required | 
| filehash | File to queried on EDR platform. . | Optional | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-threat-intel-insight

***
This API returns file insight enrichments for given file sha256. Enrichment includes top countries, top industries, last seen, first seen data, reputation and prevalence.

#### Base Command

`symantec-edr-cloud-threat-intel-insight`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filehash | SHA256 is the only valid format. . | Required | 
| token | Bearer token that is gathered after authentication must be entered. | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-threat-intel-process-chain

***
The Process Chain API provides top K sha256 lineages along with their process names for provided sha256. The lineage information contains all the ancestors as well as descendants. The top K sha256 lineages are ordered and ranked based on the number of occurrences across Symantec's global telemetry.

#### Base Command

`symantec-edr-cloud-threat-intel-process-chain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filehash | SHA256 is the only valid format. | Required | 
| token | Bearer token that is gathered after authentication must be entered. | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-threat-intel-protection-file

***
The Protection APIs provide information whether a given file has been blocked by any of Symantec technologies. These technologies include Antivirus (AV), Intrusion Prevention System (IPS) and Behavioral Analysis & System Heuristics (BASH).

#### Base Command

`symantec-edr-cloud-threat-intel-protection-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filehash | SHA256 is the only valid format. | Required | 
| token | Bearer token that is gathered after authentication must be entered. | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-threat-intel-protection-cve

***
This API returns information whether a given CVE has been blocked by any Symantec technologies.

#### Base Command

`symantec-edr-cloud-threat-intel-protection-cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| CVE | CVE to query through Symantec technology database. | Required | 
| token | Bearer token that is gathered after authentication must be entered. | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-quarantine-device

***
This API lets you quarantine devices managed by your Integrate Cyber Defense Manager.

#### Base Command

`symantec-edr-cloud-quarantine-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| deviceid | The id of the device that will be quarantined. Default is -1sHc2_IQnCc3Hq2WN3_ow. | Required | 
| token | Bearer token. | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-get-devices

***
This API lets you retrieve the list of devices.

#### Base Command

`symantec-edr-cloud-get-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token | Bearer token that will be gathered after authentication. | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-unquarantine-device

***
This API lets you unquarantine devices managed by your Integrate Cyber Defense Manager.

#### Base Command

`symantec-edr-cloud-unquarantine-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token | Bearer token. | Required | 
| deviceid | The id of the device that will be quarantined. | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-get-policies

***
This API lets you retrieve a list of your policies.

#### Base Command

`symantec-edr-cloud-get-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token | Bearer token. | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-update-deny-list-policy

***
This API lets you perform update of Deny list policy. Target updated policy to apply new changes.

#### Base Command

`symantec-edr-cloud-update-deny-list-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_uid | Policy uid which is to be patched. | Required | 
| token | Bearer token. | Required | 
| sha256 | Sha256 of the file that will be added to the deny list. | Required | 
| policy_version | Policy version. | Required | 
| filename | The filename. | Required | 

#### Context Output

There is no context output for this command.
### symantec-edr-cloud-scan-device

***
This API lets you initiate a full scan on devices managed by your Integrated Cyber Defense Manager.

#### Base Command

`symantec-edr-cloud-scan-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token | Bearer token. | Required | 
| deviceid | The id of the device that will be scanned on Symantec EDR Cloud platform. | Required | 

#### Context Output

There is no context output for this command.
