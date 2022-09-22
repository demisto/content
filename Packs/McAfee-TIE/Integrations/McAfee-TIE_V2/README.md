Connect to McAfee TIE using the McAfee DXL client.
This integration was integrated and tested with version xx of McAfee Threat Intelligence Exchange V2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-mcafee-threat-intelligence-exchange-v2).

## Configure McAfee Threat Intelligence Exchange V2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for McAfee Threat Intelligence Exchange V2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Broker CA certificates | From \`brokercerts.crt\` file. | True |
    | Client certificates | From \`client.crt\` file. | True |
    | Client private key | From \`client.key\` file. Make sure that the type of the field is not \`encrypted\` when filling it out. | True |
    | Broker URLs | The format should be: \[ssl://\]&amp;lt;hostname&amp;gt;\[:port\]. Get the hostname and port from the \`brokerlist.properties\` file. The broker should be reachable from Demisto server. | True |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |
    |  |  | False |
    |  |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### file
***
Retrieves the reputations for the specified hashes. Can be "MD5", "SHA1", or "SHA256".


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hashes of the files to query. Supports "MD5", "SHA1", and "SHA256". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Hashes.type | String | The type of the hash. | 
| File.Hashes.value | String | The value of the hash. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| File.Malicious.Description | Number | A description of why this file was found malicious. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | unknown | How reliable the score is \(for example, "C - fairly reliable"\). | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| McAfee.TIE.FilesReputations.Reputations.Hash | String | The value of the hash. | 
| McAfee.TIE.FilesReputations.Reputations.GTI.Provider_ID | Number | The identifier of the particular provider that provided the reputation. | 
| McAfee.TIE.FilesReputations.Reputations.GTI.Trust_Level | Number | The trust level for the reputation subject. | 
| McAfee.TIE.FilesReputations.Reputations.GTI.Create_Date | String | The time this reputation was created. | 
| McAfee.TIE.FilesReputations.Reputations.GTI.Provider | String | The name of the particular provider that provided the reputation. | 
| McAfee.TIE.FilesReputations.Reputations.GTI.Original_Response | String | The raw response as returned by the Global Threat Intelligence \(GTI\) reputation provider. | 
| McAfee.TIE.FilesReputations.Reputations.GTI.First_Contact | String | The time the file was first seen. | 
| McAfee.TIE.FilesReputations.Reputations.GTI.PREVALENCE | String | The number of times the file has been requested. | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Provider_ID | Number | The identifier of the particular provider that provided the reputation. | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Trust_Level | Number | The trust level for the reputation subject. | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Create_Date | String | The time this reputation was created. | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Provider | String | The name of the particular provider that provided the reputation. | 
| McAfee.TIE.FilesReputations.Reputations.ATD.GAM_Score | String | The trust score reported by the Gateway Anti-Malware \(GAM\). | 
| McAfee.TIE.FilesReputations.Reputations.ATD.AV_Engine_Score | String | The trust score reported by the Anti-Virus engine. | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Sandbox_Score | String | The trust score as a result of the sandbox evaluation. | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Verdict | String | The overall verdict \(taking into consideration all available information\). | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Behaviors | String | An encoded structure that contains observed behaviors of the file. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Provider_ID | Number | The identifier of the particular provider that provided the reputation. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Trust_Level | Number | The trust level for the reputation subject. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Create_Date | String | The time this reputation was created. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Provider | String | The name of the particular provider that provided the reputation. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Server_Version | String | The version of the TIE server that returned the reputations \(encoded version string\). | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.First_Contact | String | The time the file was first seen. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Prevalence | String | The count of unique systems that have executed the file. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Enterprise_Size | String | The count of systems within the local enterprise. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Min_Local_Rep | String | The lowest reputation found locally on a system. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Max_Local_Rep | String | The highest reputation found locally on a system. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Avg_Local_Rep | String | The average reputation found locally on systems. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Parent_Min_Local_Rep | String | The lowest reputation for the parent found locally on a system. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Parent_Max_Local_Rep | String | The highest reputation for the parent found locally on a system. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Parent_Avg_Local_Rep | String | The average reputation for the parent found locally on systems. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.File_Name_Count | String | The count of unique file names for the file. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Detection_Count | String | The count of detections for the file or certificate. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Last_Detection_Time | String | The last time a detection occurred. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Is_Prevalent | String | Whether the file is considered to be prevalent within the enterprise. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Child_File_Reps | String | The child file reputations \(aggregate string\) according to the following format: - The count of files - The maximum trust level found across the files - The minimum trust level found across the files - The trust level for the last file - The average trust level across the files | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Parent_File_Reps | String | The parent file reputations \(aggregate string\) according to the following format: - The count of files - The maximum trust level found across the files - The minimum trust level found across the files - The trust level for the last file - The average trust level across the files | 

### tie-set-file-reputation
***
Sets the “Enterprise” reputation (trust level, filename, and comment) of the specified hashes. Hashes that represent the same file can have a different "Enterprise" reputation if they are given different reputations. Permissions are required to invoke this method. See the 'How-to' in instance instruction.


#### Base Command

`tie-set-file-reputation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hashes of the files for which to set the reputation. Can be "MD5", "SHA1", or "SHA256". | Required | 
| trust_level | The new trust level for the files. Possible values are: NOT_SET, KNOWN_MALICIOUS, MOST_LIKELY_MALICIOUS, MIGHT_BE_MALICIOUS, UNKNOWN, MIGHT_BE_TRUSTED, MOST_LIKELY_TRUSTED, KNOWN_TRUSTED, KNOWN_TRUSTED_INSTALLER. | Required | 
| filename | A file name to associate with the specified files. | Optional | 
| comment | A comment to associate with the specified files. | Optional | 


#### Context Output

There is no context output for this command.
### tie-file-references
***
Retrieves the set of systems which have referenced (typically executed) the specified hashes.


#### Base Command

`tie-file-references`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hashes of the files for which to search. Can be "MD5", "SHA1", or "SHA256". | Required | 
| query_limit | The maximum number of results to return. The default and maximum number is 500 results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Hashes.type | String | The type of the hash. | 
| File.Hashes.value | String | The value of the hash. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| McAfee.TIE.FilesReferences.References.AgentGuid | String | The GUID of the system that referenced the file. | 
| McAfee.TIE.FilesReferences.References.Date | String | The time the system first referenced the file. | 
| McAfee.TIE.FilesReferences.Hash | String | The value of the hash. | 

## Breaking changes from the previous version of this integration - McAfee Threat Intelligence Exchange V2
%%FILL HERE%%
The following sections list the changes in this version.


### Outputs
#### The following outputs were removed in this version:

In the *file* command:
* *File.TrustLevel* - this output was replaced by XXX.
* *File.Vendor* - this output was replaced by XXX.
* *File.Malicious.Score* - this output was replaced by XXX.

In the *tie-file-references* command:
* *File.References.AgentGuid* - this output was replaced by XXX.
* *File.References.Date* - this output was replaced by XXX.

## Additional Considerations for this version
%%FILL HERE%%
* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.
