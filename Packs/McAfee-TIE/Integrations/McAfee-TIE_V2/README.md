Use the McAfee Threat Intelligence Exchange (TIE) integration to get file reputations and the systems that reference the files.
Connect to McAfee TIE using the McAfee DXL client.
This integration was integrated and tested with version 2.0 of McAfee Threat Intelligence Exchange V2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-mcafee-threat-intelligence-exchange-v2).
## Changes compared to V1
# Changes in commands
1. You can now pass more than one file to the commands `tie-set-file-reputation`, and `tie-file-references`.
2. The code is now python 3 compatible.
3. Added additional context outputs to all three commands.

## Detailed Instructions
This section includes information required for configuring an integration instance.
### <a name="prerequisites"></a>Prerequisites - Connect to McAfee Threat Intelligence Exchange (TIE) using the DXL TIE Client
To connect the McAfee TIE using the DXL TIE client, you need to create certificates and configure DXL. For more information, see the [documentation](https://xsoar.pan.dev/docs/reference/integrations/mc-afee-dxl#how-to-create-the-rsa-key-pair). After you complete this configuration, you will have the following files:
1. Broker CA certificates (`brokercerts.crt` file)
2. Client certificate (`client.crt` file)
3. Client private key (`client.key` file)
4. Broker list properties file (`brokerlist.properties` file)

<a name="set-file-instruction"></a>To use the `tie-set-file-reputation` command, you need to authorize the client (Demisto) to run the command. Follow the [instructions](https://xsoar.pan.dev/docs/reference/integrations/mc-afee-dxl#how-to-create-the-rsa-key-pair) to do so. In step #4, instead of selecting **Active Response Server API**, select **TIE Server Set Enterprise Reputation**.

### Dependencies (Python packages)
You don't need to install the packages, they are included in the Docker image.
  - DXL Client [documentation](https://opendxl.github.io/opendxl-client-python/pydoc/dxlclient.client.html)
  - DXL TIE Client [documentation](https://opendxl.github.io/opendxl-tie-client-python/pydoc/dxltieclient.client.html)
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
| DBotScore.Reliability | String | How reliable the score is \(for example, "C - fairly reliable"\). | 
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

### Command Example
`!file file=f2c7bb8acc97f92e987a2d4087d021b1,7eb0139d2175739b3ccb0d1110067820be6abd29`

#### Context Example
```json

```

#### Human Readable Output
### McAfee TIE Hash Reputations For f2c7bb8acc97f92e987a2d4087d021b1:
|Created date|Provider (verbose)|Provider ID|Trust level|Trust level (verbose)|
|---|---|---|---|---|
| 2017-10-15 18:33:20 | Global Threat Intelligence (GTI) | 1 | 99 | KNOWN_TRUSTED |
| 2017-10-15 18:33:20 | Enterprise reputation | 3 | 85 | MOST_LIKELY_TRUSTED |

### McAfee TIE Hash Reputations For 7eb0139d2175739b3ccb0d1110067820be6abd29:
|Created date|Provider (verbose)|Provider ID|Trust level|Trust level (verbose)|
|---|---|---|---|---|
| 2017-10-15 19:30:54 | Enterprise reputation | 3 | 1 | KNOWN_MALICIOUS |
| 2018-06-04 16:31:02 | Global Threat Intelligence (GTI) | 1 | 99 | KNOWN_TRUSTED |

### tie-set-file-reputation
***
Sets the “Enterprise” reputation (trust level, filename, and comment) of the specified hashes. Hashes that represent the same file can have a different "Enterprise" reputation if they are given different reputations. Permissions are required to invoke this method. See the [instruction](#set-file-instruction) section.

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

### Command Example
```!tie-set-file-reputation file=f2c7bb8acc97f92e987a2d4087d021b1,7eb0139d2175739b3ccb0d1110067820be6abd29 trust_level=MOST_LIKELY_TRUSTED comment="For testing" filename="tesing.exe"```

#### Human Readable Output
Successfully set files reputation

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

### Command Example
`!tie-file-references file=f2c7bb8acc97f92e987a2d4087d021b1,7eb0139d2175739b3ccb0d1110067820be6abd29 query_limit=5`

#### Context Example
```json

```

#### Human Readable Output
### References For Hash f2c7bb8acc97f92e987a2d4087d021b1:
|AgentGuid|Date|
|---|---|
| 0c906be0-224c-45d4-8e6f-bc89da69d268 | 2017-10-15 18:33:20 |
| 70be2ee9-7166-413b-b03e-64a48f6ab6c8 | 2017-10-15 18:34:11 |
| c21b8995-9c5a-412c-b727-c4284d42380a | 2017-10-15 19:30:48 |
| 24e0e935-2241-47d7-822b-20dfe0fe86de | 2017-10-15 19:30:49 |
| e50a8b51-2063-42cb-a85f-10bd0a698323 | 2017-10-15 19:30:51 |

### References For Hash 7eb0139d2175739b3ccb0d1110067820be6abd29:
|AgentGuid|Date|
|---|---|
| 157eaf84-88ab-4d95-9456-30878fded9d5 | 2017-10-15 19:30:54 |
| 0bbcd439-aaed-4931-b9f4-b37e4a49b980 | 2017-10-16 16:28:43 |
| f87fb2c3-2032-4fc5-a54f-7d36b441a122 | 2017-10-16 16:28:46 |
| 33b05a2e-6bb2-46c2-998f-893668c46402 | 2017-10-16 17:12:17 |
| 99ed15bb-ebc5-4b48-9a4d-5ad1b30abaac | 2017-10-16 17:14:36 |

<!-- ## Breaking changes from the previous version of this integration - McAfee Threat Intelligence Exchange V2
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
* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version. -->
