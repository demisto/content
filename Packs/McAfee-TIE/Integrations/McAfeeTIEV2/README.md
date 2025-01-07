Use the McAfee Threat Intelligence Exchange (TIE) integration to get file reputations and the systems that reference the files.
Connect to McAfee TIE using the McAfee DXL client.
This integration was integrated and tested with version 2.0 of McAfee Threat Intelligence Exchange V2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes).


## Detailed Instructions
This section includes information required for configuring an integration instance.
### Prerequisites - Connect to McAfee Threat Intelligence Exchange (TIE) using the DXL TIE Client
To connect the McAfee TIE using the DXL TIE client, you need to create certificates and configure DXL. For more information, see the [documentation](https://xsoar.pan.dev/docs/reference/integrations/mc-afee-dxl#how-to-create-the-rsa-key-pair). After you complete this configuration, you will have the following files:
1. Broker CA certificates (`brokercerts.crt` file)
2. Client certificate (`client.crt` file)
3. Client private key (`client.key` file)
4. Broker list properties file (`brokerlist.properties` file)

**Important**: These are the actual certificates, not request certificates.

### set-file instruction
To use the ***tie-set-file-reputation*** command, you need to authorize the client (Cortex XSOAR) to run the command. Follow the [instructions](https://opendxl.github.io/opendxl-client-python/pydoc/marsendauth.html) to do so. In step 4, instead of selecting **Active Response Server API**, select **TIE Server Set Enterprise Reputation**.

### Dependencies (Python packages)
You don't need to install the packages, they are included in the Docker image.
  - DXL Client [documentation](https://opendxl.github.io/opendxl-client-python/pydoc/dxlclient.client.html)
  - DXL TIE Client [documentation](https://opendxl.github.io/opendxl-tie-client-python/pydoc/dxltieclient.client.html)

## Configure McAfee Threat Intelligence Exchange V2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Broker CA certificates | From \`brokercerts.crt\` file. | True |
| Client certificates | From \`client.crt\` file. | True |
| Client private key | From \`client.key\` file. Make sure that the type of the field is not \`encrypted\` when filling it out. | True |
| Broker URLs | The format should be: `[ssl://]<hostname>[:port]`. Get the hostname and port from the \`brokerlist.properties\` file. The broker should be reachable from Cortex XSOAR server. | True |
| Source Reliability | Reliability of the source providing the intelligence data. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| File.Malicious.Description | String | A description of why this file was found malicious. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | How reliable the score is \(for example, "C - fairly reliable"\). | 
| McAfee.TIE.FilesReputations.Reputations.Hash | String | The value of the hash. | 
| McAfee.TIE.FilesReputations.Reputations.GTI.Provider_ID | Number | The [identifier](#providers-table) of the particular provider that provided the reputation. | 
| McAfee.TIE.FilesReputations.Reputations.GTI.Trust_Level | Number | The [trust level](#trust-level-table) for the reputation subject. | 
| McAfee.TIE.FilesReputations.Reputations.GTI.Create_Date | String | The time this reputation was created (UTC timezone). | 
| McAfee.TIE.FilesReputations.Reputations.GTI.Provider | String | The name of the particular provider that provided the reputation. | 
| McAfee.TIE.FilesReputations.Reputations.GTI.Original_Response | String | The raw response as returned by the Global Threat Intelligence \(GTI\) reputation provider. | 
| McAfee.TIE.FilesReputations.Reputations.GTI.First_Contact | String | The time the file was first seen (UTC timezone). | 
| McAfee.TIE.FilesReputations.Reputations.GTI.Prevalence | String | The number of times the file has been requested. | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Provider_ID | Number | The [identifier](#providers-table) of the particular provider that provided the reputation. | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Trust_Level | Number | The [trust level](#trust-level-table) for the reputation subject. | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Create_Date | String | The time this reputation was created (UTC timezone). | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Provider | String | The name of the particular provider that provided the reputation. | 
| McAfee.TIE.FilesReputations.Reputations.ATD.GAM_Score | String | The [trust score](#atd-trust-score-table) reported by the Gateway Anti-Malware \(GAM\). | 
| McAfee.TIE.FilesReputations.Reputations.ATD.AV_Engine_Score | String | The [trust score](#atd-trust-score-table) reported by the Anti-Virus engine. | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Sandbox_Score | String | The [trust score](#atd-trust-score-table) as a result of the sandbox evaluation. | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Verdict | String | The overall [verdict](#atd-trust-score-table) \(taking into consideration all available information\). | 
| McAfee.TIE.FilesReputations.Reputations.ATD.Behaviors | String | An encoded structure that contains observed behaviors of the file. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Provider_ID| Number | The [identifier](#providers-table) of the particular provider that provided the reputation. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Trust_Level | Number | The [trust level](#trust-level-table) for the reputation subject. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Create_Date | String | The time this reputation was created (UTC timezone). | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Provider | String | The name of the particular provider that provided the reputation. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Server_Version | String | The version of the TIE server that returned the reputations \(encoded version string\). | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.First_Contact | String | The time the file was first seen (UTC timezone). | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Prevalence | String | The number of unique systems that have executed the file. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Enterprise_Size | String | The number of systems within the local enterprise. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Min_Local_Rep | String | The lowest reputation found locally on a system. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Max_Local_Rep | String | The highest reputation found locally on a system. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Avg_Local_Rep | String | The average reputation found locally on systems. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Parent_Min_Local_Rep | String | The lowest reputation for the parent found locally on a system. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Parent_Max_Local_Rep | String | The highest reputation for the parent found locally on a system. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Parent_Avg_Local_Rep | String | The average reputation for the parent found locally on systems. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.File_Name_Count | String | The number of unique file names for the file. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Detection_Count | String | The number of detections for the file or certificate. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Last_Detection_Time | String | The last time a detection occurred (UTC timezone). | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Is_Prevalent | String | Whether the file is considered to be prevalent within the enterprise. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Child_File_Reps | String | The child file reputations \(aggregate string\) according to the following format:<br /> - The number of files.<br />- The maximum trust level found across the files.<br /> - The minimum trust level found across the files.<br /> - The trust level for the last file.<br /> - The average trust level across the files. | 
| McAfee.TIE.FilesReputations.Reputations.Enterprise.Parent_File_Reps | String | The parent file reputations \(aggregate string\) according to the following format:<br /> - The number of files.<br /> - The maximum trust level found across the files.<br /> - The minimum trust level found across the files.<br /> - The trust level for the last file.<br /> - The average trust level across the files. | 

### Providers Table
| **Provider** | **Numeric** | **Description** |
| --- | --- | --- |
| GTI | 1 | Global Threat Intelligence (GTI). |
| ENTERPRISE | 3 | Enterprise reputation (specific to the local enterprise). |
| ATD | 5 | McAfee Advanced Threat Defense (ATD). |

### Trust Level Table
| **Trust Level** | **Numeric** | **Description** |
| --- | --- | --- |
| KNOWN_TRUSTED_INSTALLER | 100 | It is a trusted installer. |
| KNOWN_TRUSTED | 99 | It is a trusted file. |
| MOST_LIKELY_TRUSTED | 85 | It is almost certain that the file is trusted. |
| MIGHT_BE_TRUSTED | 70 | It seems to be a benign file. |
| UNKNOWN | 50 | The reputation provider has encountered the file before but the provider can't determine its reputation at the moment. |
| MIGHT_BE_MALICIOUS | 30 | It seems to be a suspicious file. |
| MOST_LIKELY_MALICIOUS | 15 | It is almost certain that the file is malicious. |
| KNOWN_MALICIOUS | 1 | It is a malicious file. |
| NOT_SET | 0 | The file's reputation hasn't been determined yet. |

### ATD Trust Score Table
| **Trust Level** | **Numeric** | **Description** |
| --- | --- | --- |
| KNOWN_TRUSTED | -1 | It is a trusted file. |
| MOST_LIKELY_TRUSTED | 0 | It is almost certain that the file is trusted. |
| MIGHT_BE_TRUSTED | 1 | It seems to be a benign file. |
| UNKNOWN | 2 | The reputation provider has encountered the file before but the provider can't determine its reputation at the moment. |
| MIGHT_BE_MALICIOUS | 3 | It seems to be a suspicious file. |
| MOST_LIKELY_MALICIOUS | 4 | It is almost certain that the file is malicious. |
| KNOWN_MALICIOUS | 5 | It is a malicious file. |
| NOT_SET | -2 | The file's reputation hasn't been determined yet. |

### Command Example
`!file file=f2c7bb8acc97f92e987a2d4087d021b1,7eb0139d2175739b3ccb0d1110067820be6abd29`

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "f2c7bb8acc97f92e987a2d4087d021b1",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "file",
            "Vendor": "McAfee Threat Intelligence Exchange V2"
        },
        {
            "Indicator": "7eb0139d2175739b3ccb0d1110067820be6abd29",
            "Reliability": "C - Fairly reliable",
            "Score": 3,
            "Type": "file",
            "Vendor": "McAfee Threat Intelligence Exchange V2"
        }
    ],
    "File": [
        {
            "Hashes": [
                {
                    "type": "MD5",
                    "value": "f2c7bb8acc97f92e987a2d4087d021b1"
                }
            ],
            "MD5": "f2c7bb8acc97f92e987a2d4087d021b1"
        },
        {
            "Hashes": [
                {
                    "type": "SHA1",
                    "value": "7eb0139d2175739b3ccb0d1110067820be6abd29"
                }
            ],
            "Malicious": {
                "Description": "Trust level is 1",
                "Vendor": "McAfee Threat Intelligence Exchange V2"
            },
            "SHA1": "7eb0139d2175739b3ccb0d1110067820be6abd29"
        }
    ],
    "McAfee": {
        "TIE": {
            "FilesReputations": [
                {
                    "Reputations": {
                        "Enterprise": {
                            "Create_Date": "2017-10-15 15:33:20",
                            "Enterprise_Size": "167565",
                            "File_Name_Count": "3",
                            "First_Contact": "2017-10-15 15:33:20",
                            "Is_Prevalent": "0",
                            "Prevalence": "4336",
                            "Provider": "Enterprise reputation",
                            "Provider_ID": 3,
                            "Server_Version": "3.0.0.480",
                            "Trust_Level": 85
                        },
                        "GTI": {
                            "Create_Date": "2017-10-15 15:33:20",
                            "Original_Response": "2139160704",
                            "Provider": "Global Threat Intelligence (GTI)",
                            "Provider_ID": 1,
                            "Trust_Level": 99
                        },
                        "Hash": "f2c7bb8acc97f92e987a2d4087d021b1"
                    }
                },
                {
                    "Reputations": {
                        "Enterprise": {
                            "Create_Date": "2017-10-15 16:30:54",
                            "Enterprise_Size": "167566",
                            "File_Name_Count": "1",
                            "First_Contact": "2017-10-15 16:30:54",
                            "Is_Prevalent": "0",
                            "Prevalence": "2736",
                            "Provider": "Enterprise reputation",
                            "Provider_ID": 3,
                            "Server_Version": "3.0.0.480",
                            "Trust_Level": 1
                        },
                        "GTI": {
                            "Create_Date": "2018-06-04 13:31:02",
                            "Original_Response": "2139160704",
                            "Provider": "Global Threat Intelligence (GTI)",
                            "Provider_ID": 1,
                            "Trust_Level": 99
                        },
                        "Hash": "7eb0139d2175739b3ccb0d1110067820be6abd29"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output
### McAfee TIE Hash Reputations For f2c7bb8acc97f92e987a2d4087d021b1:
|Created date|Provider (verbose)|Provider ID|Trust level|Trust level (verbose)|
|---|---|---|---|---|
| 2017-10-15 15:33:20 | Global Threat Intelligence (GTI) | 1 | 99 | KNOWN_TRUSTED |
| 2017-10-15 15:33:20 | Enterprise reputation | 3 | 85 | MOST_LIKELY_TRUSTED |

### McAfee TIE Hash Reputations For 7eb0139d2175739b3ccb0d1110067820be6abd29:
|Created date|Provider (verbose)|Provider ID|Trust level|Trust level (verbose)|
|---|---|---|---|---|
| 2017-10-15 16:30:54 | Enterprise reputation | 3 | 1 | KNOWN_MALICIOUS |
| 2018-06-04 13:31:02 | Global Threat Intelligence (GTI) | 1 | 99 | KNOWN_TRUSTED |

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
`There is no context output for this command.`

### Command Example
```!tie-set-file-reputation file=f2c7bb8acc97f92e987a2d4087d021b1,7eb0139d2175739b3ccb0d1110067820be6abd29 trust_level=MOST_LIKELY_TRUSTED comment="For testing" filename="tesing.exe"```

#### Human Readable Output
`Successfully set files reputation.`

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
| McAfee.TIE.FilesReferences.References.Date | String | The time the system first referenced the file (UTC timezone). | 
| McAfee.TIE.FilesReferences.Hash | String | The value of the hash. | 

### Command Example
`!tie-file-references file=f2c7bb8acc97f92e987a2d4087d021b1,7eb0139d2175739b3ccb0d1110067820be6abd29 query_limit=5`

#### Context Example
```json
{
    "File": [
        {
            "Hashes": [
                {
                    "type": "MD5",
                    "value": "f2c7bb8acc97f92e987a2d4087d021b1"
                }
            ],
            "MD5": "f2c7bb8acc97f92e987a2d4087d021b1"
        },
        {
            "Hashes": [
                {
                    "type": "SHA1",
                    "value": "7eb0139d2175739b3ccb0d1110067820be6abd29"
                }
            ],
            "SHA1": "7eb0139d2175739b3ccb0d1110067820be6abd29"
        }
    ],
    "McAfee": {
        "TIE": {
            "FilesReferences": [
                {
                    "Hash": "f2c7bb8acc97f92e987a2d4087d021b1",
                    "References": [
                        {
                            "AgentGuid": "0c906be0-224c-45d4-8e6f-bc89da69d268",
                            "Date": "2017-10-15 15:33:20"
                        },
                        {
                            "AgentGuid": "70be2ee9-7166-413b-b03e-64a48f6ab6c8",
                            "Date": "2017-10-15 15:34:11"
                        },
                        {
                            "AgentGuid": "c21b8995-9c5a-412c-b727-c4284d42380a",
                            "Date": "2017-10-15 16:30:48"
                        },
                        {
                            "AgentGuid": "24e0e935-2241-47d7-822b-20dfe0fe86de",
                            "Date": "2017-10-15 16:30:49"
                        },
                        {
                            "AgentGuid": "e50a8b51-2063-42cb-a85f-10bd0a698323",
                            "Date": "2017-10-15 16:30:51"
                        }
                    ]
                },
                {
                    "Hash": "7eb0139d2175739b3ccb0d1110067820be6abd29",
                    "References": [
                        {
                            "AgentGuid": "157eaf84-88ab-4d95-9456-30878fded9d5",
                            "Date": "2017-10-15 16:30:54"
                        },
                        {
                            "AgentGuid": "0bbcd439-aaed-4931-b9f4-b37e4a49b980",
                            "Date": "2017-10-16 13:28:43"
                        },
                        {
                            "AgentGuid": "f87fb2c3-2032-4fc5-a54f-7d36b441a122",
                            "Date": "2017-10-16 13:28:46"
                        },
                        {
                            "AgentGuid": "33b05a2e-6bb2-46c2-998f-893668c46402",
                            "Date": "2017-10-16 14:12:17"
                        },
                        {
                            "AgentGuid": "99ed15bb-ebc5-4b48-9a4d-5ad1b30abaac",
                            "Date": "2017-10-16 14:14:36"
                        }
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output
### References For Hash f2c7bb8acc97f92e987a2d4087d021b1:
|AgentGuid|Date|
|---|---|
| 0c906be0-224c-45d4-8e6f-bc89da69d268 | 2017-10-15 15:33:20 |
| 70be2ee9-7166-413b-b03e-64a48f6ab6c8 | 2017-10-15 15:34:11 |
| c21b8995-9c5a-412c-b727-c4284d42380a | 2017-10-15 16:30:48 |
| 24e0e935-2241-47d7-822b-20dfe0fe86de | 2017-10-15 16:30:49 |
| e50a8b51-2063-42cb-a85f-10bd0a698323 | 2017-10-15 16:30:51 |

### References For Hash 7eb0139d2175739b3ccb0d1110067820be6abd29:
|AgentGuid|Date|
|---|---|
| 157eaf84-88ab-4d95-9456-30878fded9d5 | 2017-10-15 16:30:54 |
| 0bbcd439-aaed-4931-b9f4-b37e4a49b980 | 2017-10-16 13:28:43 |
| f87fb2c3-2032-4fc5-a54f-7d36b441a122 | 2017-10-16 13:28:46 |
| 33b05a2e-6bb2-46c2-998f-893668c46402 | 2017-10-16 14:12:17 |
| 99ed15bb-ebc5-4b48-9a4d-5ad1b30abaac | 2017-10-16 14:14:36 |


## Breaking Changes
The following sections list the changes in this version.
- You can now pass more than one file to the following commands:
   - ***tie-set-file-reputation***
   - ***tie-file-references***
- Added additional context outputs to the following commands:
   - ***file***
   - ***tie-file-references***

