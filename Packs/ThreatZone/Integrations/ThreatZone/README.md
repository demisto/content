*Threat.Zone* is a hypervisor-based, automated and interactive tool for analyzing malware , you can fight new generation malwares.

## Use Cases

1. Submit a file, remote file to ThreatZone for analysis.
2. Retrieve report details for a given analysis UUID.

## Configure ThreatZone on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **ThreatZone**.
3. Click **Add instance** to create and configure a new integration instance.


| **Parameter**                      | **Required** |
| :----------------------------------- | -------------- |
| Server URL                         | True         |
| API Key                            | True         |
| Trust any certificate (not secure) | False        |
| Use system proxy settings          | False        |
| Source Reliability                 | False        |

4. Click **Test** to validate the URLs, API Key, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a human readable output appears in the War Room with the command details.
All details and full analysis report is avaliable at Context Data.

### tz-check-limits

---

Check the plan limits from ThreatZone API.

#### Base Command

`tz-check-limits`

#### Output


| **Path**                                 | **Type** | **Description**                                                |
| ------------------------------------------ | ---------- | ---------------------------------------------------------------- |
| ThreatZone.Limits.API_Limit              | String   | The used/total API request limits of the current plan.         |
| ThreatZone.Limits.Concurrent_Limit       | String   | The used/total concurrent analysis limits of the current plan. |
| ThreatZone.Limits.Daily_Submission_Limit | String   | The used/total daily submission limits of the current plan.    |

### tz-sandbox-upload-sample

---

Submit a file for sandbox analysis.

#### Base Command

`tz-sandbox-upload-sample`

#### Input


| **Argument Name**   | **Description**                                                                                                                                        | **Required** |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| entry_id            | EntryID of the file to analyze.                                                                                                                        | True         |
| environment         | Version of Windows OS. Possible values are: w7_x64 for Windows 7 x64, w10_x64 for Windows 10 x64, w11_x64 for Windows 11 x64. Default is Windows 7 x64 | Optional     |
| private             | Privacy of the submission. Possible values are: true, false. Default is true.                                                                          | Optional     |
| timeout             | Duration of the submission analysis. Possible values are: 60, 120, 180, 300. Default is 60.                                                            | Optional     |
| work_path           | The working path of the submission. Possible values are: desktop, root, appdata, windows, temp. Default is desktop.                                    | Optional     |
| mouse_simulation    | Enable mouse simulation during the analysis. Possible values are: true, false. Default false.                                                          | Optional     |
| https_inspection    | Https inspection to read encrypted traffic. Possible values are: true, false. Default is false.                                                        | Optional     |
| internet_connection | Enable internet connection during the analysis. Possible values are: true, false. Default is false.                                                    | Optional     |
| raw_logs            | Raw logs. Possible values are: true, false. Default is false.                                                                                          | Optional     |
| snapshot            | Snapshot. Possible values are: true, false. Default is false.                                                                                          | Optional     |

#### Output


| **Path**                 | **Type** | **Description**                                     |
| -------------------------- | ---------- | ----------------------------------------------------- |
| ThreatZone.Analysis.UUID | String   | UUID of the task created to analyze the submission. |
| ThreatZone.Analysis.URL  | String   | URL of the task created to analyze the submission.  |

### tz-static-upload-sample

---

Submit a file for static analysis.

#### Base Command

`tz-static-upload-sample`

#### Input


| **Argument Name** | **Description**                 | **Required** |
| ------------------- | --------------------------------- | -------------- |
| entry_id          | EntryID of the file to analyze. | True         |

#### Output


| **Path**                 | **Type** | **Description**                                     |
| -------------------------- | ---------- | ----------------------------------------------------- |
| ThreatZone.Analysis.UUID | String   | UUID of the task created to analyze the submission. |
| ThreatZone.Analysis.URL  | String   | URL of the task created to analyze the submission.  |

### tz-cdr-upload-sample

---

Submit a file to ThreatZone CDR.

#### Base Command

`tz-cdr-upload-sample`

#### Input


| **Argument Name** | **Description**                 | **Required** |
| ------------------- | --------------------------------- | -------------- |
| entry_id          | EntryID of the file to analyze. | True         |

#### Output


| **Path**                 | **Type** | **Description**                                     |
| -------------------------- | ---------- | ----------------------------------------------------- |
| ThreatZone.Analysis.UUID | String   | UUID of the task created to analyze the submission. |
| ThreatZone.Analysis.URL  | String   | URL of the task created to analyze the submission.  |

### tz-get-report

---

Gets the report of a UUID created for a submitted file or URL.

#### Base Command

`tz-get-report`

#### Input


| **Argument Name** | **Description**                                                                            | **Required** |
| ------------------- | -------------------------------------------------------------------------------------------- | -------------- |
| uuid              | A UUID is returned when submitting a file for analysis using the`tz-run-analysis` command. | Required     |

#### Context Output


| **Path**                    | **Type** | **Description**                                              |
| ----------------------------- | ---------- | -------------------------------------------------------------- |
| ThreatZone.Result.INFO      | String   | Details of the submitted file.                               |
| ThreatZone.Result.UUID      | String   | The UUID of the task.                                        |
| ThreatZone.Result.URL       | String   | The URL of the submission analysis page in threat.zone.      |
| ThreatZone.Result.RESULT    | String   | The analysis result dict of the file submitted for analysis. |
| ThreatZone.Result.MIME      | String   | The MIME of the file submitted for analysis.                 |
| ThreatZone.Result.MD5       | String   | The MD5 hash of the file submitted for analysis.             |
| ThreatZone.Result.SHA1      | String   | The SHA1 hash of the file submitted for analysis.            |
| ThreatZone.Result.SHA256    | String   | The SHA256 hash of the file submitted for analysis.          |
| ThreatZone.Result.LEVEL     | Number   | The threat level of the file submitted for analysis.         |
| ThreatZone.Result.SANITIZED | String   | The sanitized file URL of the file submitted to CDR.         |
| File.Extension              | String   | Extension of the file sanitized by CDR.                      |
| File.Name                   | String   | The name of the file sanitized by CDR.                       |
| File.Size                   | Number   | Size of the file sanitized by CDR.                           |
| File.EntryID                | String   | EntryID of the file sanitized by CDR.                        |
| File.Info                   | String   | Info of the file sanitized by CDR.                           |
| File.MD5                    | String   | MD5 hash of the file sanitized by CDR.                       |
| File.SHA1                   | String   | SHA1 hash of the file sanitized by CDR.                      |
| File.SHA256                 | String   | SHA256 hash of the file sanitized by CDR.                    |
| File.SHA512                 | String   | SHA512 hash of the file sanitized by CDR.                    |
| File.SSDeep                 | String   | SSDeep hash of the file sanitized by CDR.                    |

#### Command Example

```tz-get-result uuid=95b6bc52-d040-4d82-a98b-af6fd5f6feea``` (Sandbox)

```tz-get-result uuid=7ddad84a-7f9b-4b56-b8f4-914287a0a1a3``` (Static-Scan)

```tz-get-result uuid=1170250a-40ac-4b73-84f7-3c0b6026d8af``` (CDR)

#### Context Example for Sandbox

```json
{
  "ThreatZone": {
    "Result": {
      "INFO": {
        "file_name": "80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108.exe",
        "private": false
      },
      "LEVEL": 3,
      "MD5": "30bdb7e22e022bcf00d157f4da0e098e",
      "REPORT": {
        "dynamic": {
          "_id": "64f1e57fc9ae854321d3a7f5",
          "additionalFiles": [],
          "enabled": true,
          "indicators": [
            {
              "_id": "64f1e5fb7949a5710e1e46be",
              "attackCodes": [
                "T1082"
              ],
              "author": "Malwation",
              "category": "Registry",
              "description": "Target reads computer name",
              "events": [
                87430,
                87431
              ],
              "level": "Suspicious",
              "name": "Reads computer name",
              "score": 3
            },
            {
              "_id": "64f1e5fb7949a5710e1e46bf",
              "attackCodes": [
                "T1112"
              ],
              "author": "Malwation",
              "category": "Registry",
              "description": "Target changes registry value",
              "events": [
                4872,
                4874,
                4876,
                4878,
                4880,
                4883,
                5597,
                5603,
                5609,
                5615,
                5621,
                5628
              ],
              "level": "Malicious",
              "name": "Registry changed",
              "score": 7
            },
            {
              "_id": "64f1e5fb7949a5710e1e46c0",
              "attackCodes": [],
              "author": "Malwation",
              "category": "Registry",
              "description": "Target reads the Internet Settings",
              "events": [
                5708,
                6089,
                6090,
                6091,
                6092,
                6096,
                6097,
                6320,
                6322,
                6323
              ],
              "level": "Suspicious",
              "name": "Reads the Internet Settings",
              "score": 5
            },
            {
              "_id": "64f1e5fb7949a5710e1e46c1",
              "attackCodes": [],
              "author": "Malwation",
              "category": "OS",
              "description": "Target creates mutex",
              "events": [
                4842
              ],
              "level": "Suspicious",
              "name": "Create mutex",
              "score": 5
            },
            {
              "_id": "64f1e5fb7949a5710e1e46c2",
              "attackCodes": [],
              "author": "Malwation",
              "category": "Network",
              "description": "Target might try to open port and listen for incoming connection",
              "events": [
                5512,
                5509,
                5386,
                5385,
                87138,
                87137,
                87136,
                87134
              ],
              "level": "Suspicious",
              "name": "Network connection",
              "score": 4
            }
          ],
          "level": 3,
          "media": [
            {
              "_id": "64f1e5fb7949a5710e1e46c3",
              "id": "75d54195-ede8-48eb-8614-55d3658ed71c",
              "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/1.png"
            },
            {
              "_id": "64f1e5fb7949a5710e1e46c4",
              "id": "3eb5c83a-79ff-4e04-a173-b6c087a6f578",
              "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/10.png"
            },
            {
              "_id": "64f1e5fb7949a5710e1e46c5",
              "id": "b966535b-9aaa-4a0b-a1a1-863d8d23c830",
              "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/2.png"
            },
            {
              "_id": "64f1e5fb7949a5710e1e46c6",
              "id": "68eac6f4-68a1-411b-b349-b919aef3e166",
              "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/3.png"
            },
            {
              "_id": "64f1e5fb7949a5710e1e46c7",
              "id": "d76344b8-ba3d-411a-adf3-515990623dd9",
              "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/4.png"
            },
            {
              "_id": "64f1e5fb7949a5710e1e46c8",
              "id": "503b92df-98e1-4e6d-80bc-d18e8e25acb8",
              "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/5.png"
            },
            {
              "_id": "64f1e5fb7949a5710e1e46c9",
              "id": "ac0228c8-79d1-40b8-930b-5ad1bbf8996f",
              "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/6.png"
            },
            {
              "_id": "64f1e5fb7949a5710e1e46ca",
              "id": "56095f8a-2319-4169-856e-1acb05ec0f7f",
              "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/7.png"
            },
            {
              "_id": "64f1e5fb7949a5710e1e46cb",
              "id": "4418068d-caa9-4e13-997e-3e631baf5d98",
              "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/8.png"
            },
            {
              "_id": "64f1e5fc7949a5710e1e46cc",
              "id": "1b025f1b-b5d7-4491-bd29-8696513f04d6",
              "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/9.png"
            },
            {
              "_id": "64f1e5fc7949a5710e1e46cd",
              "id": "4fc26473-0fe5-4ef7-9caa-050d8a7dbb11",
              "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/video.mp4"
            }
          ],
          "metafields": {
            "environment": "w7_x64",
            "https_inspection": false,
            "internet_connection": false,
            "mouse_simulation": false,
            "raw_logs": false,
            "snapshot": false,
            "timeout": 60,
            "work_path": "desktop"
          },
          "network": [],
          "process": [
            {
              "_id": "64f1e5fb7949a5710e1e46bb",
              "analysis": "basic",
              "cmd": "cmd_line",
              "eventcount": 1,
              "eventid": 35,
              "image": "win_image",
              "method": "NtUserCreateProcess",
              "operation": "create",
              "pid": 3060,
              "ppid": 1452,
              "process_name": "80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108.exe",
              "work_dir": "C:\\Windows\\system32\\"
            },
            {
              "_id": "64f1e5fb7949a5710e1e46bc",
              "analysis": "basic",
              "cmd": "cmd_line",
              "eventcount": 1,
              "eventid": 36,
              "image": "win_image",
              "method": "NtUserCreateProcess",
              "operation": "create",
              "pid": 656,
              "ppid": 3060,
              "process_name": "cmd.exe",
              "work_dir": "C:\\Windows\\system32\\"
            },
            {
              "_id": "64f1e5fb7949a5710e1e46bd",
              "analysis": "basic",
              "cmd": "cmd_line",
              "eventcount": 1,
              "eventid": 38,
              "image": "win_image",
              "method": "NtUserCreateProcess",
              "operation": "create",
              "pid": 2188,
              "ppid": 656,
              "process_name": "timeout.exe",
              "work_dir": "C:\\Windows\\system32\\"
            },
            null
          ],
          "status": 5,
          "vnc": "https://app.threat.zone/cloudvnc/index.html?path=?token=95b6bc52-d040-4d82-a98b-af6fd5f6feea"
        }
      },
      "SHA1": "0cd47f6bb5bb8e8e9dc01286adcc493acf5dd649",
      "SHA256": "80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108",
      "STATUS": 5,
      "URL": "https://app.threat.zone/submission/95b6bc52-d040-4d82-a98b-af6fd5f6feea",
      "UUID": "95b6bc52-d040-4d82-a98b-af6fd5f6feea"
    }
  }
}
```

#### Context Example for Static Scan

```json
{
  "ThreatZone": {
    "Result": {
      "INFO": {
        "file_name": "0_nUlF45uRfpbPIaqC.png",
        "private": false
      },
      "LEVEL": 2,
      "MD5": "fbce2f43185104ae8bf4d32571b19203",
      "REPORT": {
        "static": {
          "_id": "64f061eb9292e0f8f30fb5d0",
          "debugInfo": [
            {
              "AddressOfRawData": 37576,
              "DebugType": "IMAGE_DEBUG_TYPE_CODEVIEW",
              "FakeTimeStamp": false,
              "MajorVersion": 0,
              "MinorVersion": 0,
              "PdbFileName": "1394bus.pdb",
              "PointerToRawData": 34504,
              "Size": 36,
              "TimeDateStamp": "Jul 13 2009 23:51:21",
              "Type": "IMAGE_DEBUG_TYPE_CODEVIEW"
            }
          ],
          "enabled": true,
          "exports": [
            {
              "_id": "64f061eb9292e0f8f30fb9ba",
              "address": "0x1e1b6",
              "name": "Bus1394RegisterPortDriver"
            },
            {
              "_id": "64f061eb9292e0f8f30fb9bb",
              "address": "0x1c534",
              "name": "DllInitialize"
            },
            {
              "_id": "64f061eb9292e0f8f30fb9bc",
              "address": "0x1c5a4",
              "name": "DllUnload"
            }
          ],
          "generalInfo": {
            "FileHeaders": {
              "Characteristics": 258,
              "Machine": "IMAGE_FILE_MACHINE_I386",
              "Number of Sections": 9,
              "Number of Symbols": 0,
              "Pointer to Symbol Table": 0,
              "Size of Optional Header": "224 bytes",
              "TimeDateStamp": "Jul 13 2009 23:51:21"
            },
            "FileInfo": {
              "Entropy": 6.4,
              "File Type": "PE32 executable (native) Intel 80386, for MS Windows",
              "Filename": "0_nUlF45uRfpbPIaqC.png.exe",
              "Filesize": "53.50 KB",
              "MD5": "fbce2f43185104ae8bf4d32571b19203",
              "MIME Type": "application/x-dosexec",
              "Report Type": "EXE",
              "SHA1": "e0ecee70f2704093a8fb620d61a995b561b65c20",
              "SHA256": "e38dae160633fb5bf65a982374f1c7725c25ed32e89dbe2dce3a8f486cfae3cb",
              "SSDEEP": "768:KRnJAKL6Iew2Lw7Yg/rRE0mEI6zkQoWPcmL39wgZLlWy:Kzf6IeTwB6BQoW0mLygVlz"
            },
            "checkSum": true,
            "importHash": "2fce2efb37d4c88ac5967c8355c0c238",
            "overlayEntropy": 0,
            "packer": "Built with EPL",
            "richHeaderHash": null
          },
          "imports": {
            "HAL.dll": [
              {
                "address": "0x19000",
                "blacklist": false,
                "name": "ExAcquireFastMutex"
              },
              {
                "address": "0x19004",
                "blacklist": false,
                "name": "KfReleaseSpinLock"
              },
              {
                "address": "0x19008",
                "blacklist": false,
                "name": "KfAcquireSpinLock"
              },
              {
                "address": "0x1900c",
                "blacklist": false,
                "name": "ExReleaseFastMutex"
              }
            ],
            "WMILIB.SYS": [
              {
                "address": "0x19014",
                "blacklist": false,
                "name": "WmiSystemControl"
              },
              {
                "address": "0x19018",
                "blacklist": false,
                "name": "WmiCompleteRequest"
              },
              {
                "address": "0x1901c",
                "blacklist": false,
                "name": "WmiFireEvent"
              }
            ],
            "ntoskrnl.exe": [
              {
                "address": "0x19024",
                "blacklist": false,
                "name": "InterlockedPopEntrySList"
              },
              {
                "address": "0x19028",
                "blacklist": false,
                "name": "InterlockedPushEntrySList"
              },
              {
                "address": "0x1902c",
                "blacklist": false,
                "name": "_vsnprintf"
              },
              ...
            ]
          },
          "ioc": null,
          "keywords": [],
          "level": 2,
          "oleStream": [],
          "resources": [
            {
              "Entropy": "3.60",
              "Lang": "LANG_ENGLISH",
              "Name": "RT_VERSION",
              "Offset": "0x00012060",
              "SHA256": "7631030132495f40a201db9c1dfbf24f0482828dde204a4636a5d62233e80bb1",
              "Size": "916.00 B",
              "Sublang": "SUBLANG_ENGLISH_US",
              "Type": "data"
            }
          ],
          "scanType": "exe",
          "score": 5.82,
          "sections": [
            {
              "Entropy": "6.54",
              "MD5": "9f1d4b6f9e7a208744117d85528cfe4c",
              "Name": ".text",
              "Raw Size": "0x8000",
              "Virtual Address": "0x1000",
              "Virtual Size": "0x7fe1"
            },
            {
              "Entropy": "6.35",
              "MD5": "4a9d5a4eb8022275152d60f5bb2cc146",
              "Name": "PAGE",
              "Raw Size": "0x3200",
              "Virtual Address": "0xc000",
              "Virtual Size": "0x3096"
            },
            {
              "Entropy": "5.76",
              "MD5": "fc8863b2a1de0828e31a17ed25a385e6",
              "Name": ".reloc",
              "Raw Size": "0x800",
              "Virtual Address": "0x13000",
              "Virtual Size": "0x718"
            },
            {
              "Entropy": "5.12",
              "MD5": "886d0fe17c534566f8ffef08deffae22",
              "Name": "INIT",
              "Raw Size": "0xa00",
              "Virtual Address": "0x11000",
              "Virtual Size": "0x88c"
            },
            {
              "Entropy": "4.39",
              "MD5": "0025a23251ee58340947dd0ae5bd6f89",
              "Name": ".rdata",
              "Raw Size": "0x400",
              "Virtual Address": "0x9000",
              "Virtual Size": "0x314"
            },
            {
              "Entropy": "3.43",
              "MD5": "08483df6d0df4d4724045975288281b6",
              "Name": ".rsrc",
              "Raw Size": "0x400",
              "Virtual Address": "0x12000",
              "Virtual Size": "0x3f8"
            },
            {
              "Entropy": "1.71",
              "MD5": "59d05007e5ad0eaa7217a39258fb4ee4",
              "Name": ".data",
              "Raw Size": "0x200",
              "Virtual Address": "0xa000",
              "Virtual Size": "0xdc"
            },
            {
              "Entropy": "1.51",
              "MD5": "a4c018f80ed73935e617cfd9d3a57882",
              "Name": ".edata",
              "Raw Size": "0x200",
              "Virtual Address": "0x10000",
              "Virtual Size": "0x84"
            },
            {
              "Entropy": "0.33",
              "MD5": "bac82beb0d86e9e5c3ed32f95ad7eda8",
              "Name": ".guids",
              "Raw Size": "0x200",
              "Virtual Address": "0xb000",
              "Virtual Size": "0x10"
            }
          ],
          "status": 5,
          "strings": [
            {
              "_id": "64f061eb9292e0f8f30fb5d2",
              "blacklist": false,
              "hint": null,
              "value": "L!This program cannot be run in DOS mode."
            },
            {
              "_id": "64f061eb9292e0f8f30fb5d3",
              "blacklist": false,
              "hint": null,
              "value": "0(I0(I0(I0)I`(I9I7(I9I3(I9I1(I9I=(I9I1(I9I1(IRich0(I"
            },
            {
              "_id": "64f061eb9292e0f8f30fb5d4",
              "blacklist": false,
              "hint": null,
              "value": ".text"
            },
            {
              "_id": "64f061eb9292e0f8f30fb5d5",
              "blacklist": false,
              "hint": null,
              "value": "h.rdata"
            },
            ...
          ],
          "yaraRules": {
            "_id": "64f061eb9292e0f8f30fb5d1",
            "info": [
              "SEH_Save",
              "SEH_Init",
              "domain",
              "contains_base64",
              "Visual_Cpp_2003_DLL_Microsoft",
              "IsPE32",
              "HasDebugData",
              "HasRichSignature"
            ],
            "malware": []
          }
        }
      },
      "SHA1": "e0ecee70f2704093a8fb620d61a995b561b65c20",
      "SHA256": "e38dae160633fb5bf65a982374f1c7725c25ed32e89dbe2dce3a8f486cfae3cb",
      "STATUS": 5,
      "URL": "https://app.threat.zone/submission/7ddad84a-7f9b-4b56-b8f4-914287a0a1a3",
      "UUID": "7ddad84a-7f9b-4b56-b8f4-914287a0a1a3"
    }
  }
}
```

#### Context Example for CDR

```json
{
  "File": {
    "EntryID": "204@f2408274-2db1-4b29-8996-0db4a6e3d813",
    "Extension": "zip",
    "Info": "application/zip",
    "MD5": "d42c3fe93c7c72ab54f1a65b3721783e",
    "Name": "sanitized-1170250a-40ac-4b73-84f7-3c0b6026d8af.zip",
    "SHA1": "2751b056bd130b4b522de0c64a9944282a930c52",
    "SHA256": "4d241fcb3be8c5c0e57956dcd12953edbf9bd61759887ad346c35008dfbff93a",
    "SHA512": "98415a517373103e2f2ee9d7de84bb25a4fc70a39011fe91b7b3b983322b21bcb0599564f207d9843968f6383e6412fc851787870de4aef654da91296f0ff2ab",
    "SSDeep": "3:YWR4h24VJHvAMaXwLnDW0:YWyQ4VJP0UDW0",
    "Size": 52,
    "Type": "JSON data"
  },
  "ThreatZone": {
    "Result": {
      "INFO": {
        "file_name": "fff2035c-def9-482c-9e1a-405c4d427833.docx",
        "private": false
      },
      "LEVEL": 0,
      "MD5": "cf543c55343c6307349aafd098fb6958",
      "REPORT": {
        "cdr": {
          "_id": "63f5004e4373640b5482800a",
          "data": {
            "description": "File sanitized successfully.",
            "processing time": "0.03357 seconds",
            "sanitized": [
              "Image"
            ]
          },
          "enabled": true,
          "level": 0,
          "status": 5
        }
      },
      "SANITIZED": "https://app.threat.zone/download/v1/download/cdr/1170250a-40ac-4b73-84f7-3c0b6026d8af",
      "SHA1": "1bec0d7bfea812ca7aa1f5399bb7ff3671006331",
      "SHA256": "945678e901efcd35ece87a1a0eba82f39feb7d45ea4d38330a4795d1338872ca",
      "STATUS": 5,
      "URL": "https://app.threat.zone/submission/1170250a-40ac-4b73-84f7-3c0b6026d8af",
      "UUID": "1170250a-40ac-4b73-84f7-3c0b6026d8af"
    }
  }
}
```

#### Human Readable Output Example For Sandbox


| FILE_NAME                                                            | MD5                              | PRIVATE | SCAN_URL                                                                                                                                           | SHA1                                     | SHA256                                                           | STATUS                 | THREAT_LEVEL | UUID                                 |
| ---------------------------------------------------------------------- | ---------------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------ | ------------------------ | -------------- | -------------------------------------- |
| 80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108.exe | 30bdb7e22e022bcf00d157f4da0e098e | false   | [https://app.threat.zone/submission/95b6bc52-d040-4d82-a98b-af6fd5f6feea](https://app.threat.zone/submission/95b6bc52-d040-4d82-a98b-af6fd5f6feea) | 0cd47f6bb5bb8e8e9dc01286adcc493acf5dd649 | 80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108 | Submission is finished | Malicious    | 95b6bc52-d040-4d82-a98b-af6fd5f6feea |

#### Human Readable Output For Static-Scan


| FILE_NAME              | MD5                              | PRIVATE | SCAN_URL                                                                                                                                           | SHA1                                     | SHA256                                                           | STATUS                 | THREAT_LEVEL | UUID                                 |
| ------------------------ | ---------------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------ | ------------------------ | -------------- | -------------------------------------- |
| 0_nUlF45uRfpbPIaqC.png | fbce2f43185104ae8bf4d32571b19203 | false   | [https://app.threat.zone/submission/7ddad84a-7f9b-4b56-b8f4-914287a0a1a3](https://app.threat.zone/submission/7ddad84a-7f9b-4b56-b8f4-914287a0a1a3) | e0ecee70f2704093a8fb620d61a995b561b65c20 | e38dae160633fb5bf65a982374f1c7725c25ed32e89dbe2dce3a8f486cfae3cb | Submission is finished | Suspicious   | 7ddad84a-7f9b-4b56-b8f4-914287a0a1a3 |

#### Human Readable Output For CDR


| FILE_NAME                                 | MD5                              | PRIVATE | SANITIZED                                                                                                                                                                      | SCAN_URL                                                                                                                                           | SHA1                                     | SHA256                                                           | STATUS                 | THREAT_LEVEL | UUID                                 |
| ------------------------------------------- | ---------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------ | ------------------------ | -------------- | -------------------------------------- |
| fff2035c-def9-482c-9e1a-405c4d427833.docx | cf543c55343c6307349aafd098fb6958 | false   | [https://app.threat.zone/download/v1/download/cdr/1170250a-40ac-4b73-84f7-3c0b6026d8af](https://app.threat.zone/download/v1/download/cdr/1170250a-40ac-4b73-84f7-3c0b6026d8af) | [https://app.threat.zone/submission/1170250a-40ac-4b73-84f7-3c0b6026d8af](https://app.threat.zone/submission/1170250a-40ac-4b73-84f7-3c0b6026d8af) | 1bec0d7bfea812ca7aa1f5399bb7ff3671006331 | 945678e901efcd35ece87a1a0eba82f39feb7d45ea4d38330a4795d1338872ca | Submission is finished | Not Measured | 1170250a-40ac-4b73-84f7-3c0b6026d8af |


| Property | Value                                                                                                                            |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Type     | application/json                                                                                                                 |
| Size     | 100,777 bytes                                                                                                                    |
| Info     | ASCII text, with very long lines, with no line terminators                                                                       |
| MD5      | aa85ec510171690d4435e94b2cceb912                                                                                                 |
| SHA1     | d5dede7a3b9871557842eee508322df38ac946f8                                                                                         |
| SHA256   | **8a5d8c81d285359bf9099061d847d110c9b71a99ad5495f149e92d3abc8d3ecd**                                                             |
| SHA512   | d6ddf83c0e3ffed2688e70adf4eb9ab5e99add4461a856f1a94f9586a722d8e08b697d345a64d71387dbd183d4bcaed2a9e0bf9b2f6b9a8d6e3ff84edd8d4dee |
| SSDeep   | 768:ibrt4XX8p4Q/GxvCJgj5yOHUmcqnn5PRozB:ivCXX8p4Q/GxvCJgkCUmjnFGd                                                                |
