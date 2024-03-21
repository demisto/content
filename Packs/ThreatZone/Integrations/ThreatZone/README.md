*Threat.Zone* is a hypervisor-based, automated and interactive tool for analyzing malware , you can fight new generation malwares.

## Configure ThreatZone on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ThreatZone.
3. Click **Add instance** to create and configure a new integration instance.


   | **Parameter**                                                       | **Description**            | **Required** |
   | --------------------------------------------------------------------- | ---------------------------- | -------------- |
   | Server URL (e.g.[https://app.threat.zone](https://app.threat.zone)) |                            | True         |
   | ThreatZone API Key                                                  |                            | True         |
   | Source Reliability                                                  | Reliability of the source. | False        |
   | Trust any certificate (not secure)                                  |                            | False        |
   | Use system proxy settings                                           |                            | False        |
4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tz-sandbox-upload-sample

---

Submits a sample to ThreatZone for sandbox analysis.

#### Base Command

`tz-sandbox-upload-sample`

#### Input


| **Argument Name**   | **Description**                                                                                                            | **Required** |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------- | -------------- |
| entry_id            | Entry ID of the file to submit.                                                                                            | Required     |
| environment         | Choose what environment you want to run your submission. Possible values are: w7_x64, w10_x64, w11_x64. Default is w7_x64. | Optional     |
| private             | Privacy of the submission. Possible values are: true, false. Default is true.                                              | Optional     |
| timeout             | Duration of the submission analysis. Possible values are: 60, 120, 180, 300. Default is 60.                                | Optional     |
| work_path           | The working path of the submission. Possible values are: desktop, root, appdata, windows, temp. Default is desktop.        | Optional     |
| mouse_simulation    | Enable mouse simulation. Possible values are: true, false. Default is false.                                               | Optional     |
| https_inspection    | Https inspection to read encrypted traffic. Possible values are: true, false. Default is false.                            | Optional     |
| internet_connection | Enable internet connection. Possible values are: true, false. Default is false.                                            | Optional     |
| raw_logs            | Raw logs. Possible values are: true, false. Default is false.                                                              | Optional     |
| snapshot            | Snapshot. Possible values are: true, false. Default is false.                                                              | Optional     |

#### Context Output


| **Path**                                 | **Type** | **Description**                                                     |
| ------------------------------------------ | ---------- | --------------------------------------------------------------------- |
| ThreatZone.Submission.Sandbox.UUID       | String   | UUID of sample.                                                     |
| ThreatZone.Submission.Sandbox.URL        | String   | URL of analysis of sample.                                          |
| ThreatZone.Limits.E_Mail                 | String   | The owner e-mail of current plan.                                   |
| ThreatZone.Limits.API_Limit              | String   | The remaining/total API request limits of the current plan.         |
| ThreatZone.Limits.Concurrent_Limit       | String   | The remaining/total concurrent analysis limits of the current plan. |
| ThreatZone.Limits.Daily_Submission_Limit | String   | The remaining/total daily submission limits of the current plan.    |

### tz-static-upload-sample

---

Submits a sample to ThreatZone for static analysis.

#### Base Command

`tz-static-upload-sample`

#### Input


| **Argument Name** | **Description**                 | **Required** |
| ------------------- | --------------------------------- | -------------- |
| entry_id          | Entry ID of the file to submit. | Required     |

#### Context Output


| **Path**                                 | **Type** | **Description**                                                     |
| ------------------------------------------ | ---------- | --------------------------------------------------------------------- |
| ThreatZone.Submission.Static.UUID        | String   | UUID of sample.                                                     |
| ThreatZone.Submission.Static.URL         | String   | URL of analysis of sample.                                          |
| ThreatZone.Limits.E_Mail                 | String   | The owner e-mail of current plan.                                   |
| ThreatZone.Limits.API_Limit              | String   | The remaining/total API request limits of the current plan.         |
| ThreatZone.Limits.Concurrent_Limit       | String   | The remaining/total concurrent analysis limits of the current plan. |
| ThreatZone.Limits.Daily_Submission_Limit | String   | The remaining/total daily submission limits of the current plan.    |

### tz-cdr-upload-sample

---

Submits a sample to ThreatZone for CDR.

#### Base Command

`tz-cdr-upload-sample`

#### Input


| **Argument Name** | **Description**                 | **Required** |
| ------------------- | --------------------------------- | -------------- |
| entry_id          | Entry ID of the file to submit. | Required     |

#### Context Output


| **Path**                                 | **Type** | **Description**                                                     |
| ------------------------------------------ | ---------- | --------------------------------------------------------------------- |
| ThreatZone.Submission.CDR.UUID           | String   | UUID of sample.                                                     |
| ThreatZone.Submission.CDR.URL            | String   | URL of analysis of sample.                                          |
| ThreatZone.Limits.E_Mail                 | String   | The owner e-mail of current plan.                                   |
| ThreatZone.Limits.API_Limit              | String   | The remaining/total API request limits of the current plan.         |
| ThreatZone.Limits.Concurrent_Limit       | String   | The remaining/total concurrent analysis limits of the current plan. |
| ThreatZone.Limits.Daily_Submission_Limit | String   | The remaining/total daily submission limits of the current plan.    |

### tz-get-result

---

Retrive the analysis result from ThreatZone.

#### Base Command

`tz-get-result`

#### Input


| **Argument Name** | **Description**         | **Required** |
| ------------------- | ------------------------- | -------------- |
| uuid              | UUID of the submission. | Required     |

#### Context Output


| **Path**                   | **Type** | **Description**                                                            |
| ---------------------------- | ---------- | ---------------------------------------------------------------------------- |
| ThreatZone.Analysis.STATUS | String   | The status of the submission scanning process.                             |
| ThreatZone.Analysis.LEVEL  | String   | Threat Level of the scanned file.\(malicious, suspicious or informative\). |
| ThreatZone.Analysis.URL    | String   | The result page url of the submission.                                     |
| ThreatZone.Analysis.INFO   | String   | Contains the file name, scan process status and public status.             |
| ThreatZone.Analysis.REPORT | String   | The analysis report of the submission.                                     |
| ThreatZone.Analysis.MD5    | String   | The md5 hash of the submission.                                            |
| ThreatZone.Analysis.SHA1   | String   | The sha1 hash of the submission.                                           |
| ThreatZone.Analysis.SHA256 | String   | The sha256 hash of the submission.                                         |
| ThreatZone.Analysis.UUID   | String   | The UUID of the submission.                                                |
| DBotScore.Indicator        | String   | The indicator that was tested.                                             |
| DBotScore.Reliability      | String   | The reliability of the source providing the intelligence data.             |
| DBotScore.Score            | Number   | The actual score.                                                          |
| DBotScore.Type             | String   | The indicator type.                                                        |
| DBotScore.Vendor           | unknown  | The vendor used to calculate the score.                                    |

### tz-get-sanitized

---

Downloads and uploads sanitized file from ThreatZone API to WarRoom & Context Data.

#### Base Command

`tz-get-sanitized`

#### Input


| **Argument Name** | **Description**         | **Required** |
| ------------------- | ------------------------- | -------------- |
| uuid              | UUID of the submission. | Required     |

#### Context Output


| **Path**       | **Type** | **Description**                           |
| ---------------- | ---------- | ------------------------------------------- |
| File.Extension | String   | Extension of the file sanitized by CDR.   |
| File.Name      | String   | The name of the file sanitized by CDR.    |
| File.Size      | Number   | Size of the file sanitized by CDR.        |
| File.EntryID   | String   | EntryID of the file sanitized by CDR.     |
| File.Info      | String   | Info of the file sanitized by CDR.        |
| File.MD5       | String   | MD5 hash of the file sanitized by CDR.    |
| File.SHA1      | String   | SHA1 hash of the file sanitized by CDR.   |
| File.SHA256    | String   | SHA256 hash of the file sanitized by CDR. |
| File.SHA512    | String   | SHA512 hash of the file sanitized by CDR. |
| File.SSDeep    | String   | SSDeep hash of the file sanitized by CDR. |

### tz-check-limits

---

Check the plan limits from ThreatZone API.

#### Base Command

`tz-check-limits`

#### Input


| **Argument Name** | **Description** | **Required** |
| ------------------- | ----------------- | -------------- |

#### Context Output


| **Path**                                 | **Type** | **Description**                                                     |
| ------------------------------------------ | ---------- | --------------------------------------------------------------------- |
| ThreatZone.Limits.E_Mail                 | String   | The owner e-mail of current plan.                                   |
| ThreatZone.Limits.API_Limit              | String   | The remaining/total API request limits of the current plan.         |
| ThreatZone.Limits.Concurrent_Limit       | String   | The remaining/total concurrent analysis limits of the current plan. |
| ThreatZone.Limits.Daily_Submission_Limit | String   | The remaining/total daily submission limits of the current plan.    |

#### Command Example

```tz-get-result uuid=95b6bc52-d040-4d82-a98b-af6fd5f6feea``` (Sandbox)

```tz-get-result uuid=7ddad84a-7f9b-4b56-b8f4-914287a0a1a3``` (Static-Scan)

```tz-get-result uuid=1170250a-40ac-4b73-84f7-3c0b6026d8af``` (CDR)

#### Context Example for Sandbox

Note: Long output parts are truncated

```json
{
  "DBotScore": {
    "Indicator": "80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108",
    "Reliability": "A - Completely reliable",
    "Score": 3,
    "Type": "file",
    "Vendor": "ThreatZone"
  },
  "File": {
    "Hashes": [
      {
        "type": "SHA256",
        "value": "80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108"
      }
    ],
    "Malicious": {
      "Description": null,
      "Vendor": "ThreatZone"
    },
    "SHA256": "80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108"
  },
  "ThreatZone": {
    "Analysis": {
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

Note: Long output parts are truncated

```json
{
  "DBotScore": {
    "Indicator": "e38dae160633fb5bf65a982374f1c7725c25ed32e89dbe2dce3a8f486cfae3cb",
    "Reliability": "A - Completely reliable",
    "Score": 2,
    "Type": "file",
    "Vendor": "ThreatZone"
  },
  "File": {
    "Hashes": [
      {
        "type": "SHA256",
        "value": "e38dae160633fb5bf65a982374f1c7725c25ed32e89dbe2dce3a8f486cfae3cb"
      }
    ],
    "SHA256": "e38dae160633fb5bf65a982374f1c7725c25ed32e89dbe2dce3a8f486cfae3cb"
  },
  "ThreatZone": {
    "Analysis": {
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
              {
                "address": "0x19030",
                "blacklist": false,
                "name": "IofCallDriver"
              },
              {
                "address": "0x19034",
                "blacklist": false,
                "name": "IoBuildPartialMdl"
              },
              {
                "address": "0x19038",
                "blacklist": false,
                "name": "IoAllocateMdl"
              },
              {
                "address": "0x1903c",
                "blacklist": false,
                "name": "IoFreeMdl"
              },
              {
                "address": "0x19040",
                "blacklist": false,
                "name": "ZwCreateKey"
              },
              {
                "address": "0x19044",
                "blacklist": false,
                "name": "ZwClose"
              },
              {
                "address": "0x19048",
                "blacklist": false,
                "name": "IoOpenDeviceRegistryKey"
              },
              {
                "address": "0x1904c",
                "blacklist": false,
                "name": "ZwDeleteKey"
              },
              {
                "address": "0x19050",
                "blacklist": false,
                "name": "ZwOpenKey"
              },
              {
                "address": "0x19054",
                "blacklist": false,
                "name": "IoFreeIrp"
              },
              {
                "address": "0x19058",
                "blacklist": false,
                "name": "IoAllocateIrp"
              },
              {
                "address": "0x1905c",
                "blacklist": false,
                "name": "memmove"
              },
              {
                "address": "0x19060",
                "blacklist": false,
                "name": "_allshl"
              },
              {
                "address": "0x19064",
                "blacklist": false,
                "name": "_allmul"
              },
              {
                "address": "0x19068",
                "blacklist": false,
                "name": "RtlAnsiStringToUnicodeString"
              },
              {
                "address": "0x1906c",
                "blacklist": false,
                "name": "RtlInitAnsiString"
              },
              {
                "address": "0x19070",
                "blacklist": false,
                "name": "RtlAppendUnicodeToString"
              },
              {
                "address": "0x19074",
                "blacklist": false,
                "name": "MmMapLockedPagesSpecifyCache"
              },
              {
                "address": "0x19078",
                "blacklist": false,
                "name": "InterlockedIncrement"
              },
              {
                "address": "0x1907c",
                "blacklist": false,
                "name": "IoDeleteDevice"
              },
              {
                "address": "0x19080",
                "blacklist": false,
                "name": "RtlEqualUnicodeString"
              },
              {
                "address": "0x19084",
                "blacklist": false,
                "name": "RtlFreeUnicodeString"
              },
              {
                "address": "0x19088",
                "blacklist": false,
                "name": "IoCreateDevice"
              },
              {
                "address": "0x1908c",
                "blacklist": false,
                "name": "RtlCompareUnicodeString"
              },
              {
                "address": "0x19090",
                "blacklist": false,
                "name": "ZwEnumerateKey"
              },
              {
                "address": "0x19094",
                "blacklist": false,
                "name": "IoInvalidateDeviceRelations"
              },
              {
                "address": "0x19098",
                "blacklist": false,
                "name": "KeSetImportanceDpc"
              },
              {
                "address": "0x1909c",
                "blacklist": false,
                "name": "_aullrem"
              },
              {
                "address": "0x190a0",
                "blacklist": false,
                "name": "KeSetEvent"
              },
              {
                "address": "0x190a4",
                "blacklist": false,
                "name": "KeInsertQueueDpc"
              },
              {
                "address": "0x190a8",
                "blacklist": false,
                "name": "ExfInterlockedInsertTailList"
              },
              {
                "address": "0x190ac",
                "blacklist": false,
                "name": "KefReleaseSpinLockFromDpcLevel"
              },
              {
                "address": "0x190b0",
                "blacklist": false,
                "name": "KefAcquireSpinLockAtDpcLevel"
              },
              {
                "address": "0x190b4",
                "blacklist": false,
                "name": "InterlockedDecrement"
              },
              {
                "address": "0x190b8",
                "blacklist": false,
                "name": "ExfInterlockedRemoveHeadList"
              },
              {
                "address": "0x190bc",
                "blacklist": false,
                "name": "MmBuildMdlForNonPagedPool"
              },
              {
                "address": "0x190c0",
                "blacklist": false,
                "name": "MmCreateMdl"
              },
              {
                "address": "0x190c4",
                "blacklist": false,
                "name": "KeInitializeDpc"
              },
              {
                "address": "0x190c8",
                "blacklist": false,
                "name": "KeInitializeEvent"
              },
              {
                "address": "0x190cc",
                "blacklist": false,
                "name": "PoSetPowerState"
              },
              {
                "address": "0x190d0",
                "blacklist": false,
                "name": "PoStartNextPowerIrp"
              },
              {
                "address": "0x190d4",
                "blacklist": false,
                "name": "KeWaitForSingleObject"
              },
              {
                "address": "0x190d8",
                "blacklist": false,
                "name": "ZwQueryValueKey"
              },
              {
                "address": "0x190dc",
                "blacklist": false,
                "name": "RtlAppendUnicodeStringToString"
              },
              {
                "address": "0x190e0",
                "blacklist": false,
                "name": "IoInitializeIrp"
              },
              {
                "address": "0x190e4",
                "blacklist": false,
                "name": "ObfDereferenceObject"
              },
              {
                "address": "0x190e8",
                "blacklist": false,
                "name": "ObfReferenceObject"
              },
              {
                "address": "0x190ec",
                "blacklist": false,
                "name": "RtlCopyUnicodeString"
              },
              {
                "address": "0x190f0",
                "blacklist": false,
                "name": "RtlInt64ToUnicodeString"
              },
              {
                "address": "0x190f4",
                "blacklist": false,
                "name": "RtlIntegerToUnicodeString"
              },
              {
                "address": "0x190f8",
                "blacklist": false,
                "name": "ExDeleteNPagedLookasideList"
              },
              {
                "address": "0x190fc",
                "blacklist": false,
                "name": "KeCancelTimer"
              },
              {
                "address": "0x19100",
                "blacklist": false,
                "name": "KeSetTimer"
              },
              {
                "address": "0x19104",
                "blacklist": false,
                "name": "ExInitializeNPagedLookasideList"
              },
              {
                "address": "0x19108",
                "blacklist": false,
                "name": "KeInitializeTimer"
              },
              {
                "address": "0x1910c",
                "blacklist": false,
                "name": "_aullshr"
              },
              {
                "address": "0x19110",
                "blacklist": false,
                "name": "KeTickCount"
              },
              {
                "address": "0x19114",
                "blacklist": false,
                "name": "KeBugCheckEx"
              },
              {
                "address": "0x19118",
                "blacklist": false,
                "name": "memset"
              },
              {
                "address": "0x1911c",
                "blacklist": false,
                "name": "KeInitializeSpinLock"
              },
              {
                "address": "0x19120",
                "blacklist": false,
                "name": "IoWMIRegistrationControl"
              },
              {
                "address": "0x19124",
                "blacklist": false,
                "name": "memcpy"
              },
              {
                "address": "0x19128",
                "blacklist": false,
                "name": "ExFreePool"
              },
              {
                "address": "0x1912c",
                "blacklist": false,
                "name": "ExAllocatePoolWithTag"
              },
              {
                "address": "0x19130",
                "blacklist": false,
                "name": "IofCompleteRequest"
              },
              {
                "address": "0x19134",
                "blacklist": false,
                "name": "KeSetTargetProcessorDpcEx"
              },
              {
                "address": "0x19138",
                "blacklist": false,
                "name": "RtlInitUnicodeString"
              },
              {
                "address": "0x1913c",
                "blacklist": false,
                "name": "ProbeForRead"
              },
              {
                "address": "0x19140",
                "blacklist": false,
                "name": "ExAllocatePoolWithQuotaTag"
              },
              {
                "address": "0x19144",
                "blacklist": false,
                "name": "RtlUnwind"
              }
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
            }
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

Note: Long output parts are truncated

```json
{
  "DBotScore": {
    "Indicator": "945678e901efcd35ece87a1a0eba82f39feb7d45ea4d38330a4795d1338872ca",
    "Reliability": "A - Completely reliable",
    "Score": 0,
    "Type": "file",
    "Vendor": "ThreatZone"
  },
  "File": {
    "Hashes": [
      {
        "type": "SHA256",
        "value": "945678e901efcd35ece87a1a0eba82f39feb7d45ea4d38330a4795d1338872ca"
      }
    ],
    "SHA256": "945678e901efcd35ece87a1a0eba82f39feb7d45ea4d38330a4795d1338872ca"
  },
  "ThreatZone": {
    "Analysis": {
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


| FILE_NAME                                 | MD5                              | PRIVATE | SCAN_URL                                                                                                                                           | SHA1                                     | SHA256                                                           | STATUS                 | THREAT_LEVEL | UUID                                 |
| ------------------------------------------- | ---------------------------------- | --------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------ | ------------------------ | -------------- | -------------------------------------- |
| fff2035c-def9-482c-9e1a-405c4d427833.docx | cf543c55343c6307349aafd098fb6958 | false | [https://app.threat.zone/submission/1170250a-40ac-4b73-84f7-3c0b6026d8af](https://app.threat.zone/submission/1170250a-40ac-4b73-84f7-3c0b6026d8af) | 1bec0d7bfea812ca7aa1f5399bb7ff3671006331 | 945678e901efcd35ece87a1a0eba82f39feb7d45ea4d38330a4795d1338872ca | Submission is finished | Not Measured | 1170250a-40ac-4b73-84f7-3c0b6026d8af |
