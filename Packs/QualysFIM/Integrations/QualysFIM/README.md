#Qualys FIM: File Integrity Monitoring

Log and track file changes across global IT systems.
This integration was integrated and tested with version 2.6.0.0-23 of qualys_fim
## Configure qualys_fim in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username | Username for authentication | True |
| Password | Password for authentication | True |
| Qualys API Platform URL | The Qualys API server URL that you should use for API requests depends on the platform where your account is located.  Platforms and URLS: Qualys US Platform 1: https://gateway.qg1.apps.qualys.com Qualys US Platform 2: https://gateway.qg2.apps.qualys.com Qualys US Platform 3: https://gateway.qg3.apps.qualys.com Qualys EU Platform 1: https://gateway.qg1.apps.qualys.eu Qualys EU Platform 2: https://gateway.qg2.apps.qualys.eu Qualys India Platform 1: https://gateway.qg1.apps.qualys.in Qualys Private Cloud Platform\(Custom Platform\): https://gateway.\<customer_base_url\> | True |
| Fetch incidents | Fetch incidents| False |
| Fetch time | First fetch timestamp (\<number\> \<time unit\>) e.g., 12 hours, 7 days | False |
| Incident Type | Incident type | False |
| Max Fetch | Max Fetch is limited to 200 incidents per fetch. Choose a value lower than 200. | False |
| Fetch Filter | Filter the incidents fetching by providing a query using Qualys syntax i.e., "id:ebe6c64a-8b0d-3401-858d-d57fb25860c7". Refer to the "How to Search" Qualys FIM guide for more information about Qualys syntax: https://qualysguard.qg2.apps.qualys.com/fim/help/search/language.htm | False |
| Insecure | Trust any certificate (not secure) | False |
| Proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### qualys-fim-events-list
***
Retrieve a list of all FIM events from the current user account.


#### Base Command

`qualys-fim-events-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Filter the events list by providing a query using Qualys syntax. i.e., "id:ebe6c64a-8b0d-3401-858d-d57fb25860c7". Refer to the "How to Search" Qualys FIM guide for more information about Qualys syntax: https://qualysguard.qg2.apps.qualys.com/fim/help/search/language.htm. | Optional | 
| page_number | Page number (index) to list items from. The "limit" argument defines the page size (the number of items in a page). | Optional | 
| limit | The number of records to include. | Optional | 
| incident_ids | Comma-separated list of incident IDs to be included while searching for events in incidents. | Optional | 
| sort | The method by which to sort the requested events. Possible values: "most_recent" and "least_recent". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QualysFIM.Events.id | str | Event ID. | 
| QualysFIM.Events.fullPath | str | Full path of the event. | 
| QualysFIM.Events.dateTime | str | Date/time the event occurred.  | 
| QualysFIM.Events.severity | int | Event severity. | 
| QualysFIM.Events.agentId | str | Agent ID. | 


#### Command Example
```!qualys-fim-events-list limit=12 sort=least_recent filter=severity:4```

#### Context Example
```json
{
    "QualysFIM": {
        "Event": [
            {
                "action": "Content",
                "actor": {
                    "imagePath": "\\Device\\HarddiskVolume2\\Windows\\System32\\svchost.exe",
                    "process": "svchost.exe",
                    "processID": 320,
                    "userID": "1-2-3-4",
                    "userName": "nt authority\\system"
                },
                "asset": {
                    "agentId": "12345678",
                    "agentVersion": "4.0.0.411",
                    "assetType": "HOST",
                    "created": "2021-01-17T16:01:41.086+0000",
                    "ec2": null,
                    "hostId": "15994867",
                    "interfaces": [
                        {
                            "address": "8.8.8.8",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        },
                        {
                            "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        }
                    ],
                    "lastCheckedIn": "2021-01-17T16:16:57.057Z",
                    "lastLoggedOnUser": "User",
                    "name": "DC.user.local",
                    "netbiosName": "DC",
                    "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                    "system": {
                        "lastBoot": "2021-01-17T16:16:57.057Z"
                    },
                    "tags": [
                        "78721806"
                    ],
                    "updated": "2021-01-17T16:01:41.086+0000"
                },
                "changedAttributes": null,
                "class": "Disk",
                "customerId": "12345678999",
                "dateTime": "2021-01-17T16:16:57.843+0000",
                "fullPath": "\\Device\\HarddiskVolume2\\Windows\\System32\\LogFiles\\Sum\\Svc.log",
                "id": "de361739-a082-3240-8459-786b8ed5fa3b",
                "incidentId": "4710aa44-8d69-4c00-8013-737768cb54be",
                "name": "Svc.log",
                "newContent": null,
                "oldContent": null,
                "platform": "WINDOWS",
                "processedTime": "2021-01-17T16:18:56.786+0000",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "rules": [
                            {
                                "description": "",
                                "id": "bd760834-5bce-41ab-9ab4-47d8da94a145",
                                "name": "System32",
                                "number": 1,
                                "section": null,
                                "severity": 4,
                                "type": "directory"
                            }
                        ],
                        "type": "WINDOWS"
                    }
                ],
                "severity": 4,
                "type": "File"
            },
            {
                "action": "Content",
                "actor": {
                    "imagePath": "",
                    "process": "",
                    "processID": 4,
                    "userID": "1-2-3-4",
                    "userName": "nt authority\\system"
                },
                "asset": {
                    "agentId": "12345678",
                    "agentVersion": "4.0.0.411",
                    "assetType": "HOST",
                    "created": "2021-01-17T16:01:41.086+0000",
                    "ec2": null,
                    "hostId": "15994867",
                    "interfaces": [
                        {
                            "address": "8.8.8.8",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        },
                        {
                            "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        }
                    ],
                    "lastCheckedIn": "2021-01-17T16:16:57.057Z",
                    "lastLoggedOnUser": "QMASTERS",
                    "name": "DC.qmasters.local",
                    "netbiosName": "DC",
                    "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                    "system": {
                        "lastBoot": "2021-01-17T16:16:57.057Z"
                    },
                    "tags": [
                        "78721806"
                    ],
                    "updated": "2021-01-17T16:01:41.086+0000"
                },
                "changedAttributes": null,
                "class": "Disk",
                "customerId": "12345678999",
                "dateTime": "2021-01-17T16:17:02.606+0000",
                "fullPath": "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\SOFTWARE.LOG2",
                "id": "a123456",
                "incidentId": "4710aa44-8d69-4c00-8013-737768cb54be",
                "name": "SOFTWARE.LOG2",
                "newContent": null,
                "oldContent": null,
                "platform": "WINDOWS",
                "processedTime": "2021-01-17T16:18:56.790+0000",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "rules": [
                            {
                                "description": "",
                                "id": "bd760834-5bce-41ab-9ab4-47d8da94a145",
                                "name": "System32",
                                "number": 1,
                                "section": null,
                                "severity": 4,
                                "type": "directory"
                            }
                        ],
                        "type": "WINDOWS"
                    }
                ],
                "severity": 4,
                "type": "File"
            },
            {
                "action": "Content",
                "actor": {
                    "imagePath": "\\Device\\HarddiskVolume2\\Windows\\System32\\svchost.exe",
                    "process": "svchost.exe",
                    "processID": 400,
                    "userID": "S-1-5-19",
                    "userName": "nt authority\\local service"
                },
                "asset": {
                    "agentId": "12345678",
                    "agentVersion": "4.0.0.411",
                    "assetType": "HOST",
                    "created": "2021-01-17T16:01:41.086+0000",
                    "ec2": null,
                    "hostId": "15994867",
                    "interfaces": [
                        {
                            "address": "8.8.8.8",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        },
                        {
                            "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        }
                    ],
                    "lastCheckedIn": "2021-01-17T16:16:57.057Z",
                    "lastLoggedOnUser": "QMASTERS",
                    "name": "DC.qmasters.local",
                    "netbiosName": "DC",
                    "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                    "system": {
                        "lastBoot": "2021-01-17T16:16:57.057Z"
                    },
                    "tags": [
                        "78721806"
                    ],
                    "updated": "2021-01-17T16:01:41.086+0000"
                },
                "changedAttributes": null,
                "class": "Disk",
                "customerId": "12345678999",
                "dateTime": "2021-01-17T16:17:52.405+0000",
                "fullPath": "\\Device\\HarddiskVolume2\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Known Folders API Service.evtx",
                "id": "366b1576-57f2-335f-9929-3026f5111767",
                "incidentId": "4710aa44-8d69-4c00-8013-737768cb54be",
                "name": "Microsoft-Windows-Known Folders API Service.evtx",
                "newContent": null,
                "oldContent": null,
                "platform": "WINDOWS",
                "processedTime": "2021-01-17T16:18:56.792+0000",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "rules": [
                            {
                                "description": "",
                                "id": "bd760834-5bce-41ab-9ab4-47d8da94a145",
                                "name": "System32",
                                "number": 1,
                                "section": null,
                                "severity": 4,
                                "type": "directory"
                            }
                        ],
                        "type": "WINDOWS"
                    }
                ],
                "severity": 4,
                "type": "File"
            },
            {
                "action": "Create",
                "actor": {
                    "imagePath": "\\Device\\HarddiskVolume2\\Windows\\winsxs\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.14393.693_none_42ff55c9655f38bf\\TiWorker.exe",
                    "process": "TiWorker.exe",
                    "processID": 1592,
                    "userID": "S-1-5-18",
                    "userName": "nt authority\\system"
                },
                "asset": {
                    "agentId": "12345678",
                    "agentVersion": "4.0.0.411",
                    "assetType": "HOST",
                    "created": "2021-01-17T16:01:41.086+0000",
                    "ec2": null,
                    "hostId": "15994867",
                    "interfaces": [
                        {
                            "address": "8.8.8.8",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        },
                        {
                            "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        }
                    ],
                    "lastCheckedIn": "2021-01-17T16:16:57.057Z",
                    "lastLoggedOnUser": "QMASTERS",
                    "name": "DC.qmasters.local",
                    "netbiosName": "DC",
                    "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                    "system": {
                        "lastBoot": "2021-01-17T16:16:57.057Z"
                    },
                    "tags": [
                        "78721806"
                    ],
                    "updated": "2021-01-17T16:01:41.086+0000"
                },
                "changedAttributes": [
                    2
                ],
                "class": "Disk",
                "customerId": "12345678999",
                "dateTime": "2021-01-17T16:18:20.743+0000",
                "fullPath": "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.blf",
                "id": "ea119f31-162a-3d0c-b2f7-01b32b6bc015",
                "incidentId": "778c1168-bc37-476a-aff8-3eadcd2489e9",
                "name": "COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.blf",
                "newContent": null,
                "oldContent": null,
                "platform": "WINDOWS",
                "processedTime": "2021-01-17T16:18:56.786+0000",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "rules": [
                            {
                                "description": "",
                                "id": "bd760834-5bce-41ab-9ab4-47d8da94a145",
                                "name": "System32",
                                "number": 1,
                                "section": null,
                                "severity": 4,
                                "type": "directory"
                            }
                        ],
                        "type": "WINDOWS"
                    }
                ],
                "severity": 4,
                "type": "File"
            },
            {
                "action": "Content",
                "actor": {
                    "imagePath": "\\Device\\HarddiskVolume2\\Windows\\winsxs\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.14393.693_none_42ff55c9655f38bf\\TiWorker.exe",
                    "process": "TiWorker.exe",
                    "processID": 1592,
                    "userID": "S-1-5-18",
                    "userName": "nt authority\\system"
                },
                "asset": {
                    "agentId": "12345678",
                    "agentVersion": "4.0.0.411",
                    "assetType": "HOST",
                    "created": "2021-01-17T16:01:41.086+0000",
                    "ec2": null,
                    "hostId": "15994867",
                    "interfaces": [
                        {
                            "address": "8.8.8.8",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        },
                        {
                            "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        }
                    ],
                    "lastCheckedIn": "2021-01-17T16:16:57.057Z",
                    "lastLoggedOnUser": "QMASTERS",
                    "name": "DC.qmasters.local",
                    "netbiosName": "DC",
                    "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                    "system": {
                        "lastBoot": "2021-01-17T16:16:57.057Z"
                    },
                    "tags": [
                        "78721806"
                    ],
                    "updated": "2021-01-17T16:01:41.086+0000"
                },
                "changedAttributes": null,
                "class": "Disk",
                "customerId": "12345678999",
                "dateTime": "2021-01-17T16:18:20.752+0000",
                "fullPath": "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.0.regtrans-ms",
                "id": "16aff3b1-6198-3996-bfb7-ee99cd3bbe2d",
                "incidentId": "778c1168-bc37-476a-aff8-3eadcd2489e9",
                "name": "COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.0.regtrans-ms",
                "newContent": null,
                "oldContent": null,
                "platform": "WINDOWS",
                "processedTime": "2021-01-17T16:18:56.796+0000",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "rules": [
                            {
                                "description": "",
                                "id": "bd760834-5bce-41ab-9ab4-47d8da94a145",
                                "name": "System32",
                                "number": 1,
                                "section": null,
                                "severity": 4,
                                "type": "directory"
                            }
                        ],
                        "type": "WINDOWS"
                    }
                ],
                "severity": 4,
                "type": "File"
            },
            {
                "action": "Content",
                "actor": {
                    "imagePath": "\\Device\\HarddiskVolume2\\Windows\\winsxs\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.14393.693_none_42ff55c9655f38bf\\TiWorker.exe",
                    "process": "TiWorker.exe",
                    "processID": 1592,
                    "userID": "S-1-5-18",
                    "userName": "nt authority\\system"
                },
                "asset": {
                    "agentId": "12345678",
                    "agentVersion": "4.0.0.411",
                    "assetType": "HOST",
                    "created": "2021-01-17T16:01:41.086+0000",
                    "ec2": null,
                    "hostId": "15994867",
                    "interfaces": [
                        {
                            "address": "8.8.8.8",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        },
                        {
                            "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        }
                    ],
                    "lastCheckedIn": "2021-01-17T16:16:57.057Z",
                    "lastLoggedOnUser": "QMASTERS",
                    "name": "DC.qmasters.local",
                    "netbiosName": "DC",
                    "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                    "system": {
                        "lastBoot": "2021-01-17T16:16:57.057Z"
                    },
                    "tags": [
                        "78721806"
                    ],
                    "updated": "2021-01-17T16:01:41.086+0000"
                },
                "changedAttributes": null,
                "class": "Disk",
                "customerId": "12345678999",
                "dateTime": "2021-01-17T16:18:20.752+0000",
                "fullPath": "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.blf",
                "id": "8c96931f-db80-3e47-a79a-a0585ec77037",
                "incidentId": "778c1168-bc37-476a-aff8-3eadcd2489e9",
                "name": "COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.blf",
                "newContent": null,
                "oldContent": null,
                "platform": "WINDOWS",
                "processedTime": "2021-01-17T16:18:57.276+0000",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "rules": [
                            {
                                "description": "",
                                "id": "bd760834-5bce-41ab-9ab4-47d8da94a145",
                                "name": "System32",
                                "number": 1,
                                "section": null,
                                "severity": 4,
                                "type": "directory"
                            }
                        ],
                        "type": "WINDOWS"
                    }
                ],
                "severity": 4,
                "type": "File"
            },
            {
                "action": "Create",
                "actor": {
                    "imagePath": "\\Device\\HarddiskVolume2\\Windows\\winsxs\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.14393.693_none_42ff55c9655f38bf\\TiWorker.exe",
                    "process": "TiWorker.exe",
                    "processID": 1592,
                    "userID": "S-1-5-18",
                    "userName": "nt authority\\system"
                },
                "asset": {
                    "agentId": "12345678",
                    "agentVersion": "4.0.0.411",
                    "assetType": "HOST",
                    "created": "2021-01-17T16:01:41.086+0000",
                    "ec2": null,
                    "hostId": "15994867",
                    "interfaces": [
                        {
                            "address": "8.8.8.8",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        },
                        {
                            "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        }
                    ],
                    "lastCheckedIn": "2021-01-17T16:16:57.057Z",
                    "lastLoggedOnUser": "QMASTERS",
                    "name": "DC.qmasters.local",
                    "netbiosName": "DC",
                    "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                    "system": {
                        "lastBoot": "2021-01-17T16:16:57.057Z"
                    },
                    "tags": [
                        "78721806"
                    ],
                    "updated": "2021-01-17T16:01:41.086+0000"
                },
                "changedAttributes": [
                    2
                ],
                "class": "Disk",
                "customerId": "12345678999",
                "dateTime": "2021-01-17T16:18:20.752+0000",
                "fullPath": "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.0.regtrans-ms",
                "id": "421c080f-ebae-35ca-8ad4-19ac62554a0c",
                "incidentId": "778c1168-bc37-476a-aff8-3eadcd2489e9",
                "name": "COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.0.regtrans-ms",
                "newContent": null,
                "oldContent": null,
                "platform": "WINDOWS",
                "processedTime": "2021-01-17T16:18:56.785+0000",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "rules": [
                            {
                                "description": "",
                                "id": "bd760834-5bce-41ab-9ab4-47d8da94a145",
                                "name": "System32",
                                "number": 1,
                                "section": null,
                                "severity": 4,
                                "type": "directory"
                            }
                        ],
                        "type": "WINDOWS"
                    }
                ],
                "severity": 4,
                "type": "File"
            },
            {
                "action": "Create",
                "actor": {
                    "imagePath": "\\Device\\HarddiskVolume2\\Windows\\winsxs\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.14393.693_none_42ff55c9655f38bf\\TiWorker.exe",
                    "process": "TiWorker.exe",
                    "processID": 1592,
                    "userID": "S-1-5-18",
                    "userName": "nt authority\\system"
                },
                "asset": {
                    "agentId": "12345678",
                    "agentVersion": "4.0.0.411",
                    "assetType": "HOST",
                    "created": "2021-01-17T16:01:41.086+0000",
                    "ec2": null,
                    "hostId": "15994867",
                    "interfaces": [
                        {
                            "address": "8.8.8.8",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        },
                        {
                            "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        }
                    ],
                    "lastCheckedIn": "2021-01-17T16:16:57.057Z",
                    "lastLoggedOnUser": "QMASTERS",
                    "name": "DC.qmasters.local",
                    "netbiosName": "DC",
                    "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                    "system": {
                        "lastBoot": "2021-01-17T16:16:57.057Z"
                    },
                    "tags": [
                        "78721806"
                    ],
                    "updated": "2021-01-17T16:01:41.086+0000"
                },
                "changedAttributes": [
                    2
                ],
                "class": "Disk",
                "customerId": "12345678999",
                "dateTime": "2021-01-17T16:18:20.752+0000",
                "fullPath": "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.1.regtrans-ms",
                "id": "0cf60a82-b006-385a-ba14-f666733a063b",
                "incidentId": "778c1168-bc37-476a-aff8-3eadcd2489e9",
                "name": "COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.1.regtrans-ms",
                "newContent": null,
                "oldContent": null,
                "platform": "WINDOWS",
                "processedTime": "2021-01-17T16:18:56.790+0000",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "rules": [
                            {
                                "description": "",
                                "id": "bd760834-5bce-41ab-9ab4-47d8da94a145",
                                "name": "System32",
                                "number": 1,
                                "section": null,
                                "severity": 4,
                                "type": "directory"
                            }
                        ],
                        "type": "WINDOWS"
                    }
                ],
                "severity": 4,
                "type": "File"
            },
            {
                "action": "Content",
                "actor": {
                    "imagePath": "\\Device\\HarddiskVolume2\\Windows\\winsxs\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.14393.693_none_42ff55c9655f38bf\\TiWorker.exe",
                    "process": "TiWorker.exe",
                    "processID": 1592,
                    "userID": "S-1-5-18",
                    "userName": "nt authority\\system"
                },
                "asset": {
                    "agentId": "12345678",
                    "agentVersion": "4.0.0.411",
                    "assetType": "HOST",
                    "created": "2021-01-17T16:01:41.086+0000",
                    "ec2": null,
                    "hostId": "15994867",
                    "interfaces": [
                        {
                            "address": "8.8.8.8",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        },
                        {
                            "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        }
                    ],
                    "lastCheckedIn": "2021-01-17T16:16:57.057Z",
                    "lastLoggedOnUser": "QMASTERS",
                    "name": "DC.qmasters.local",
                    "netbiosName": "DC",
                    "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                    "system": {
                        "lastBoot": "2021-01-17T16:16:57.057Z"
                    },
                    "tags": [
                        "78721806"
                    ],
                    "updated": "2021-01-17T16:01:41.086+0000"
                },
                "changedAttributes": null,
                "class": "Disk",
                "customerId": "12345678999",
                "dateTime": "2021-01-17T16:18:20.752+0000",
                "fullPath": "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.1.regtrans-ms",
                "id": "0e5d5385-8dac-31a8-846c-29755c73cf88",
                "incidentId": "778c1168-bc37-476a-aff8-3eadcd2489e9",
                "name": "COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.1.regtrans-ms",
                "newContent": null,
                "oldContent": null,
                "platform": "WINDOWS",
                "processedTime": "2021-01-17T16:18:56.785+0000",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "rules": [
                            {
                                "description": "",
                                "id": "bd760834-5bce-41ab-9ab4-47d8da94a145",
                                "name": "System32",
                                "number": 1,
                                "section": null,
                                "severity": 4,
                                "type": "directory"
                            }
                        ],
                        "type": "WINDOWS"
                    }
                ],
                "severity": 4,
                "type": "File"
            },
            {
                "action": "Content",
                "actor": {
                    "imagePath": "\\Device\\HarddiskVolume2\\Windows\\winsxs\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.14393.693_none_42ff55c9655f38bf\\TiWorker.exe",
                    "process": "TiWorker.exe",
                    "processID": 1592,
                    "userID": "S-1-5-18",
                    "userName": "nt authority\\system"
                },
                "asset": {
                    "agentId": "12345678",
                    "agentVersion": "4.0.0.411",
                    "assetType": "HOST",
                    "created": "2021-01-17T16:01:41.086+0000",
                    "ec2": null,
                    "hostId": "15994867",
                    "interfaces": [
                        {
                            "address": "8.8.8.8",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        },
                        {
                            "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        }
                    ],
                    "lastCheckedIn": "2021-01-17T16:16:57.057Z",
                    "lastLoggedOnUser": "QMASTERS",
                    "name": "DC.qmasters.local",
                    "netbiosName": "DC",
                    "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                    "system": {
                        "lastBoot": "2021-01-17T16:16:57.057Z"
                    },
                    "tags": [
                        "78721806"
                    ],
                    "updated": "2021-01-17T16:01:41.086+0000"
                },
                "changedAttributes": null,
                "class": "Disk",
                "customerId": "12345678999",
                "dateTime": "2021-01-17T16:18:20.768+0000",
                "fullPath": "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.2.regtrans-ms",
                "id": "68047fa3-8f25-3063-bce8-0b988b87190c",
                "incidentId": "778c1168-bc37-476a-aff8-3eadcd2489e9",
                "name": "COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.2.regtrans-ms",
                "newContent": null,
                "oldContent": null,
                "platform": "WINDOWS",
                "processedTime": "2021-01-17T16:18:57.276+0000",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "rules": [
                            {
                                "description": "",
                                "id": "bd760834-5bce-41ab-9ab4-47d8da94a145",
                                "name": "System32",
                                "number": 1,
                                "section": null,
                                "severity": 4,
                                "type": "directory"
                            }
                        ],
                        "type": "WINDOWS"
                    }
                ],
                "severity": 4,
                "type": "File"
            },
            {
                "action": "Create",
                "actor": {
                    "imagePath": "\\Device\\HarddiskVolume2\\Windows\\winsxs\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.14393.693_none_42ff55c9655f38bf\\TiWorker.exe",
                    "process": "TiWorker.exe",
                    "processID": 1592,
                    "userID": "S-1-5-18",
                    "userName": "nt authority\\system"
                },
                "asset": {
                    "agentId": "12345678",
                    "agentVersion": "4.0.0.411",
                    "assetType": "HOST",
                    "created": "2021-01-17T16:01:41.086+0000",
                    "ec2": null,
                    "hostId": "15994867",
                    "interfaces": [
                        {
                            "address": "8.8.8.8",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        },
                        {
                            "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        }
                    ],
                    "lastCheckedIn": "2021-01-17T16:16:57.057Z",
                    "lastLoggedOnUser": "QMASTERS",
                    "name": "DC.qmasters.local",
                    "netbiosName": "DC",
                    "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                    "system": {
                        "lastBoot": "2021-01-17T16:16:57.057Z"
                    },
                    "tags": [
                        "78721806"
                    ],
                    "updated": "2021-01-17T16:01:41.086+0000"
                },
                "changedAttributes": [
                    2
                ],
                "class": "Disk",
                "customerId": "12345678999",
                "dateTime": "2021-01-17T16:18:20.768+0000",
                "fullPath": "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.2.regtrans-ms",
                "id": "5d6084f2-3a47-3c71-8131-ebd2f1d7c684",
                "incidentId": "778c1168-bc37-476a-aff8-3eadcd2489e9",
                "name": "COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.2.regtrans-ms",
                "newContent": null,
                "oldContent": null,
                "platform": "WINDOWS",
                "processedTime": "2021-01-17T16:18:56.790+0000",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "rules": [
                            {
                                "description": "",
                                "id": "bd760834-5bce-41ab-9ab4-47d8da94a145",
                                "name": "System32",
                                "number": 1,
                                "section": null,
                                "severity": 4,
                                "type": "directory"
                            }
                        ],
                        "type": "WINDOWS"
                    }
                ],
                "severity": 4,
                "type": "File"
            },
            {
                "action": "Attributes",
                "actor": {
                    "imagePath": "",
                    "process": "",
                    "processID": 4,
                    "userID": "S-1-5-18",
                    "userName": "nt authority\\system"
                },
                "asset": {
                    "agentId": "12345678",
                    "agentVersion": "4.0.0.411",
                    "assetType": "HOST",
                    "created": "2021-01-17T16:01:41.086+0000",
                    "ec2": null,
                    "hostId": "15994867",
                    "interfaces": [
                        {
                            "address": "8.8.8.8",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        },
                        {
                            "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                            "hostname": "DC",
                            "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                            "macAddress": "00:0C:00:0B:A0:0E"
                        }
                    ],
                    "lastCheckedIn": "2021-01-17T16:16:57.057Z",
                    "lastLoggedOnUser": "QMASTERS",
                    "name": "DC.qmasters.local",
                    "netbiosName": "DC",
                    "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                    "system": {
                        "lastBoot": "2021-01-17T16:16:57.057Z"
                    },
                    "tags": [
                        "78721806"
                    ],
                    "updated": "2021-01-17T16:01:41.086+0000"
                },
                "changedAttributes": null,
                "class": "Disk",
                "customerId": "12345678999",
                "dateTime": "2021-01-17T16:18:46.955+0000",
                "fullPath": "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\SOFTWARE.LOG2",
                "id": "2e84bdd4-5395-3549-a29f-548e3aca0e83",
                "incidentId": "4710aa44-8d69-4c00-8013-737768cb54be",
                "name": "SOFTWARE.LOG2",
                "newContent": null,
                "oldContent": null,
                "platform": "WINDOWS",
                "processedTime": "2021-01-17T16:23:59.023+0000",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "rules": [
                            {
                                "description": "",
                                "id": "bd760834-5bce-41ab-9ab4-47d8da94a145",
                                "name": "System32",
                                "number": 1,
                                "section": null,
                                "severity": 4,
                                "type": "directory"
                            }
                        ],
                        "type": "WINDOWS"
                    }
                ],
                "severity": 4,
                "type": "File"
            }
        ]
    }
}
```

#### Human Readable Output

>### Listed 12 Events:
>|id|severity|dateTime|agentId|fullPath|
>|---|---|---|---|---|
>| de361739-a082-3240-8459-786b8ed5fa3b | 4 | 2021-01-17 16:16:57 | 12345678 | \Device\HarddiskVolume2\Windows\System32\LogFiles\Sum\Svc.log |
>| a123456 | 4 | 2021-01-17 16:17:02 | 12345678 | \Device\HarddiskVolume2\Windows\System32\config\SOFTWARE.LOG2 |
>| 366b1576-57f2-335f-9929-3026f5111767 | 4 | 2021-01-17 16:17:52 | 12345678 | \Device\HarddiskVolume2\Windows\System32\winevt\Logs\Microsoft-Windows-Known Folders API Service.evtx |
>| ea119f31-162a-3d0c-b2f7-01b32b6bc015 | 4 | 2021-01-17 16:18:20 | 12345678 | \Device\HarddiskVolume2\Windows\System32\config\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.blf |
>| 16aff3b1-6198-3996-bfb7-ee99cd3bbe2d | 4 | 2021-01-17 16:18:20 | 12345678 | \Device\HarddiskVolume2\Windows\System32\config\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.0.regtrans-ms |
>| 8c96931f-db80-3e47-a79a-a0585ec77037 | 4 | 2021-01-17 16:18:20 | 12345678 | \Device\HarddiskVolume2\Windows\System32\config\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.blf |
>| 421c080f-ebae-35ca-8ad4-19ac62554a0c | 4 | 2021-01-17 16:18:20 | 12345678 | \Device\HarddiskVolume2\Windows\System32\config\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.0.regtrans-ms |
>| 0cf60a82-b006-385a-ba14-f666733a063b | 4 | 2021-01-17 16:18:20 | 12345678 | \Device\HarddiskVolume2\Windows\System32\config\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.1.regtrans-ms |
>| 0e5d5385-8dac-31a8-846c-29755c73cf88 | 4 | 2021-01-17 16:18:20 | 12345678 | \Device\HarddiskVolume2\Windows\System32\config\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.1.regtrans-ms |
>| 68047fa3-8f25-3063-bce8-0b988b87190c | 4 | 2021-01-17 16:18:20 | 12345678 | \Device\HarddiskVolume2\Windows\System32\config\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.2.regtrans-ms |
>| 5d6084f2-3a47-3c71-8131-ebd2f1d7c684 | 4 | 2021-01-17 16:18:20 | 12345678 | \Device\HarddiskVolume2\Windows\System32\config\COMPONENTS{b30b23f5-4b70-11e6-80e6-e41d2d18dfd0}.TxR.2.regtrans-ms |
>| 2e84bdd4-5395-3549-a29f-548e3aca0e83 | 4 | 2021-01-17 16:18:46 | 12345678 | \Device\HarddiskVolume2\Windows\System32\config\SOFTWARE.LOG2 |


### qualys-fim-event-get
***
Retrieve information about a given event, by event ID.


#### Base Command

`qualys-fim-event-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | ID of the event to retrieve information about. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QualysFIM.Event.id | str | Event ID. | 
| QualysFIM.Event.fullPath | str | Full path of the event. | 
| QualysFIM.Event.dateTime | str | Date/time the event occurred.  | 
| QualysFIM.Event.name | str | Event name. | 
| QualysFIM.Event.severity | int | Event severity. | 
| QualysFIM.Event.action | str | Event action. | 
| QualysFIM.Event.incidentId | str | Event ID. | 
| QualysFIM.Event.profiles | str | List of all monitoring profiles name. | 


#### Command Example
```!qualys-fim-event-get event_id=de361739-a082-3240-8459-786b8ed5fa3b```

#### Context Example
```json
{
    "QualysFIM": {
        "Event": {
            "action": "Content",
            "actor": {
                "imagePath": "\\Device\\HarddiskVolume2\\Windows\\System32\\svchost.exe",
                "process": "svchost.exe",
                "processID": 320,
                "userID": "S-1-5-18",
                "userName": "nt authority\\system"
            },
            "asset": {
                "agentId": "12345678",
                "agentVersion": "4.0.0.411",
                "assetType": "HOST",
                "created": "2021-01-17T16:01:41.086+0000",
                "ec2": null,
                "hostId": "15994867",
                "interfaces": [
                    {
                        "address": "8.8.8.8",
                        "hostname": "DC",
                        "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                        "macAddress": "00:0C:00:0B:A0:0E"
                    },
                    {
                        "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                        "hostname": "DC",
                        "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                        "macAddress": "00:0C:00:0B:A0:0E"
                    }
                ],
                "lastCheckedIn": "2021-01-17T16:16:57.057Z",
                "lastLoggedOnUser": "QMASTERS",
                "name": "DC.qmasters.local",
                "netbiosName": "DC",
                "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                "system": {
                    "lastBoot": "2021-01-17T16:16:57.057Z"
                },
                "tags": [
                    "78721806"
                ],
                "updated": "2021-01-17T16:01:41.086+0000"
            },
            "changedAttributes": null,
            "class": "Disk",
            "customerId": "12345678999",
            "dateTime": "2021-01-17T16:16:57.843+0000",
            "fullPath": "\\Device\\HarddiskVolume2\\Windows\\System32\\LogFiles\\Sum\\Svc.log",
            "id": "de361739-a082-3240-8459-786b8ed5fa3b",
            "incidentId": "4710aa44-8d69-4c00-8013-737768cb54be",
            "name": "Svc.log",
            "newContent": null,
            "oldContent": null,
            "platform": "WINDOWS",
            "processedTime": "2021-01-17T16:18:56.786+0000",
            "profiles": [
                {
                    "category": {
                        "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                        "name": "PCI"
                    },
                    "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                    "name": "test_01",
                    "rules": [
                        {
                            "description": "",
                            "id": "bd760834-5bce-41ab-9ab4-47d8da94a145",
                            "name": "System32",
                            "number": 1,
                            "section": null,
                            "severity": 4,
                            "type": "directory"
                        }
                    ],
                    "type": "WINDOWS"
                }
            ],
            "severity": 4,
            "type": "File"
        }
    }
}
```

#### Human Readable Output

>### Found Event:
>|name|action|id|severity|action|incidentId|profiles|type|dateTime|fullPath|
>|---|---|---|---|---|---|---|---|---|---|
>| Svc.log | Content | de361739-a082-3240-8459-786b8ed5fa3b | 4 | Content | 4710aa44-8d69-4c00-8013-737768cb54be | test_01 | File | 2021-01-17 16:16:57 | \Device\HarddiskVolume2\Windows\System32\LogFiles\Sum\Svc.log |


### qualys-fim-incidents-list
***
Retrieve a list of all FIM incidents from the current user account.


#### Base Command

`qualys-fim-incidents-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Filter the events list by providing a query using Qualys syntax. i.e., "id:ebe6c64a-8b0d-3401-858d-d57fb25860c7". Refer to the "How to Search" Qualys FIM guide for more information about Qualys syntax: https://qualysguard.qg2.apps.qualys.com/fim/help/search/language.htm. | Optional | 
| page_number | Page number (index) to list items from. The "limit" argument defines the page size (the number of items in a page). | Optional | 
| limit | The number of records to include. | Optional | 
| attributes | Comma-separated list of attributes to include in the response. By default, all attributes will be returned in the result, i.e., attributes="attributes=name,id". | Optional | 
| sort | The method by which to sort the requested events. Possible values: "most_recent" and "least_recent". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QualysFIM.Incidents.id | str | Incident ID. | 
| QualysFIM.Incidents.name | str | Incident name. | 
| QualysFIM.Incidents.type | str | Incident type. | 
| QualysFIM.Incidents.occurred | str | Indicates when the incident was created. | 
| QualysFIM.Incidents.username | str | Name of the user who created this incident. | 
| QualysFIM.Incidents.status | str | Incident status. | 


#### Command Example
```!qualys-fim-incidents-list sort=least_recent limit=15 attributes=name,status,id filter=status:closed```

#### Context Example
```json
{
    "QualysFIM": {
        "Incident": [
            {
                "id": "4710aa44-8d69-4c00-8013-737768cb54be",
                "name": "Deletion of Log Files",
                "status": "CLOSED"
            },
            {
                "id": "179e5d4e-1153-4d12-9980-4807b78fee62",
                "name": "test700",
                "status": "CLOSED"
            },
            {
                "id": "b53eac81-902a-4c38-aee0-11f3b62d92fb",
                "name": "w2www",
                "status": "CLOSED"
            },
            {
                "id": "b1f8c69b-e6ff-4470-8cf1-b37bd793d90d",
                "name": "ppp3",
                "status": "CLOSED"
            },
            {
                "id": "b576c51b-480a-44d2-a19e-98b2c6cda4af",
                "name": "www",
                "status": "CLOSED"
            },
            {
                "id": "497ab672-c65b-42c1-a913-8c62a8262cce",
                "name": "rrr",
                "status": "CLOSED"
            },
            {
                "id": "7b182a08-413e-4777-9493-9a23eb8c7e9e",
                "name": "testtest2",
                "status": "CLOSED"
            },
            {
                "id": "2ebf1510-2fa3-4e53-9475-a9377cb81673",
                "name": "test_incident_31",
                "status": "CLOSED"
            },
            {
                "id": "61c90caf-ea98-45eb-82db-469a27105e91",
                "name": "test 15",
                "status": "CLOSED"
            },
            {
                "id": "7b63aed9-b849-4c49-8b33-b6bf56bcfc79",
                "name": "ppp",
                "status": "CLOSED"
            },
            {
                "id": "d223968d-fa86-43c2-b7d6-4de0e2100a0d",
                "name": "777",
                "status": "CLOSED"
            },
            {
                "id": "2ad82774-d6e9-4e33-913c-d6a1729530e0",
                "name": "ll2",
                "status": "CLOSED"
            },
            {
                "id": "c5815a31-508b-469e-8990-e81ce2c6f33e",
                "name": "testtest1",
                "status": "CLOSED"
            },
            {
                "id": "b6997b4d-8451-438b-9333-0f1ec81b870c",
                "name": "test100",
                "status": "CLOSED"
            },
            {
                "id": "a9be84fd-5a7f-45b1-9f69-b1507ab2b218",
                "name": "wwww",
                "status": "CLOSED"
            }
        ]
    }
}
```

#### Human Readable Output

>### Listed 15 Incidents:
>|id|name|status|
>|---|---|---|
>| 4710aa44-8d69-4c00-8013-737768cb54be | Deletion of Log Files | CLOSED |
>| 179e5d4e-1153-4d12-9980-4807b78fee62 | test700 | CLOSED |
>| b53eac81-902a-4c38-aee0-11f3b62d92fb | w2www | CLOSED |
>| b1f8c69b-e6ff-4470-8cf1-b37bd793d90d | ppp3 | CLOSED |
>| b576c51b-480a-44d2-a19e-98b2c6cda4af | www | CLOSED |
>| 497ab672-c65b-42c1-a913-8c62a8262cce | rrr | CLOSED |
>| 7b182a08-413e-4777-9493-9a23eb8c7e9e | testtest2 | CLOSED |
>| 2ebf1510-2fa3-4e53-9475-a9377cb81673 | test_incident_31 | CLOSED |
>| 61c90caf-ea98-45eb-82db-469a27105e91 | test 15 | CLOSED |
>| 7b63aed9-b849-4c49-8b33-b6bf56bcfc79 | ppp | CLOSED |
>| d223968d-fa86-43c2-b7d6-4de0e2100a0d | 777 | CLOSED |
>| 2ad82774-d6e9-4e33-913c-d6a1729530e0 | ll2 | CLOSED |
>| c5815a31-508b-469e-8990-e81ce2c6f33e | testtest1 | CLOSED |
>| b6997b4d-8451-438b-9333-0f1ec81b870c | test100 | CLOSED |
>| a9be84fd-5a7f-45b1-9f69-b1507ab2b218 | wwww | CLOSED |


### qualys-fim-incidents-get-events
***
Retrieve a list of the events logged under an incident.


#### Base Command

`qualys-fim-incidents-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | ID of the incident to retrieve the events for. | Required | 
| filter | Filter the events list by providing a query using Qualys syntax. i.e., "id:ebe6c64a-8b0d-3401-858d-d57fb25860c7". Refer to the "How to Search" Qualys FIM guide for more information about Qualys syntax: https://qualysguard.qg2.apps.qualys.com/fim/help/search/language.htm. | Optional | 
| page_number | Page number (index) to list items from. The "limit" argument defines the page size (the number of items in a page). | Optional | 
| limit | The number of records to include. | Optional | 
| attributes | Comma-separated list of attributes to include in the response. By default, all attributes will be returned in the result, i.e., attributes="attributes=name,id". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QualysFIM.IncidentEvents.id | str | Event ID. | 
| QualysFIM.IncidentEvents.name | str | Event name. | 
| QualysFIM.IncidentEvents.severity | str | Event severity. | 
| QualysFIM.IncidentEvents.type | str | Event type. | 
| QualysFIM.IncidentEvents.occurred | str | Indicates when the event was created. | 
| QualysFIM.IncidentEvents.username | str | Name of the user who created this incident. | 
| QualysFIM.IncidentEvents.status | str | Incident status. | 
| QualysFIM.IncidentEvents.action | str | Action that was taken that triggered the event creation. | 


#### Command Example
```!qualys-fim-incidents-get-events incident_id=4710aa44-8d69-4c00-8013-737768cb54be limit=7 attributes=id,name,type page_number=2 filter=action:create```

#### Context Example
```json
{
    "QualysFIM": {
        "Event": [
            {
                "id": "85873770-2c46-3c1c-94f6-a1fd117ca504",
                "name": "8fe303d4743fc547b447af276bb19008",
                "type": "File"
            },
            {
                "id": "2e3ca9c5-354f-3f3d-a16b-c390b3b139d2",
                "name": "6f3604d7c44b1b44b1addd026d40f547",
                "type": "File"
            },
            {
                "id": "cb8fd91a-5f0a-374e-9ccc-a1d762273322",
                "name": "tw-4080-41f0-b2f98d.tmp",
                "type": "File"
            },
            {
                "id": "b267ddd7-308d-33f6-863e-fc85efaae6de",
                "name": "SRUtmp.log",
                "type": "File"
            },
            {
                "id": "b129d76f-827f-3f1e-babb-e96fbfbdc697",
                "name": "oem117.cat",
                "type": "File"
            },
            {
                "id": "87399be0-69fe-3881-85a1-b01ce1288672",
                "name": "EtwRTTerminal-Services-LSM-ApplicationLag-6812.etl",
                "type": "File"
            },
            {
                "id": "0636da15-3c33-359f-9574-0bbc2d331e8a",
                "name": "SRUtmp.log",
                "type": "File"
            }
        ]
    }
}
```

#### Human Readable Output

>### Listed 7 Events From Incident:
>|id|name|type|
>|---|---|---|
>| 85873770-2c46-3c1c-94f6-a1fd117ca504 | 8fe303d4743fc547b447af276bb19008 | File |
>| 2e3ca9c5-354f-3f3d-a16b-c390b3b139d2 | 6f3604d7c44b1b44b1addd026d40f547 | File |
>| cb8fd91a-5f0a-374e-9ccc-a1d762273322 | tw-4080-41f0-b2f98d.tmp | File |
>| b267ddd7-308d-33f6-863e-fc85efaae6de | SRUtmp.log | File |
>| b129d76f-827f-3f1e-babb-e96fbfbdc697 | oem117.cat | File |
>| 87399be0-69fe-3881-85a1-b01ce1288672 | EtwRTTerminal-Services-LSM-ApplicationLag-6812.etl | File |
>| 0636da15-3c33-359f-9574-0bbc2d331e8a | SRUtmp.log | File |


### qualys-fim-incident-create
***
Create a manual FIM incident of type "DEFAULT".


#### Base Command

`qualys-fim-incident-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | Date from which to start the event search. Example format: yyyy-mm-dd, 2021-01-01. | Optional | 
| to_date | Date at which to stop the event search. Example format: yyyy-mm-dd, 2021-02-30. | Optional | 
| filters | Filter the events list by providing a query using Qualys syntax. i.e., "dateTime : ['2021-01-01'..'2021-03-29']. When you use this argument it will overwrite the "from_date" and "to_date" arguments. If you don't use the filter, the query will include the events from the last 24 hours. Refer to the "How to Search" Qualys FIM guide for more information about Qualys syntax: https://qualysguard.qg2.apps.qualys.com/fim/help/search/language.htm. | Optional | 
| name | The name of the incident. Must be less than 128 characters. | Required | 
| reviewers | Reviewers who will approve the incident. | Optional | 
| comment | Comments for approval of the incident. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QualysFIM.CreatedIncident.id | str | Incident ID. | 
| QualysFIM.CreatedIncident.name | str | Incident name. | 
| QualysFIM.CreatedIncident.occurred | str | Indicates when the incident was created. | 
| QualysFIM.CreatedIncident.username | str | Name of the user who created the incident. | 
| QualysFIM.CreatedIncident.status | str | Incident status. | 
| QualysFIM.CreatedIncident.reviewers | str | List of reviewers who will approve the incident. | 


#### Command Example
```!qualys-fim-incident-create name=testtest7 comment=new_incident filters="dateTime: ['2021-01-01'..'2021-02-15']"```

#### Context Example
```json
{
    "QualysFIM": {
        "CreatedIncident": {
            "approvalType": "MANUAL",
            "customerId": "12345678999",
            "filters": [
                "dateTime: ['2021-01-01'..'2021-02-15']"
            ],
            "id": "5f9f5504-46eb-4a30-b022-fd0dba7758eb",
            "name": "testtest7",
            "reviewers": [
                "useruser"
            ],
            "type": "DEFAULT",
            "userInfo": {
                "date": 1613469168294,
                "user": {
                    "id": "1a7f00bd-cbde-7d97-831f-ba25de45c44e",
                    "name": "Qmasters"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Created New Incident: testtest7
>|id|name|reviewers|username|occurred|filters|approvalType|
>|---|---|---|---|---|---|---|
>| 5f9f5504-46eb-4a30-b022-fd0dba7758eb | testtest7 | useruser | Qmasters | 2021-02-16 09:52:48 | dateTime: ['2021-01-01'..'2021-02-15'] | MANUAL |


### qualys-fim-incident-approve
***
Mark an existing FIM incident as approved.


#### Base Command

`qualys-fim-incident-approve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| approval_status | The approval status of the incident. Possible values: "APPROVED", "POLICY_VIOLATION", "UNAPPROVED". | Required | 
| change_type | Type of incidents. Possible values: "MANUAL", "AUTOMATED", "COMPROMISE", "OTHER". | Required | 
| comment | Comments for the incidents. | Required | 
| incident_id | incident ID to approve. | Required | 
| disposition_category | The category of the incident created by the rule. Possible values: "PATCHING", "PRE_APPROVED_CHANGE_CONTROL", "CONFIGURATION_CHANGE", "HUMAN_ERROR", "DATA_CORRUPTION", "EMERGENCY_CHANGE", "CHANGE_CONTROL_VIOLATION", "GENERAL_HACKING", "MALWARE". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QualysFIM.ApprovedIncident.id | str | Incident ID. | 
| QualysFIM.ApprovedIncident.name | str | Incident name. | 
| QualysFIM.ApprovedIncident.type | str | Incident type. | 
| QualysFIM.ApprovedIncident.filterFromDate | str | The date from which to filter the approved incident. | 
| QualysFIM.ApprovedIncident.filterToDate | str | The date until when to filter the approved incident. | 
| QualysFIM.ApprovedIncident.approvalDate | str | Approval date of the incident. | 
| QualysFIM.ApprovedIncident.approvalStatus | str | Approval status of the incident. | 
| QualysFIM.ApprovedIncident.comment | str | Comments for incidents created by the rule. | 
| QualysFIM.ApprovedIncident.username | str | Name of the user who created this incident. | 
| QualysFIM.ApprovedIncident.status | str | Incident status. | 
| QualysFIM.ApprovedIncident.reviewers | str | List of reviewers who will approve the incident. | 


#### Command Example
```!qualys-fim-incident-approve incident_id=8af30349-bd07-4c0d-8469-58d9d7218ffa approval_status=APPROVED change_type=AUTOMATED comment=approved disposition_category=MALWARE```

#### Context Example
```json
{
    "QualysFIM": {
        "Incident": {
            "approvalDate": "2021-02-16T09:52:49.985+0000",
            "approvalStatus": "APPROVED",
            "approvalType": "MANUAL",
            "assignDate": "2021-02-16T09:46:44.769+0000",
            "changeType": "AUTOMATED",
            "comment": "approved",
            "createdById": "1a7f00bd-cbde-7d97-831f-ba25de45c44e",
            "createdByName": "Qmasters",
            "createdDate": "2021-02-16T09:46:44.768+0000",
            "customerId": "12345678999",
            "deleted": false,
            "dispositionCategory": "MALWARE",
            "filterFromDate": "2021-01-01T00:00:00.000+0000",
            "filterToDate": "2021-02-15T00:00:00.000+0000",
            "filterUpdatedDate": "2021-02-16T09:46:44.768+0000",
            "filters": [
                "dateTime: ['2021-01-01'..'2021-02-15']"
            ],
            "id": "8af30349-bd07-4c0d-8469-58d9d7218ffa",
            "lastUpdatedById": "1a7f00bd-cbde-7d97-831f-ba25de45c44e",
            "lastUpdatedByName": "Qmasters",
            "lastUpdatedDate": "2021-02-16T09:46:44.768+0000",
            "marked": false,
            "markupStatus": null,
            "moved": null,
            "name": "testtest",
            "reviewers": [
                "useruser"
            ],
            "ruleId": null,
            "ruleName": null,
            "status": "CLOSED",
            "type": "DEFAULT"
        }
    }
}
```

#### Human Readable Output

>### Approved Incident: testtest
>|id|name|type|filterFromDate|filterToDate|filters|approvalDate|approvalStatus|approvalType|comment|createdByName|status|reviewers|dispositionCategory|changeType|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 8af30349-bd07-4c0d-8469-58d9d7218ffa | testtest | DEFAULT | 2021-01-01 00:00:00 | 2021-02-15 00:00:00 | dateTime: ['2021-01-01'..'2021-02-15'] | 2021-02-16 09:52:49 | APPROVED | MANUAL | approved | Qmasters | CLOSED | useruser | MALWARE | AUTOMATED |


### qualys-fim-assets-list
***
Retrieve a list of all FIM assets.


#### Base Command

`qualys-fim-assets-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attributes | The list of comma-separated attributes that you want to include in the response. By default, all attributes will be returned in the result. i.e: attributes="attributes=interfaces.hostname". | Optional | 
| filter | Filter the events list by providing a query using Qualys syntax. i.e., "id:ebe6c64a-8b0d-3401-858d-d57fb25860c7". Refer to the "How to Search" Qualys FIM guide for more information about Qualys syntax: https://qualysguard.qg2.apps.qualys.com/fim/help/search/language.htm. | Optional | 
| page_number | Page number (index) to list items from. The "limit" argument defines the page size (the number of items in a page). | Optional | 
| limit | The number of records to include. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QualysFIM.Assets.hostname | str | Asset hostname. | 
| QualysFIM.Assets.lastCheckedIn | str | Date the asset was last checked. | 
| QualysFIM.Assets.created | str | Date the asset was created.  | 


#### Command Example
```!qualys-fim-assets-list limit=3```

#### Context Example
```json
{
    "QualysFIM": {
        "Asset": [
            {
                "activationDate": 1610279920980,
                "agentService": {
                    "driverVersion": "4.1.0.744",
                    "httpStatus": null,
                    "osStatus": null,
                    "status": "FIM_EVENTS_UPLOADED",
                    "statusCode": 2007,
                    "updatedDate": 1613467885762
                },
                "agentUuid": "b1caea93-0d21-4343-801c-92009f036c79",
                "agentVersion": "1.1.1.1",
                "assetId": 20032549,
                "created": 1610279920980,
                "customerId": 524090,
                "customerUuid": "12345678999",
                "ec2": null,
                "hostId": 15855913,
                "id": "b1caea93-0d21-4343-801c-92009f036c79",
                "interfaces": [
                    {
                        "address": "10.0.0.12",
                        "hostname": "Qmasters_desktop",
                        "interfaceName": "Intel(R) Dual Band Wireless-AC 8265",
                        "macAddress": "04:33:C2:64:45:B5"
                    },
                    {
                        "address": "1.1.1.1",
                        "hostname": null,
                        "interfaceName": "Hyper-V Virtual Ethernet Adapter #2",
                        "macAddress": "00:15:5D:8E:77:64"
                    },
                    {
                        "address": "1.1.1.1",
                        "hostname": null,
                        "interfaceName": "Hyper-V Virtual Ethernet Adapter",
                        "macAddress": "00:15:5D:74:86:60"
                    },
                    {
                        "address": "aa00:0:0:0:00aa:0a00:a00a:00a0",
                        "hostname": null,
                        "interfaceName": "Hyper-V Virtual Ethernet Adapter #2",
                        "macAddress": "00:15:5D:8E:77:64"
                    },
                    {
                        "address": "aa00:0:0:0:00aa:0a00:a00a:00a0",
                        "hostname": null,
                        "interfaceName": "Hyper-V Virtual Ethernet Adapter",
                        "macAddress": "00:15:5D:74:86:60"
                    },
                    {
                        "address": "aa00:0:0:0:00aa:0a00:a00a:00a0",
                        "hostname": "Qmasters_desktop",
                        "interfaceName": "Intel(R) Dual Band Wireless-AC 8265",
                        "macAddress": "04:33:C2:64:45:B5"
                    }
                ],
                "lastCheckedIn": 1613463519000,
                "lastLoggedOnUser": ".\\Qmasters",
                "manifest": {
                    "id": "4bca8be5-4b84-473c-998d-16fbcbd08761",
                    "status": "FIM_MANIFEST_ASSIGNED",
                    "updatedDate": 1610978060927
                },
                "name": "Qmasters_desktop",
                "netbiosName": "Qmasters_desktop",
                "operatingSystem": "Microsoft Windows 10 Pro 10.0.18363 64-bit N/A Build 18363",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "createdBy": {
                            "date": 1610279901826,
                            "user": {
                                "id": "1a7f00bd-cbde-7d97-831f-ba25de45c44e",
                                "name": "Qmasters"
                            }
                        },
                        "customerId": "12345678999",
                        "id": "810dbed0-7314-4531-b7a0-7f2733f1be10",
                        "name": "qmasters_02",
                        "osVersions": [],
                        "status": "ACTIVATED",
                        "type": "WINDOWS",
                        "version": "1.0"
                    },
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "createdBy": {
                            "date": 1610895239253,
                            "user": {
                                "id": "1a7f00bd-cbde-7d97-831f-ba25de45c44e",
                                "name": "Qmasters"
                            }
                        },
                        "customerId": "12345678999",
                        "id": "ca93db3b-6e8a-4b22-b394-c436caf5f7cd",
                        "name": "Monitoring Profile for Windows",
                        "osVersions": [],
                        "status": "ACTIVATED",
                        "type": "WINDOWS",
                        "version": "2.0"
                    },
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "createdBy": {
                            "date": 1610895240533,
                            "user": {
                                "id": "1a7f00bd-cbde-7d97-831f-ba25de45c44e",
                                "name": "Qmasters"
                            }
                        },
                        "customerId": "12345678999",
                        "id": "53f22775-6ea6-4bde-a2e4-ade0b8754a6c",
                        "name": "Monitoring Profile for Oracle Database on Windows",
                        "osVersions": [],
                        "status": "ACTIVATED",
                        "type": "WINDOWS",
                        "version": "1.0"
                    },
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "createdBy": {
                            "date": 1610895241659,
                            "user": {
                                "id": "1a7f00bd-cbde-7d97-831f-ba25de45c44e",
                                "name": "Qmasters"
                            }
                        },
                        "customerId": "12345678999",
                        "id": "142a5071-183d-4359-a7dd-e6b3a766c1ad",
                        "name": "Lightweight Monitoring Profile for Windows",
                        "osVersions": [],
                        "status": "ACTIVATED",
                        "type": "WINDOWS",
                        "version": "2.0"
                    },
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "createdBy": {
                            "date": 1610226039643,
                            "user": {
                                "id": "1a7f00bd-cbde-7d97-831f-ba25de45c44e",
                                "name": "Qmasters"
                            }
                        },
                        "customerId": "12345678999",
                        "id": "b5ff2d41-1c38-4c5f-bdf9-d94dee15b027",
                        "name": "Qmasters",
                        "osVersions": [],
                        "status": "ACTIVATED",
                        "type": "WINDOWS",
                        "version": "1.0"
                    },
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "createdBy": {
                            "date": 1610894881272,
                            "user": {
                                "id": "1a7f00bd-cbde-7d97-831f-ba25de45c44e",
                                "name": "Qmasters"
                            }
                        },
                        "customerId": "12345678999",
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "osVersions": [],
                        "status": "ACTIVATED",
                        "type": "WINDOWS",
                        "version": "1.0"
                    }
                ],
                "system": {
                    "lastBoot": 1613463519000
                },
                "tags": [
                    "fde350b6-c5c3-4764-8060-185269d93109",
                    "89bec2e4-9046-44b4-ba35-6098af65aca2"
                ]
            },
            {
                "activationDate": 1610899301086,
                "agentService": {
                    "driverVersion": "1.1.1.1",
                    "httpStatus": null,
                    "osStatus": null,
                    "status": "FIM_EVENTS_UPLOADED",
                    "statusCode": 2007,
                    "updatedDate": 1610900638754
                },
                "agentUuid": "12345678",
                "agentVersion": "4.0.0.411",
                "assetId": 20234688,
                "created": 1610899301086,
                "customerId": 524090,
                "customerUuid": "12345678999",
                "ec2": null,
                "hostId": 15994867,
                "id": "12345678",
                "interfaces": [
                    {
                        "address": "8.8.8.8",
                        "hostname": "DC",
                        "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                        "macAddress": "00:0C:00:0B:A0:0E"
                    },
                    {
                        "address": "fe00:0:0:0:00a0:a000:00dc:000b",
                        "hostname": "DC",
                        "interfaceName": "Intel(R) 82574L Gigabit Network Connection #2",
                        "macAddress": "00:0C:00:0B:A0:0E"
                    }
                ],
                "lastCheckedIn": 1610900217057,
                "lastLoggedOnUser": "QMASTERS",
                "manifest": {
                    "id": "3aff4a9e-d8f0-4df2-b345-74d05b9a3200",
                    "status": "FIM_MANIFEST_ASSIGNED",
                    "updatedDate": 1610900110706
                },
                "name": "DC.qmasters.local",
                "netbiosName": "DC",
                "operatingSystem": "Microsoft Windows Server 2016 Standard Evaluation 10.0.14393 64-bit N/A Build 14393",
                "profiles": [
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "createdBy": {
                            "date": 1610895239253,
                            "user": {
                                "id": "1a7f00bd-cbde-7d97-831f-ba25de45c44e",
                                "name": "Qmasters"
                            }
                        },
                        "customerId": "12345678999",
                        "id": "ca93db3b-6e8a-4b22-b394-c436caf5f7cd",
                        "name": "Monitoring Profile for Windows",
                        "osVersions": [],
                        "status": "ACTIVATED",
                        "type": "WINDOWS",
                        "version": "2.0"
                    },
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "createdBy": {
                            "date": 1610894881272,
                            "user": {
                                "id": "1a7f00bd-cbde-7d97-831f-ba25de45c44e",
                                "name": "Qmasters"
                            }
                        },
                        "customerId": "12345678999",
                        "id": "432b8f93-c610-4c8f-9e7d-6cdae41f2dc5",
                        "name": "test_01",
                        "osVersions": [],
                        "status": "ACTIVATED",
                        "type": "WINDOWS",
                        "version": "1.0"
                    },
                    {
                        "category": {
                            "id": "2dab5022-2fdd-11e7-93ae-92361f002671",
                            "name": "PCI"
                        },
                        "createdBy": {
                            "date": 1610279901826,
                            "user": {
                                "id": "1a7f00bd-cbde-7d97-831f-ba25de45c44e",
                                "name": "Qmasters"
                            }
                        },
                        "customerId": "12345678999",
                        "id": "810dbed0-7314-4531-b7a0-7f2733f1be10",
                        "name": "qmasters_02",
                        "osVersions": [],
                        "status": "ACTIVATED",
                        "type": "WINDOWS",
                        "version": "1.0"
                    }
                ],
                "system": {
                    "lastBoot": 1610900217057
                },
                "tags": [
                    "fde350b6-c5c3-4764-8060-185269d93109"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Listed 2 Assets:
>|Hostname|Last Activity|Creation Time|Agent Version|Driver Version|Last Agent Update|Asset ID|
>|---|---|---|---|---|---|---|
>| Qmasters_desktop | 2021-02-16 08:18:39 | 2021-01-10 11:58:40 | 1.1.1.1 | 4.1.0.744 | 2021-02-16 09:31:25 | b1caea93-0d21-4343-801c-92009f036c79 |
>| DC | 2021-01-17 16:16:57 | 2021-01-17 16:01:41 | 4.0.0.411 | 1.1.1.1 | 2021-01-17 16:23:58 | 12345678 |
