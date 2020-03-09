import json
from py42.sdk import SDK
from Code42 import (
    Code42Client,
    build_query_payload,
    map_observation_to_security_query,
    map_to_code42_event_context,
    map_to_code42_alert_context,
    map_to_file_context,
    alert_get_command,
    alert_resolve_command,
    departingemployee_add_command,
    departingemployee_remove_command,
    fetch_incidents,
    securitydata_search_command
)
import time

MOCK_URL = "https://123-fake-api.com"

MOCK_SECURITYDATA_SEARCH_QUERY = {
    "hash": "d41d8cd98f00b204e9800998ecf8427e",
    "hostname": "DESKTOP-0001",
    "username": "user3@example.com",
    "exposure": "ApplicationRead",
    "results": 50
}

MOCK_SECURITY_EVENT_RESPONSE = {
    "fileEvents": [
        {
            "actor": None,
            "cloudDriveId": None,
            "createTimestamp": "2019-02-14T22:16:32.977Z",
            "detectionSourceAlias": None,
            "deviceUid": "902443375841117412",
            "deviceUserName": "user1@example.com",
            "directoryId": [
            ],
            "domainName": "10.0.1.24",
            "emailDlpPolicyNames": None,
            "emailFrom": None,
            "emailRecipients": None,
            "emailSender": None,
            "emailSubject": None,
            "eventId": "0_39550347-381e-490e-8397-46629a0e7af6_902443373841117412_941153704842724615_952",
            "eventTimestamp": "2019-10-02T16:57:31.990Z",
            "eventType": "READ_BY_APP",
            "exposure": [
                "ApplicationRead"
            ],
            "fileCategory": "IMAGE",
            "fileId": None,
            "fileName": "data.jpg",
            "fileOwner": "user1",
            "filePath": "C:/Users/user1/Pictures/",
            "fileSize": 9875,
            "fileType": "FILE",
            "insertionTimestamp": "2019-02-14T22:22:06.126Z",
            "md5Checksum": "8cfe4d76431ee20dd82fbd3778b6396f",
            "modifyTimestamp": "2019-02-14T22:16:34.664Z",
            "osHostName": "LAPTOP-012",
            "privateIpAddresses": [
                "10.0.1.24",
                "0:0:0:0:0:0:0:1",
                "127.0.0.1",
                "fe80:0:0:0:bd2b:9ac6:5b3a:b47f%eth0"
            ],
            "processName": "\\Device\\HarddiskVolume2\\Users\\user1\\AppData\\Local\\slack\\app-4.3.4\\slack.exe",
            "processOwner": "user1",
            "publicIpAddress": "126.18.85.1",
            "removableMediaBusType": None,
            "removableMediaCapacity": None,
            "removableMediaMediaName": None,
            "removableMediaName": None,
            "removableMediaPartitionId": [
            ],
            "removableMediaSerialNumber": None,
            "removableMediaVendor": None,
            "removableMediaVolumeName": [
            ],
            "sha256Checksum": "adb54dbe1f8268ce39351bad43eddbc419a08e6db3bbf7eb7b601a5d88b8d03b",
            "shared": None,
            "sharedWith": [
            ],
            "sharingTypeAdded": [
            ],
            "source": "Endpoint",
            "syncDestination": None,
            "tabUrl": None,
            "url": None,
            "userUid": "902428473202285579",
            "windowTitle": [
                "Slack | cats_omg | Sysadmin buddies"
            ]
        },
        {
            "actor": "user2@example.com",
            "cloudDriveId": "0BUjUO34z2CQnUk9PVA",
            "createTimestamp": "2019-09-02T19:55:26.389Z",
            "detectionSourceAlias": "Google Drive",
            "deviceUid": None,
            "deviceUserName": "NAME_NOT_AVAILABLE",
            "directoryId": [
                "0BUjQW60z2RMnUk9CFE"
            ],
            "domainName": None,
            "emailDlpPolicyNames": None,
            "emailFrom": None,
            "emailRecipients": None,
            "emailSender": None,
            "emailSubject": None,
            "eventId": "0798_6go4TW7QFQxF5UuBdCFddpX7ZbB9_1_13b87573-f82f-47aa-891c-6966f6e4ec54",
            "eventTimestamp": "2019-10-02T15:00:09.745Z",
            "eventType": "CREATED",
            "exposure": [],
            "fileCategory": "IMAGE",
            "fileId": "0798_6go4TW7QFQxF5UuBdCFddpX7ZbB9",
            "fileName": "Kitties",
            "fileOwner": "user2@example.com",
            "filePath": None,
            "fileSize": 333114,
            "fileType": "FILE",
            "insertionTimestamp": "2020-10-02T15:02:18.390Z",
            "md5Checksum": "eef8b12d2ed0d6a69fe77699d5640c7b",
            "modifyTimestamp": "2019-10-02T14:55:26.389Z",
            "osHostName": None,
            "privateIpAddresses": [],
            "processName": None,
            "processOwner": None,
            "publicIpAddress": None,
            "removableMediaBusType": None,
            "removableMediaCapacity": None,
            "removableMediaMediaName": None,
            "removableMediaName": None,
            "removableMediaPartitionId": [],
            "removableMediaSerialNumber": None,
            "removableMediaVendor": None,
            "removableMediaVolumeName": [],
            "sha256Checksum": "5e25e54e1cc43ed07c6e888464cb98e5f5343aa7aa485d174d9649be780a17b9",
            "shared": "FALSE",
            "sharedWith": [],
            "sharingTypeAdded": [],
            "source": "GoogleDrive",
            "syncDestination": None,
            "tabUrl": None,
            "url": "https://drive.google.com/a/c42se.com/file/d/1tm4_6go4TW7QFQxF5UuBdCFddpX7ZbB9/view?usp=drivesdk",
            "userUid": "UNKNOWN",
            "windowTitle": []
        },
        {
            "actor": None,
            "cloudDriveId": None,
            "createTimestamp": "2019-08-10T22:22:07.460Z",
            "detectionSourceAlias": None,
            "deviceUid": "920258207244664650",
            "deviceUserName": "user3@example.com",
            "directoryId": [
            ],
            "domainName": "USER3-DEMO01",
            "emailDlpPolicyNames": None,
            "emailFrom": None,
            "emailRecipients": None,
            "emailSender": None,
            "emailSubject": None,
            "eventId": "0_25e609cd-ccee-4b40-ba62-165f312ed8f4_920258207243264650_940574180289182590_4",
            "eventTimestamp": "2019-10-02T16:55:08.772Z",
            "eventType": "MODIFIED",
            "exposure": [
                "RemovableMedia"
            ],
            "fileCategory": "PDF",
            "fileId": None,
            "fileName": "Blueprints.pdf",
            "fileOwner": "Everyone",
            "filePath": "F:/",
            "fileSize": 946814,
            "fileType": "FILE",
            "insertionTimestamp": "2019-10-02T17:00:01.806Z",
            "md5Checksum": "f61e05de73f798b9f43c11b299653894",
            "modifyTimestamp": "2019-09-10T22:22:08Z",
            "osHostName": "USER3-DEMO01",
            "privateIpAddresses": [
                "0:0:0:0:0:0:0:1",
                "127.0.0.1",
                "172.16.1.1"
            ],
            "processName": None,
            "processOwner": None,
            "publicIpAddress": "8.8.14.14",
            "removableMediaBusType": "USB",
            "removableMediaCapacity": 30751588352,
            "removableMediaMediaName": "SanDisk Ultra USB 3.0 Media",
            "removableMediaName": "Ultra USB 3.0",
            "removableMediaPartitionId": [
                "5b0acc46-0000-0000-0000-100000000000"
            ],
            "removableMediaSerialNumber": "4C532378360368700544",
            "removableMediaVendor": "SanDisk",
            "removableMediaVolumeName": [
                "DIGI (F:)"
            ],
            "sha256Checksum": "92e5bcca6b7d2c081e4169ee293098a76d5887081b6db33b841ab6440dfc08a0",
            "shared": None,
            "sharedWith": [
            ],
            "sharingTypeAdded": [
            ],
            "source": "Endpoint",
            "syncDestination": None,
            "tabUrl": None,
            "url": None,
            "userUid": "920256648733700844",
            "windowTitle": [
            ]
        }
    ]
}

MOCK_CODE42_EVENT_CONTEXT = [
    {
        "DevicePrivateIPAddress": ["10.0.1.24",
                                   "0:0:0:0:0:0:0:1",
                                   "127.0.0.1",
                                   "fe80:0:0:0:bd2b:9ac6:5b3a:b47f%eth0"],
        "DeviceUsername": "user1@example.com",
        "EndpointID": "902443375841117412",
        "EventID": "0_39550347-381e-490e-8397-46629a0e7af6_902443373841117412_941153704842724615_952",
        "EventTimestamp": "2019-10-02T16:57:31.990Z",
        "EventType": "READ_BY_APP",
        "Exposure": ["ApplicationRead"],
        "FileCategory": "IMAGE",
        "FileCreated": "2019-02-14T22:16:32.977Z",
        "FileHostname": "LAPTOP-012",
        "FileMD5": "8cfe4d76431ee20dd82fbd3778b6396f",
        "FileModified": "2019-02-14T22:16:34.664Z",
        "FileName": "data.jpg",
        "FileOwner": "user1",
        "FilePath": "C:/Users/user1/Pictures/",
        "FileSHA256": "adb54dbe1f8268ce39351bad43eddbc419a08e6db3bbf7eb7b601a5d88b8d03b",
        "FileSize": 9875,
        "ProcessName": "\\Device\\HarddiskVolume2\\Users\\user1\\AppData\\Local\\slack\\app-4.3.4\\slack.exe",
        "ProcessOwner": "user1",
        "Source": "Endpoint",
        "WindowTitle": ["Slack | cats_omg | Sysadmin buddies"]
    },
    {
        "DeviceUsername": "NAME_NOT_AVAILABLE",
        "EventID": "0798_6go4TW7QFQxF5UuBdCFddpX7ZbB9_1_13b87573-f82f-47aa-891c-6966f6e4ec54",
        "EventTimestamp": "2019-10-02T15:00:09.745Z",
        "EventType": "CREATED",
        "FileCategory": "IMAGE",
        "FileCreated": "2019-09-02T19:55:26.389Z",
        "FileMD5": "eef8b12d2ed0d6a69fe77699d5640c7b",
        "FileModified": "2019-10-02T14:55:26.389Z",
        "FileName": "Kitties",
        "FileOwner": "user2@example.com",
        "FileSHA256": "5e25e54e1cc43ed07c6e888464cb98e5f5343aa7aa485d174d9649be780a17b9",
        "FileShared": "FALSE",
        "FileSize": 333114,
        "FileURL": "https://drive.google.com/a/c42se.com/file/d/1tm4_6go4TW7QFQxF5UuBdCFddpX7ZbB9/view?usp=drivesdk",
        "Source": "GoogleDrive"
    },
    {
        "DevicePrivateIPAddress": ["0:0:0:0:0:0:0:1", "127.0.0.1", "172.16.1.1"],
        "DeviceUsername": "user3@example.com",
        "EndpointID": "920258207244664650",
        "EventID": "0_25e609cd-ccee-4b40-ba62-165f312ed8f4_920258207243264650_940574180289182590_4",
        "EventTimestamp": "2019-10-02T16:55:08.772Z",
        "EventType": "MODIFIED",
        "Exposure": ["RemovableMedia"],
        "FileCategory": "PDF",
        "FileCreated": "2019-08-10T22:22:07.460Z",
        "FileHostname": "USER3-DEMO01",
        "FileMD5": "f61e05de73f798b9f43c11b299653894",
        "FileModified": "2019-09-10T22:22:08Z",
        "FileName": "Blueprints.pdf",
        "FileOwner": "Everyone",
        "FilePath": "F:/",
        "FileSHA256": "92e5bcca6b7d2c081e4169ee293098a76d5887081b6db33b841ab6440dfc08a0",
        "FileSize": 946814,
        "RemovableMediaCapacity": 30751588352,
        "RemovableMediaMediaName": "SanDisk Ultra USB 3.0 Media",
        "RemovableMediaName": "Ultra USB 3.0",
        "RemovableMediaSerialNumber": "4C532378360368700544",
        "RemovableMediaType": "USB",
        "RemovableMediaVendor": "SanDisk",
        "Source": "Endpoint"
    }
]

MOCK_FILE_CONTEXT = [
    {
        "Hostname": "LAPTOP-012",
        "MD5": "8cfe4d76431ee20dd82fbd3778b6396f",
        "Name": "data.jpg",
        "Path": "C:/Users/user1/Pictures/",
        "SHA256": "adb54dbe1f8268ce39351bad43eddbc419a08e6db3bbf7eb7b601a5d88b8d03b",
        "Size": 9875
    },
    {
        "MD5": "eef8b12d2ed0d6a69fe77699d5640c7b",
        "Name": "Kitties",
        "SHA256": "5e25e54e1cc43ed07c6e888464cb98e5f5343aa7aa485d174d9649be780a17b9",
        "Size": 333114
    },
    {
        "Hostname": "USER3-DEMO01",
        "MD5": "f61e05de73f798b9f43c11b299653894",
        "Name": "Blueprints.pdf",
        "Path": "F:/",
        "SHA256": "92e5bcca6b7d2c081e4169ee293098a76d5887081b6db33b841ab6440dfc08a0",
        "Size": 946814
    }
]

MOCK_ALERT_RESPONSE = {
    "alerts": [
        {
            "actor": "user1@example.com",
            "createdAt": "2019-10-02T17:02:23.5867670Z",
            "description": "",
            "id": "36fb8ca5-0533-4d25-9763-e09d35d60610",
            "name": "Departing Employee Alert",
            "severity": "HIGH",
            "state": "OPEN",
            "target": "N/A",
            "tenantId": "fef27d1d-e835-465c-be8f-ac9db7a54684",
            "type": "FED_ENDPOINT_EXFILTRATION",
            "type$": "ALERT_SUMMARY"
        },
        {
            "actor": "user2@example.com",
            "createdAt": "2019-10-02T17:02:24.2071980Z",
            "description": "",
            "id": "18ac641d-7d9c-4d37-a48f-c89396c07d03",
            "name": "High-Risk Employee Alert",
            "severity": "MEDIUM",
            "state": "OPEN",
            "target": "N/A",
            "tenantId": "fef27d1d-e835-465c-be8f-ac9db7a54684",
            "type": "FED_CLOUD_SHARE_PERMISSIONS",
            "type$": "ALERT_SUMMARY"
        },
        {
            "actor": "user3@exmaple.com",
            "createdAt": "2019-10-02T17:03:28.2885720Z",
            "description": "",
            "id": "3137ff1b-b824-42e4-a476-22bccdd8ddb8",
            "name": "Custom Alert 1",
            "severity": "LOW",
            "state": "OPEN",
            "target": "N/A",
            "tenantId": "fef27d1d-e835-465c-be8f-ac9db7a54684",
            "type": "FED_ENDPOINT_EXFILTRATION",
            "type$": "ALERT_SUMMARY"
        }
    ],
    "type$": "ALERT_QUERY_RESPONSE"
}

MOCK_ALERT_DETAILS_RESPONSE = [
    {
        "alerts": [
            {
                "actor": "user1@example.com",
                "createdAt": "2019-10-02T17:02:23.5867670Z",
                "description": "",
                "id": "36fb8ca5-0533-4d25-9763-e09d35d60610",
                "name": "Departing Employee Alert",
                "notes": "Departing Employee Notes",
                "observations": [
                    {
                        "data": r"""{"type$":"OBSERVED_ENDPOINT_ACTIVITY","id":"e940d9de-bd73-4665-8b3c-196aca6b8a53",
                                "sources":["Endpoint"],"exposureTypes":["ApplicationRead"],"firstActivityAt":
                                "2019-10-02T16:50:00.0000000Z","lastActivityAt":"2019-10-02T16:55:00.0000000Z",
                                "fileCount":7,"totalFileSize":66119,"fileCategories":[{"type$":"OBSERVED_FILE_CATEGORY",
                                "category":"SourceCode","fileCount":7,
                                "totalFileSize":66119,"isSignificant":false}],"syncToServices":[]}""",
                        "id": "e940d9de-bd73-4665-8b3c-196aca6b8a53",
                        "observedAt": "2019-10-02T17:00:00.0000000Z",
                        "type": "FedEndpointExfiltration",
                        "type$": "OBSERVATION"
                    }
                ],
                "ruleId": "c4404ee8-503c-4a21-98f5-37561ee4caf0",
                "ruleSource": "Departing Employee",
                "severity": "HIGH",
                "state": "OPEN",
                "target": "N/A",
                "tenantId": "fef27d1d-e835-465c-be8f-ac9db7a54684",
                "type": "FED_ENDPOINT_EXFILTRATION",
                "type$": "ALERT_SUMMARY"
            }
        ]
    },
    {
        "alerts": [
            {
                "actor": "user2@example.com",
                "createdAt": "2019-10-02T17:02:24.2071980Z",
                "description": "",
                "id": "18ac641d-7d9c-4d37-a48f-c89396c07d03",
                "name": "High-Risk Employee Alert",
                "notes": "High-Risk Employee Notes",
                "observations": [
                    {
                        "data": r"""{"type$":"OBSERVED_CLOUD_SHARE_ACTIVITY","id":"495fb9a2-ab18-4b62-98bd-c141ed776de5",
                                "sources":["GoogleDrive"],"exposureTypes":["PublicSearchableShare","PublicLinkShare"],
                                "firstActivityAt":"2019-10-02T16:50:00.0000000Z","lastActivityAt":
                                "2019-10-02T16:55:00.0000000Z","fileCount":1,"totalFileSize":8089,
                                "fileCategories":[{"type$":"OBSERVED_FILE_CATEGORY",
                                "category":"Document","fileCount":1,"totalFileSize":8089,"isSignificant":false}]}""",
                        "id": "495fb9a2-ab18-4b62-98bd-c141ed776de5",
                        "observedAt": "2019-10-02T16:57:00.0000000Z",
                        "type": "FedCloudSharePermissions",
                        "type$": "OBSERVATION"
                    }
                ],
                "ruleId": "c4404ee8-503c-4a21-98f5-37561ee4caf0",
                "ruleSource": "High-Risk Employee",
                "severity": "MEDIUM",
                "state": "OPEN",
                "target": "N/A",
                "tenantId": "fef27d1d-e835-465c-be8f-ac9db7a54684",
                "type": "FED_CLOUD_SHARE_PERMISSIONS",
                "type$": "ALERT_SUMMARY"
            }
        ]
    },
    {
        "alerts": [
            {
                "actor": "user3@example.com",
                "createdAt": "2019-10-02T17:03:28.2885720Z",
                "description": "",
                "id": "3137ff1b-b824-42e4-a476-22bccdd8ddb8",
                "name": "Custom Alert 1",
                "notes": "Removable Media Alert",
                "observations": [
                    {
                        "data": r"""{"type$":"OBSERVED_ENDPOINT_ACTIVITY","id":"a1fac38d-4816-4090-bf1c-9c429f6265f0",
                              "sources":["Endpoint"],"exposureTypes":["RemovableMedia"],"firstActivityAt":
                              "2019-10-02T16:45:00.0000000Z","lastActivityAt":"2019-10-02T16:50:00.0000000Z","fileCount":4,
                              "totalFileSize":997653,"fileCategories":[{"type$":"OBSERVED_FILE_CATEGORY",
                              "category":"Document","fileCount":2,"totalFileSize":50839,"isSignificant":false},
                              {"type$":"OBSERVED_FILE_CATEGORY","category":"Pdf","fileCount":2,
                              "totalFileSize":946814,"isSignificant":false}],"syncToServices":[]}""",
                        "id": "a1fac38d-4816-4090-bf1c-9c429f6265f0",
                        "observedAt": "2019-10-02T17:00:00.0000000Z",
                        "type": "FedEndpointExfiltration",
                        "type$": "OBSERVATION"
                    }
                ],
                "ruleId": "dcee3e9c-c914-424a-bb23-bb60f0ae9f0f",
                "ruleSource": "Alerting",
                "severity": "LOW",
                "state": "OPEN",
                "target": "N/A",
                "tenantId": "fef27d1d-e835-465c-be8f-ac9db7a54684",
                "type": "FED_ENDPOINT_EXFILTRATION",
                "type$": "ALERT_SUMMARY"
            }
        ]
    }
]


MOCK_CODE42_ALERT_CONTEXT = [
    {
        "ID": "36fb8ca5-0533-4d25-9763-e09d35d60610",
        "Name": "Departing Employee Alert",
        "Occurred": "2019-10-02T17:02:23.5867670Z",
        "Severity": "HIGH",
        "State": "OPEN",
        "Type": "FED_ENDPOINT_EXFILTRATION",
        "Username": "user1@example.com"
    },
    {
        "ID": "18ac641d-7d9c-4d37-a48f-c89396c07d03",
        "Name": "High-Risk Employee Alert",
        "Occurred": "2019-10-02T17:02:24.2071980Z",
        "Severity": "MEDIUM",
        "State": "OPEN",
        "Type": "FED_CLOUD_SHARE_PERMISSIONS",
        "Username": "user2@example.com"
    },
    {
        "ID": "3137ff1b-b824-42e4-a476-22bccdd8ddb8",
        "Name": "Custom Alert 1",
        "Occurred": "2019-10-02T17:03:28.2885720Z",
        "Severity": "LOW",
        "State": "OPEN",
        "Type": "FED_ENDPOINT_EXFILTRATION",
        "Username": "user3@example.com"
    }
]

MOCK_QUERY_PAYLOAD = {
    "groupClause": "AND",
    "groups": [
        {
            "filterClause": "AND",
            "filters": [
                {
                    "operator": "IS",
                    "term": "md5Checksum",
                    "value": "d41d8cd98f00b204e9800998ecf8427e"
                }
            ]
        },
        {
            "filterClause": "AND",
            "filters": [
                {
                    "operator": "IS",
                    "term": "osHostName",
                    "value": "DESKTOP-0001"
                }
            ]
        },
        {
            "filterClause": "AND",
            "filters": [
                {
                    "operator": "IS",
                    "term": "deviceUserName",
                    "value": "user3@example.com"
                }
            ]
        },
        {
            "filterClause": "AND",
            "filters": [
                {
                    "operator": "IS",
                    "term": "exposure",
                    "value": "ApplicationRead"
                }
            ]
        }
    ],
    "pgNum": 1,
    "pgSize": 50,
    "srtDir": "asc",
    "srtKey": "eventId"
}

MOCK_OBSERVATION_QUERIES = [
    {
        "groupClause": "AND",
        "groups": [
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "IS",
                        "term": "deviceUserName",
                        "value": "user1@example.com"
                    }
                ]
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_AFTER",
                        "term": "eventTimestamp",
                        "value": "2019-10-02T16:50:00.000Z"
                    }
                ]
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_BEFORE",
                        "term": "eventTimestamp",
                        "value": "2019-10-02T16:55:00.000Z"
                    }
                ]
            },
            {
                "filterClause": "OR",
                "filters": [
                    {
                        "operator": "IS",
                        "term": "eventType",
                        "value": "CREATED"
                    },
                    {
                        "operator": "IS",
                        "term": "eventType",
                        "value": "MODIFIED"
                    },
                    {
                        "operator": "IS",
                        "term": "eventType",
                        "value": "READ_BY_APP"
                    }
                ]
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "IS",
                        "term": "exposure",
                        "value": "ApplicationRead"
                    }
                ]
            },
        ],
        "pgNum": 1,
        "pgSize": 100,
        "srtDir": "asc",
        "srtKey": "eventId"
    },
    {
        "groupClause": "AND",
        "groups": [
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "IS",
                        "term": "actor",
                        "value": "user2@example.com"
                    }
                ]
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_AFTER",
                        "term": "eventTimestamp",
                        "value": "2019-10-02T16:50:00.000Z"
                    }
                ]
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_BEFORE",
                        "term": "eventTimestamp",
                        "value": "2019-10-02T16:55:00.000Z"
                    }
                ]
            },
            {
                "filterClause": "OR",
                "filters": [
                    {
                        "operator": "IS",
                        "term": "exposure",
                        "value": "IsPublic"
                    },
                    {
                        "operator": "IS",
                        "term": "exposure",
                        "value": "SharedViaLink"
                    }
                ]
            }
        ],
        "pgNum": 1,
        "pgSize": 100,
        "srtDir": "asc",
        "srtKey": "eventId"
    },
    {
        "groupClause": "AND",
        "groups": [
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "IS",
                        "term": "deviceUserName",
                        "value": "user3@example.com"
                    }
                ]
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_AFTER",
                        "term": "eventTimestamp",
                        "value": "2019-10-02T16:45:00.000Z"
                    }
                ]
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_BEFORE",
                        "term": "eventTimestamp",
                        "value": "2019-10-02T16:50:00.000Z"
                    }
                ]
            },
            {
                "filterClause": "OR",
                "filters": [
                    {
                        "operator": "IS",
                        "term": "eventType",
                        "value": "CREATED"
                    },
                    {
                        "operator": "IS",
                        "term": "eventType",
                        "value": "MODIFIED"
                    },
                    {
                        "operator": "IS",
                        "term": "eventType",
                        "value": "READ_BY_APP"
                    }
                ]
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "IS",
                        "term": "exposure",
                        "value": "RemovableMedia"
                    }
                ]
            }
        ],
        "pgNum": 1,
        "pgSize": 100,
        "srtDir": "asc",
        "srtKey": "eventId"
    }
]


def create_alert_mocks(requests_mock):
    requests_mock.get(MOCK_URL + '/c42api/v3/auth/jwt?useBody=true', json={"data": {"v3_user_token": "faketoken"}})
    requests_mock.get(MOCK_URL + '/api/User/my', json={})
    requests_mock.get(MOCK_URL + '/c42api/v3/customer/my', json={"data": {"tenantUid": "123"}})
    requests_mock.get(MOCK_URL + '/api/ServerEnv', json={"stsBaseUrl": MOCK_URL})
    requests_mock.get(MOCK_URL + '/v1/AlertService-API_URL', text=MOCK_URL + '/svc/api')


def create_departingemployee_mocks(requests_mock):
    requests_mock.get(MOCK_URL + '/c42api/v3/auth/jwt?useBody=true', json={"data": {"v3_user_token": "faketoken"}})
    requests_mock.get(MOCK_URL + '/api/User/my', json={})
    requests_mock.get(MOCK_URL + '/c42api/v3/customer/my', json={"data": {"tenantUid": "123"}})
    requests_mock.get(MOCK_URL + '/api/ServerEnv', json={"stsBaseUrl": MOCK_URL})
    requests_mock.get(MOCK_URL + '/v1/FedObserver-API_URL', text=MOCK_URL + '/svc/api')
    requests_mock.get(MOCK_URL + '/v1/employeecasemanagement-API_URL', text=MOCK_URL + '/svc/apiv/v1')
    requests_mock.get(MOCK_URL + '/v1/visualization-services-API_URL', text=MOCK_URL + '/svc/apiv/v1')


def create_securitydata_mocks(requests_mock):
    requests_mock.get(MOCK_URL + '/c42api/v3/auth/jwt?useBody=true', json={"data": {"v3_user_token": "faketoken"}})
    requests_mock.get(MOCK_URL + '/api/User/my', json={})
    requests_mock.get(MOCK_URL + '/c42api/v3/customer/my', json={"data": {"tenantUid": "123"}})
    requests_mock.get(MOCK_URL + '/api/ServerEnv', json={"stsBaseUrl": MOCK_URL})


def test_build_query_payload():
    query = build_query_payload(MOCK_SECURITYDATA_SEARCH_QUERY)
    assert json.loads(query) == MOCK_QUERY_PAYLOAD


def test_map_observation_to_security_query():
    for i in range(0, len(MOCK_ALERT_DETAILS_RESPONSE)):
        query = map_observation_to_security_query(
            MOCK_ALERT_DETAILS_RESPONSE[i]['alerts'][0]['observations'][0], MOCK_ALERT_DETAILS_RESPONSE[i]['alerts'][0]['actor'])
        assert json.loads(query) == MOCK_OBSERVATION_QUERIES[i]


def test_map_to_code42_event_context():
    for i in range(0, len(MOCK_SECURITY_EVENT_RESPONSE['fileEvents'])):
        context = map_to_code42_event_context(MOCK_SECURITY_EVENT_RESPONSE['fileEvents'][i])
        assert context == MOCK_CODE42_EVENT_CONTEXT[i]


def test_map_to_code42_alert_context():
    for i in range(0, len(MOCK_ALERT_DETAILS_RESPONSE)):
        context = map_to_code42_alert_context(MOCK_ALERT_DETAILS_RESPONSE[i]['alerts'][0])
        assert context == MOCK_CODE42_ALERT_CONTEXT[i]


def test_map_to_file_context():
    for i in range(0, len(MOCK_SECURITY_EVENT_RESPONSE['fileEvents'])):
        context = map_to_file_context(MOCK_SECURITY_EVENT_RESPONSE['fileEvents'][i])
        assert context == MOCK_FILE_CONTEXT[i]


def test_alert_get_command(requests_mock):
    create_alert_mocks(requests_mock)
    requests_mock.post(MOCK_URL + '/svc/api/v1/query-details', json=MOCK_ALERT_DETAILS_RESPONSE[0])
    client = Code42Client(
        sdk=SDK,
        base_url=MOCK_URL,
        auth=("123", "123"),
        verify=False,
        proxy=None
    )
    _, _, res = alert_get_command(client, {'id': '36fb8ca5-0533-4d25-9763-e09d35d60610'})
    assert res['ruleId'] == "c4404ee8-503c-4a21-98f5-37561ee4caf0"


def test_alert_resolve_command(requests_mock):
    create_alert_mocks(requests_mock)
    requests_mock.post(MOCK_URL + '/svc/api/v1/resolve-alert', json={'dummyresponse': True})
    requests_mock.post(MOCK_URL + '/svc/api/v1/query-details', json=MOCK_ALERT_DETAILS_RESPONSE[0])
    client = Code42Client(
        sdk=SDK,
        base_url=MOCK_URL,
        auth=("123", "123"),
        verify=False,
        proxy=None
    )
    _, _, res = alert_resolve_command(client, {'id': '36fb8ca5-0533-4d25-9763-e09d35d60610'})
    assert res['id'] == '36fb8ca5-0533-4d25-9763-e09d35d60610'


def test_departingemployee_remove_command(requests_mock):
    create_departingemployee_mocks(requests_mock)
    requests_mock.post(MOCK_URL + '/svc/api/v1/departingemployee/search',
                       json={'cases': [{'username': 'user1@example.com', 'caseId': 123, 'tenantId': '123'}]})
    requests_mock.post(MOCK_URL + '/svc/api/v1/departingemployee/details',
                       json={'username': 'user1@example.com', 'caseId': 123, 'tenantId': '123'})
    requests_mock.post(MOCK_URL + '/svc/api/v1/departingemployee/resolve')
    client = Code42Client(
        sdk=SDK,
        base_url=MOCK_URL,
        auth=("123", "123"),
        verify=False,
        proxy=None
    )
    _, _, res = departingemployee_remove_command(client, {'username': 'user1@example.com'})
    assert res == 123


def test_departingemployee_add_command(requests_mock):
    create_departingemployee_mocks(requests_mock)
    requests_mock.post(MOCK_URL + '/svc/api/v1/departingemployee/create', json={'caseId': 123})
    client = Code42Client(
        sdk=SDK,
        base_url=MOCK_URL,
        auth=("123", "123"),
        verify=False,
        proxy=None
    )
    _, _, res = departingemployee_add_command(client, {'username': 'user1@example.com',
                                              'departuredate': '2020-01-01', 'notes': 'Dummy note'})
    assert res == 123


def test_securitydata_search_command(requests_mock):
    create_securitydata_mocks(requests_mock)
    requests_mock.post(MOCK_URL + '/forensic-search/queryservice/api/v1/fileevent', json=MOCK_SECURITY_EVENT_RESPONSE)
    client = Code42Client(
        sdk=SDK,
        base_url=MOCK_URL,
        auth=("123", "123"),
        verify=False,
        proxy=None
    )
    _, _, res = securitydata_search_command(client, MOCK_SECURITYDATA_SEARCH_QUERY)
    assert len(res) == 3


def test_fetch_incidents_first_run(requests_mock, mocker):
    create_alert_mocks(requests_mock)
    requests_mock.post(MOCK_URL + '/svc/api/v1/query-alerts', json=MOCK_ALERT_RESPONSE)
    requests_mock.post(MOCK_URL + '/svc/api/v1/query-details', json=MOCK_ALERT_DETAILS_RESPONSE[0])
    requests_mock.post(MOCK_URL + '/forensic-search/queryservice/api/v1/fileevent', json=MOCK_SECURITY_EVENT_RESPONSE)
    client = Code42Client(
        sdk=SDK,
        base_url=MOCK_URL,
        auth=("123", "123"),
        verify=False,
        proxy=None
    )
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={'last_fetch': None},
        first_fetch_time="24 hours",
        event_severity_filter=None,
        fetch_limit=int("10"),
        include_files=True,
        integration_context=None
    )
    assert len(incidents) == 3
    assert next_run['last_fetch']


def test_fetch_incidents_next_run(requests_mock, mocker):
    mock_date = "2020-01-01T00:00:00.000Z"
    mock_timestamp = int(time.mktime(time.strptime(mock_date, "%Y-%m-%dT%H:%M:%S.000Z")))
    create_alert_mocks(requests_mock)
    requests_mock.post(MOCK_URL + '/svc/api/v1/query-alerts', json=MOCK_ALERT_RESPONSE)
    requests_mock.post(MOCK_URL + '/svc/api/v1/query-details', json=MOCK_ALERT_DETAILS_RESPONSE[0])
    requests_mock.post(MOCK_URL + '/forensic-search/queryservice/api/v1/fileevent', json=MOCK_SECURITY_EVENT_RESPONSE)
    client = Code42Client(
        sdk=SDK,
        base_url=MOCK_URL,
        auth=("123", "123"),
        verify=False,
        proxy=None
    )
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={'last_fetch': mock_timestamp},
        first_fetch_time="24 hours",
        event_severity_filter=None,
        fetch_limit=int("10"),
        include_files=True,
        integration_context=None
    )
    assert len(incidents) == 3
    assert next_run['last_fetch']


def test_fetch_incidents_fetch_limit(requests_mock, mocker):
    mock_date = "2020-01-01T00:00:00.000Z"
    mock_timestamp = int(time.mktime(time.strptime(mock_date, "%Y-%m-%dT%H:%M:%S.000Z")))
    create_alert_mocks(requests_mock)
    requests_mock.post(MOCK_URL + '/svc/api/v1/query-alerts', json=MOCK_ALERT_RESPONSE)
    requests_mock.post(MOCK_URL + '/svc/api/v1/query-details', json=MOCK_ALERT_DETAILS_RESPONSE[0])
    requests_mock.post(MOCK_URL + '/forensic-search/queryservice/api/v1/fileevent', json=MOCK_SECURITY_EVENT_RESPONSE)
    client = Code42Client(
        sdk=SDK,
        base_url=MOCK_URL,
        auth=("123", "123"),
        verify=False,
        proxy=None
    )
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={'last_fetch': mock_timestamp},
        first_fetch_time="24 hours",
        event_severity_filter=None,
        fetch_limit=int("2"),
        include_files=True,
        integration_context=None
    )
    assert len(incidents) == 2
    assert next_run['last_fetch']
    assert len(remaining_incidents) == 1
    # Run again to get the last incident
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={'last_fetch': mock_timestamp},
        first_fetch_time="24 hours",
        event_severity_filter=None,
        fetch_limit=int("2"),
        include_files=True,
        integration_context={'remaining_incidents': remaining_incidents}
    )
    assert len(incidents) == 1
    assert next_run['last_fetch']
    assert not remaining_incidents
