import json
import pytest
from py42.sdk.queries.fileevents.filters import FileCategory
from requests import Response
from py42.sdk import SDKClient
from py42.response import Py42Response
from py42.sdk.queries.alerts.filters import Severity
from Code42 import (
    Code42Client,
    Code42LegalHoldMatterNotFoundError,
    Code42InvalidLegalHoldMembershipError,
    get_file_category_value,
    build_query_payload,
    map_observation_to_security_query,
    map_to_code42_event_context,
    map_to_code42_alert_context,
    map_to_file_context,
    alert_get_command,
    alert_resolve_command,
    departingemployee_add_command,
    departingemployee_remove_command,
    departingemployee_get_all_command,
    highriskemployee_add_command,
    highriskemployee_remove_command,
    highriskemployee_get_all_command,
    highriskemployee_add_risk_tags_command,
    highriskemployee_remove_risk_tags_command,
    securitydata_search_command,
    user_create_command,
    user_block_command,
    user_unblock_command,
    user_deactivate_command,
    user_reactivate_command,
    legal_hold_add_user_command,
    legal_hold_remove_user_command,
    download_file_command,
    fetch_incidents,
    highriskemployee_get_command,
    departingemployee_get_command,
    Code42AlertNotFoundError,
    Code42UserNotFoundError,
    Code42OrgNotFoundError,
    Code42UnsupportedHashError,
    Code42MissingSearchArgumentsError,
)
import time

MOCK_URL = "https://123-fake-api.com"

MOCK_AUTH = ("123", "123")

MOCK_FETCH_TIME = "24 hours"

MOCK_SECURITY_DATA_SEARCH_QUERY = {
    "hash": "d41d8cd98f00b204e9800998ecf8427e",
    "hostname": "DESKTOP-0001",
    "username": "user3@example.com",
    "exposure": "ApplicationRead",
    "results": 50,
}

MOCK_SECURITY_DATA_SEARCH_QUERY_EXPOSURE_TYPE_ALL = {
    "hash": "d41d8cd98f00b204e9800998ecf8427e",
    "hostname": "DESKTOP-0001",
    "username": "user3@example.com",
    "exposure": "All",
    "results": 50,
}

MOCK_SECURITY_DATA_SEARCH_QUERY_EXPOSURE_TYPE_ALL_WITH_OTHERS = {
    "hash": "d41d8cd98f00b204e9800998ecf8427e",
    "hostname": "DESKTOP-0001",
    "username": "user3@example.com",
    "exposure": "ApplicationRead, All",
    "results": 50,
}

MOCK_SECURITY_DATA_SEARCH_QUERY_WITHOUT_EXPOSURE_TYPE = {
    "hash": "d41d8cd98f00b204e9800998ecf8427e",
    "hostname": "DESKTOP-0001",
    "username": "user3@example.com",
    "results": 50,
}

MOCK_SECURITY_EVENT_RESPONSE = """
{
    "totalCount":3,
    "fileEvents":[
        {
            "eventId":"0_1d71796f-af5b-4231-9d8e-df6434da4663_935873453596901068_956171635867906205_5",
            "eventType":"READ_BY_APP",
            "eventTimestamp":"2020-05-28T12:46:39.838Z",
            "insertionTimestamp":"2020-05-28T12:51:50.040Z",
            "fieldErrors":[],
            "filePath":"C:/Users/QA/Downloads/",
            "fileName":"company_secrets.txt",
            "fileType":"FILE",
            "fileCategory":"IMAGE",
            "fileCategoryByBytes":"Image",
            "fileCategoryByExtension":"Image",
            "fileSize":265122,
            "fileOwner":"Test",
            "md5Checksum":"9cea266b4e07974df1982ae3b9de92ce",
            "sha256Checksum":"34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
            "createTimestamp":"2020-05-28T12:43:34.902Z",
            "modifyTimestamp":"2020-05-28T12:43:35.105Z",
            "deviceUserName":"test@example.com",
            "osHostName":"HOSTNAME",
            "domainName":"host.docker.internal",
            "publicIpAddress":"255.255.255.255",
            "privateIpAddresses":["255.255.255.255","127.0.0.1"],
            "deviceUid":"935873453596901068",
            "userUid":"912098363086307495",
            "actor":null,
            "directoryId":[],
            "source":"Endpoint",
            "url":null,
            "shared":null,
            "sharedWith":[],
            "sharingTypeAdded":[],
            "cloudDriveId":null,
            "detectionSourceAlias":null,
            "fileId":null,
            "exposure":["ApplicationRead"],
            "processOwner":"QA",
            "processName":"chrome.exe",
            "windowTitle":["Jira"],
            "tabUrl":"example.com",
            "removableMediaVendor":null,
            "removableMediaName":null,
            "removableMediaSerialNumber":null,
            "removableMediaCapacity":null,
            "removableMediaBusType":null,
            "removableMediaMediaName":null,
            "removableMediaVolumeName":[],
            "removableMediaPartitionId":[],
            "syncDestination":null,
            "emailDlpPolicyNames":null,
            "emailSubject":null,
            "emailSender":null,
            "emailFrom":null,
            "emailRecipients":null,
            "outsideActiveHours":false,
            "mimeTypeByBytes":"image/png",
            "mimeTypeByExtension":"image/png",
            "mimeTypeMismatch":false,
            "printJobName":null,
            "printerName":null,
            "printedFilesBackupPath":null,
            "remoteActivity":"UNKNOWN",
            "trusted":false
        },
        {
            "eventId":"0_1d71796f-af5b-4231-9d8e-df6434da4663_935873453596901068_956171635867906205_5",
            "eventType":"READ_BY_APP",
            "eventTimestamp":"2020-05-28T12:46:39.838Z",
            "insertionTimestamp":"2020-05-28T12:51:50.040Z",
            "fieldErrors":[],
            "filePath":"C:/Users/QA/Downloads/",
            "fileName":"data.jpg",
            "fileType":"FILE",
            "fileCategory":"IMAGE",
            "fileCategoryByBytes":"Image",
            "fileCategoryByExtension":"Image",
            "fileSize":265122,
            "fileOwner":"QA",
            "md5Checksum":"9cea266b4e07974df1982ae3b9de92ce",
            "sha256Checksum":"34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
            "createTimestamp":"2020-05-28T12:43:34.902Z",
            "modifyTimestamp":"2020-05-28T12:43:35.105Z",
            "deviceUserName":"test@example.com",
            "osHostName":"TEST'S MAC",
            "domainName":"host.docker.internal",
            "publicIpAddress":"255.255.255.255",
            "privateIpAddresses":["127.0.0.1"],
            "deviceUid":"935873453596901068",
            "userUid":"912098363086307495",
            "actor":null,
            "directoryId":[],
            "source":"Endpoint",
            "url":null,
            "shared":null,
            "sharedWith":[],
            "sharingTypeAdded":[],
            "cloudDriveId":null,
            "detectionSourceAlias":null,
            "fileId":null,
            "exposure":["ApplicationRead"],
            "processOwner":"QA",
            "processName":"chrome.exe",
            "windowTitle":["Jira"],
            "tabUrl":"example.com/test",
            "removableMediaVendor":null,
            "removableMediaName":null,
            "removableMediaSerialNumber":null,
            "removableMediaCapacity":null,
            "removableMediaBusType":null,
            "removableMediaMediaName":null,
            "removableMediaVolumeName":[],
            "removableMediaPartitionId":[],
            "syncDestination":null,
            "emailDlpPolicyNames":null,
            "emailSubject":null,
            "emailSender":null,
            "emailFrom":null,
            "emailRecipients":null,
            "outsideActiveHours":false,
            "mimeTypeByBytes":"image/png",
            "mimeTypeByExtension":"image/png",
            "mimeTypeMismatch":false,
            "printJobName":null,
            "printerName":null,
            "printedFilesBackupPath":null,
            "remoteActivity":"UNKNOWN",
            "trusted":false
        },
        {
            "eventId":"0_1d71796f-af5b-4231-9d8e-df6434da4663_935873453596901068_956171635867906205_5",
            "eventType":"READ_BY_APP",
            "eventTimestamp":"2020-05-28T12:46:39.838Z",
            "insertionTimestamp":"2020-05-28T12:51:50.040Z",
            "fieldErrors":[],
            "filePath":"C:/Users/QA/Downloads/",
            "fileName":"confidential.pdf",
            "fileType":"FILE",
            "fileCategory":"IMAGE",
            "fileCategoryByBytes":"Image",
            "fileCategoryByExtension":"Image",
            "fileSize":265122,
            "fileOwner":"Mock",
            "md5Checksum":"9cea266b4e07974df1982ae3b9de92ce",
            "sha256Checksum":"34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
            "createTimestamp":"2020-05-28T12:43:34.902Z",
            "modifyTimestamp":"2020-05-28T12:43:35.105Z",
            "deviceUserName":"test@example.com",
            "osHostName":"Test's Windows",
            "domainName":"host.docker.internal",
            "publicIpAddress":"255.255.255.255",
            "privateIpAddresses":["0:0:0:0:0:0:0:1","127.0.0.1"],
            "deviceUid":"935873453596901068",
            "userUid":"912098363086307495",
            "actor":null,
            "directoryId":[],
            "source":"Endpoint",
            "url":null,
            "shared":null,
            "sharedWith":[],
            "sharingTypeAdded":[],
            "cloudDriveId":null,
            "detectionSourceAlias":null,
            "fileId":null,
            "exposure":["ApplicationRead"],
            "processOwner":"QA",
            "processName":"chrome.exe",
            "windowTitle":["Jira"],
            "tabUrl":"example.com/foo",
            "removableMediaVendor":null,
            "removableMediaName":null,
            "removableMediaSerialNumber":null,
            "removableMediaCapacity":null,
            "removableMediaBusType":null,
            "removableMediaMediaName":null,
            "removableMediaVolumeName":[],
            "removableMediaPartitionId":[],
            "syncDestination":null,
            "emailDlpPolicyNames":null,
            "emailSubject":null,
            "emailSender":null,
            "emailFrom":null,
            "emailRecipients":null,
            "outsideActiveHours":false,
            "mimeTypeByBytes":"image/png",
            "mimeTypeByExtension":"image/png",
            "mimeTypeMismatch":false,
            "printJobName":null,
            "printerName":null,
            "printedFilesBackupPath":null,
            "remoteActivity":"UNKNOWN",
            "trusted":false
        }
    ]
}
"""

MOCK_CODE42_EVENT_CONTEXT = [
    {
        "ApplicationTabURL": "example.com",
        "DevicePrivateIPAddress": ["255.255.255.255", "127.0.0.1"],
        "DeviceUsername": "test@example.com",
        "EndpointID": "935873453596901068",
        "EventID": "0_1d71796f-af5b-4231-9d8e-df6434da4663_935873453596901068_956171635867906205_5",
        "EventTimestamp": "2020-05-28T12:46:39.838Z",
        "EventType": "READ_BY_APP",
        "Exposure": ["ApplicationRead"],
        "FileCategory": "IMAGE",
        "FileCreated": "2020-05-28T12:43:34.902Z",
        "FileHostname": "HOSTNAME",
        "FileMD5": "9cea266b4e07974df1982ae3b9de92ce",
        "FileModified": "2020-05-28T12:43:35.105Z",
        "FileName": "company_secrets.txt",
        "FileOwner": "Test",
        "FilePath": "C:/Users/QA/Downloads/",
        "FileSHA256": "34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
        "FileSize": 265122,
        "ProcessName": "chrome.exe",
        "ProcessOwner": "QA",
        "Source": "Endpoint",
        "WindowTitle": ["Jira"],
    },
    {
        "ApplicationTabURL": "example.com/test",
        "DevicePrivateIPAddress": ["127.0.0.1"],
        "DeviceUsername": "test@example.com",
        "EndpointID": "935873453596901068",
        "EventID": "0_1d71796f-af5b-4231-9d8e-df6434da4663_935873453596901068_956171635867906205_5",
        "EventTimestamp": "2020-05-28T12:46:39.838Z",
        "EventType": "READ_BY_APP",
        "Exposure": ["ApplicationRead"],
        "FileCategory": "IMAGE",
        "FileCreated": "2020-05-28T12:43:34.902Z",
        "FileHostname": "TEST'S MAC",
        "FileMD5": "9cea266b4e07974df1982ae3b9de92ce",
        "FileModified": "2020-05-28T12:43:35.105Z",
        "FileName": "data.jpg",
        "FileOwner": "QA",
        "FilePath": "C:/Users/QA/Downloads/",
        "FileSHA256": "34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
        "FileSize": 265122,
        "ProcessName": "chrome.exe",
        "ProcessOwner": "QA",
        "Source": "Endpoint",
        "WindowTitle": ["Jira"],
    },
    {
        "ApplicationTabURL": "example.com/foo",
        "DevicePrivateIPAddress": ["0:0:0:0:0:0:0:1", "127.0.0.1"],
        "DeviceUsername": "test@example.com",
        "EndpointID": "935873453596901068",
        "EventID": "0_1d71796f-af5b-4231-9d8e-df6434da4663_935873453596901068_956171635867906205_5",
        "EventTimestamp": "2020-05-28T12:46:39.838Z",
        "EventType": "READ_BY_APP",
        "Exposure": ["ApplicationRead"],
        "FileCategory": "IMAGE",
        "FileCreated": "2020-05-28T12:43:34.902Z",
        "FileHostname": "Test's Windows",
        "FileMD5": "9cea266b4e07974df1982ae3b9de92ce",
        "FileModified": "2020-05-28T12:43:35.105Z",
        "FileName": "confidential.pdf",
        "FileOwner": "Mock",
        "FilePath": "C:/Users/QA/Downloads/",
        "FileSHA256": "34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
        "FileSize": 265122,
        "ProcessName": "chrome.exe",
        "ProcessOwner": "QA",
        "Source": "Endpoint",
        "WindowTitle": ["Jira"],
    },
]

MOCK_FILE_CONTEXT = [
    {
        "Hostname": "HOSTNAME",
        "MD5": "9cea266b4e07974df1982ae3b9de92ce",
        "Name": "company_secrets.txt",
        "Path": "C:/Users/QA/Downloads/",
        "SHA256": "34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
        "Size": 265122,
    },
    {
        "Hostname": "TEST'S MAC",
        "MD5": "9cea266b4e07974df1982ae3b9de92ce",
        "Name": "data.jpg",
        "Path": "C:/Users/QA/Downloads/",
        "SHA256": "34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
        "Size": 265122,
    },
    {
        "Hostname": "Test's Windows",
        "MD5": "9cea266b4e07974df1982ae3b9de92ce",
        "Name": "confidential.pdf",
        "Path": "C:/Users/QA/Downloads/",
        "SHA256": "34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
        "Size": 265122,
    },
]

MOCK_ALERTS_RESPONSE = """{
  "type$": "ALERT_QUERY_RESPONSE",
  "alerts": [
    {
      "type$": "ALERT_SUMMARY",
      "tenantId": "1d700000-af5b-4231-9d8e-df6434d00000",
      "type": "FED_ENDPOINT_EXFILTRATION",
      "name": "Departing Employee Alert",
      "description": "Cortex XSOAR is cool.",
      "actor": "user1@example.com",
      "target": "N/A",
      "severity": "HIGH",
      "ruleId": "9befe477-3487-40b7-89a6-bbcced4cf1fe",
      "ruleSource": "Departing Employee",
      "id": "36fb8ca5-0533-4d25-9763-e09d35d60610",
      "createdAt": "2019-10-02T17:02:23.5867670Z",
      "state": "OPEN"
    },
    {
      "type$": "ALERT_SUMMARY",
      "tenantId": "1d700000-af5b-4231-9d8e-df6434d00000",
      "type": "FED_CLOUD_SHARE_PERMISSIONS",
      "name": "High-Risk Employee Alert",
      "actor": "user2@example.com",
      "target": "N/A",
      "severity": "MEDIUM",
      "ruleId": "9befe477-3487-40b7-89a6-bbcced4cf1fe",
      "ruleSource": "Departing Employee",
      "id": "18ac641d-7d9c-4d37-a48f-c89396c07d03",
      "createdAt": "2019-10-02T17:02:24.2071980Z",
      "state": "OPEN"
    },
    {
      "type$": "ALERT_SUMMARY",
      "tenantId": "1d700000-af5b-4231-9d8e-df6434d00000",
      "type": "FED_ENDPOINT_EXFILTRATION",
      "name": "Custom Alert 1",
      "actor": "user3@example.com",
      "target": "N/A",
      "severity": "LOW",
      "ruleId": "9befe477-3487-40b7-89a6-bbcced4cf1fe",
      "ruleSource": "Departing Employee",
      "id": "3137ff1b-b824-42e4-a476-22bccdd8ddb8",
      "createdAt": "2019-10-02T17:03:28.2885720Z",
      "state": "OPEN"
    }
  ],
  "totalCount": 3,
  "problems": []
}"""

MOCK_ALERT_DETAILS_RESPONSE = """{
  "type$": "ALERT_DETAILS_RESPONSE",
  "alerts": [
    {
      "type$": "ALERT_DETAILS",
      "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
      "type": "FED_ENDPOINT_EXFILTRATION",
      "name": "Departing Employee Alert",
      "description": "Cortex XSOAR is cool.",
      "actor": "user1@example.com",
      "actorId": "912098363086307495",
      "target": "N/A",
      "severity": "HIGH",
      "ruleId": "4576576e-13cb-4f88-be3a-ee77739de649",
      "ruleSource": "Alerting",
      "id": "36fb8ca5-0533-4d25-9763-e09d35d60610",
      "createdAt": "2019-10-02T17:02:23.5867670Z",
      "state": "OPEN",
      "observations": [
        {
          "type$": "OBSERVATION",
          "id": "240526fc-3a32-4755-85ab-c6ee6e7f31ce",
          "observedAt": "2020-05-28T12:50:00.0000000Z",
          "type": "FedEndpointExfiltration",
          "data": {
            "type$": "OBSERVED_ENDPOINT_ACTIVITY",
            "id": "240526fc-3a32-4755-85ab-c6ee6e7f31ce",
            "sources": [
              "Endpoint"
            ],
            "exposureTypes": [
              "ApplicationRead"
            ],
            "firstActivityAt": "2020-05-28T12:50:00.0000000Z",
            "lastActivityAt": "2020-05-28T12:50:00.0000000Z",
            "fileCount": 3,
            "totalFileSize": 533846,
            "fileCategories": [
              {
                "type$": "OBSERVED_FILE_CATEGORY",
                "category": "SourceCode",
                "fileCount": 3,
                "totalFileSize": 533846,
                "isSignificant": true
              },
              {
                "type$": "OBSERVED_FILE_CATEGORY",
                "category": "Pdf",
                "fileCount": 3,
                "totalFileSize": 533846,
                "isSignificant": true
              }
            ],
            "files": [
              {
                "type$": "OBSERVED_FILE",
                "eventId": "0_1d71796f-af5b-4231-9d8e-df6434da4663_935873453596901068_956171635867906205_5",
                "path": "C:/Users/QA/Downloads/",
                "name": "Customers.jpg",
                "category": "Image",
                "size": 265122
              },
              {
                "type$": "OBSERVED_FILE",
                "eventId": "0_1d71796f-af5b-4231-9d8e-df6434da4663_935873453596901068_956171635867906205_6",
                "path": "C:/Users/QA/Downloads/",
                "name": "data.png",
                "category": "Image",
                "size": 129129
              },
              {
                "type$": "OBSERVED_FILE",
                "eventId": "0_1d71796f-af5b-4231-9d8e-df6434da4663_935873453596901068_956171635867906205_7",
                "path": "C:/Users/QA/Downloads/",
                "name": "company_secrets.ps",
                "category": "Image",
                "size": 139595
              }
            ],
            "syncToServices": [],
            "sendingIpAddresses": [
              "127.0.0.1"
            ]
          }
        },
        {
          "type$": "OBSERVATION",
          "id": "7f4d125d-c7ca-4264-83fe-fa442bf270b6",
          "observedAt": "2020-06-11T20:20:00.0000000Z",
          "type": "FedCloudSharePermissions",
          "data": {
            "type$": "OBSERVED_CLOUD_SHARE_ACTIVITY",
            "id": "7f4d125d-c7ca-4264-83fe-fa442bf270b6",
            "sources": [
              "GoogleDrive"
            ],
            "exposureTypes": [
              "SharedOutsideTrustedDomain"
            ],
            "firstActivityAt": "2020-06-11T20:20:00.0000000Z",
            "lastActivityAt": "2020-06-11T20:25:00.0000000Z",
            "fileCount": 1,
            "totalFileSize": 182554405,
            "fileCategories": [
              {
                "type$": "OBSERVED_FILE_CATEGORY",
                "category": "Archive",
                "fileCount": 1,
                "totalFileSize": 182554405,
                "isSignificant": false
              }
            ],
            "files": [
              {
                "type$": "OBSERVED_FILE",
                "eventId": "14FnN9-YOhVUO_Tv8Mu-hEgevc2K4l07l_5_9e633ffd-9329-4cf4-8645-27a23b83ebc0",
                "name": "Code42CrashPlan_8.0.0_1525200006800_778_Mac.dmg",
                "category": "Archive",
                "size": 182554405
              }
            ],
            "outsideTrustedDomainsEmails": [
              "user1@example.com"
            ],
            "outsideTrustedDomainsEmailsCount": 1,
            "outsideTrustedDomainsCounts": [
              {
                "type$": "OBSERVED_DOMAIN_INFO",
                "domain": "gmail.com",
                "count": 1
              }
            ],
            "outsideTrustedDomainsTotalDomainCount": 1,
            "outsideTrustedDomainsTotalDomainCountTruncated": false
          }
        },
        {
          "type$": "OBSERVATION",
          "id": "7f4d125d-c7ca-4264-83fe-fa442bf270b6",
          "observedAt": "2020-06-11T20:20:00.0000000Z",
          "type": "FedCloudSharePermissions",
          "data": {
            "type$": "OBSERVED_CLOUD_SHARE_ACTIVITY",
            "id": "7f4d125d-c7ca-4264-83fe-fa442bf270b6",
            "sources": [
              "GoogleDrive"
            ],
            "exposureTypes": [
              "UnknownExposureTypeThatWeDontSupportYet"
            ],
            "firstActivityAt": "2020-06-11T20:20:00.0000000Z",
            "lastActivityAt": "2020-06-11T20:25:00.0000000Z",
            "fileCount": 1,
            "totalFileSize": 182554405,
            "fileCategories": [
              {
                "type$": "OBSERVED_FILE_CATEGORY",
                "category": "Archive",
                "fileCount": 1,
                "totalFileSize": 182554405,
                "isSignificant": false
              }
            ],
            "files": [
              {
                "type$": "OBSERVED_FILE",
                "eventId": "14FnN9-YOhVUO_Tv8Mu-hEgevc2K4l07l_5_9e633ffd-9329-4cf4-8645-27a23b83ebc0",
                "name": "Code42CrashPlan_8.0.0_1525200006800_778_Mac.dmg",
                "category": "Archive",
                "size": 182554405
              }
            ],
            "outsideTrustedDomainsEmails": [
              "user1@example.com"
            ],
            "outsideTrustedDomainsEmailsCount": 1,
            "outsideTrustedDomainsCounts": [
              {
                "type$": "OBSERVED_DOMAIN_INFO",
                "domain": "gmail.com",
                "count": 1
              }
            ],
            "outsideTrustedDomainsTotalDomainCount": 1,
            "outsideTrustedDomainsTotalDomainCountTruncated": false
          }
        }
      ]
    }
  ]
}"""

MOCK_CODE42_ALERT_CONTEXT = [
    {
        "ID": "36fb8ca5-0533-4d25-9763-e09d35d60610",
        "Name": "Departing Employee Alert",
        "Description": "Cortex XSOAR is cool.",
        "Occurred": "2019-10-02T17:02:23.5867670Z",
        "Severity": "HIGH",
        "State": "OPEN",
        "Type": "FED_ENDPOINT_EXFILTRATION",
        "Username": "user1@example.com",
    },
    {
        "ID": "18ac641d-7d9c-4d37-a48f-c89396c07d03",
        "Name": "High-Risk Employee Alert",
        "Occurred": "2019-10-02T17:02:24.2071980Z",
        "Severity": "MEDIUM",
        "State": "OPEN",
        "Type": "FED_CLOUD_SHARE_PERMISSIONS",
        "Username": "user2@example.com",
    },
    {
        "ID": "3137ff1b-b824-42e4-a476-22bccdd8ddb8",
        "Name": "Custom Alert 1",
        "Occurred": "2019-10-02T17:03:28.2885720Z",
        "Severity": "LOW",
        "State": "OPEN",
        "Type": "FED_ENDPOINT_EXFILTRATION",
        "Username": "user3@example.com",
    },
]

MOCK_FILE_EVENT_QUERY_PAYLOAD = {
    "groupClause": "AND",
    "groups": [
        {
            "filterClause": "AND",
            "filters": [
                {
                    "operator": "IS",
                    "term": "md5Checksum",
                    "value": "d41d8cd98f00b204e9800998ecf8427e",
                }
            ],
        },
        {
            "filterClause": "AND",
            "filters": [{"operator": "IS", "term": "osHostName", "value": "DESKTOP-0001"}],
        },
        {
            "filterClause": "AND",
            "filters": [{"operator": "IS", "term": "deviceUserName", "value": "user3@example.com"}],
        },
        {
            "filterClause": "AND",
            "filters": [{"operator": "IS", "term": "exposure", "value": "ApplicationRead"}],
        },
    ],
    "pgNum": 1,
    "pgSize": 50,
    "srtDir": "asc",
    "srtKey": "eventId",
}

MOCK_OBSERVATION_QUERIES = [
    {
        "groupClause": "AND",
        "groups": [
            {
                "filterClause": "AND",
                "filters": [
                    {"operator": "IS", "term": "deviceUserName", "value": "user1@example.com"}
                ],
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_AFTER",
                        "term": "eventTimestamp",
                        "value": "2020-05-28T12:50:00.000Z",
                    }
                ],
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_BEFORE",
                        "term": "eventTimestamp",
                        "value": "2020-05-28T12:50:00.000Z",
                    }
                ],
            },
            {
                "filterClause": "OR",
                "filters": [
                    {"operator": "IS", "term": "eventType", "value": "CREATED"},
                    {"operator": "IS", "term": "eventType", "value": "MODIFIED"},
                    {"operator": "IS", "term": "eventType", "value": "READ_BY_APP"},
                ],
            },
            {
                "filterClause": "AND",
                "filters": [{"operator": "IS", "term": "exposure", "value": "ApplicationRead"}],
            },
            {
                "filterClause": "OR",
                "filters": [
                    {"operator": "IS", "term": "fileCategory", "value": "PDF"},
                    {"operator": "IS", "term": "fileCategory", "value": "SOURCE_CODE"}
                ]
            }
        ],
        "pgNum": 1,
        "pgSize": 10000,
        "srtDir": "asc",
        "srtKey": "eventId",
    },
    {
        "groupClause": "AND",
        "groups": [
            {
                "filterClause": "AND",
                "filters": [{"operator": "IS", "term": "actor", "value": "user1@example.com"}],
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_AFTER",
                        "term": "eventTimestamp",
                        "value": "2020-06-11T20:20:00.000Z",
                    }
                ],
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_BEFORE",
                        "term": "eventTimestamp",
                        "value": "2020-06-11T20:25:00.000Z",
                    }
                ],
            },
            {
                "filterClause": "AND",
                "filters": [
                    {"operator": "IS", "term": "exposure", "value": "OutsideTrustedDomains"}
                ],
            },
        ],
        "pgNum": 1,
        "pgSize": 10000,
        "srtDir": "asc",
        "srtKey": "eventId",
    },
    {
        "groupClause": "AND",
        "groups": [
            {
                "filterClause": "AND",
                "filters": [{"operator": "IS", "term": "actor", "value": "user1@example.com"}],
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_AFTER",
                        "term": "eventTimestamp",
                        "value": "2020-06-11T20:20:00.000Z",
                    }
                ],
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_BEFORE",
                        "term": "eventTimestamp",
                        "value": "2020-06-11T20:25:00.000Z",
                    }
                ],
            },
            {
                "filterClause": "AND",
                "filters": [
                    {"operator": "IS_NOT", "term": "exposure", "value": "IsPublic"},
                    {"operator": "IS_NOT", "term": "exposure", "value": "OutsideTrustedDomains"},
                    {"operator": "IS_NOT", "term": "exposure", "value": "SharedViaLink"},
                ],
            },
        ],
        "pgNum": 1,
        "pgSize": 10000,
        "srtDir": "asc",
        "srtKey": "eventId",
    },
    {
        "groupClause": "AND",
        "groups": [
            {
                "filterClause": "AND",
                "filters": [
                    {"operator": "IS", "term": "deviceUserName", "value": "user3@example.com"}
                ],
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_AFTER",
                        "term": "eventTimestamp",
                        "value": "2019-10-02T16:50:00.000Z",
                    }
                ],
            },
            {
                "filterClause": "AND",
                "filters": [
                    {
                        "operator": "ON_OR_BEFORE",
                        "term": "eventTimestamp",
                        "value": "2019-10-02T16:50:00.000Z",
                    }
                ],
            },
            {
                "filterClause": "OR",
                "filters": [
                    {"operator": "IS", "term": "eventType", "value": "CREATED"},
                    {"operator": "IS", "term": "eventType", "value": "MODIFIED"},
                    {"operator": "IS", "term": "eventType", "value": "READ_BY_APP"},
                ],
            },
            {
                "filterClause": "AND",
                "filters": [{"operator": "IS", "term": "exposure", "value": "RemovableMedia"}],
            },
        ],
        "pgNum": 1,
        "pgSize": 10000,
        "srtDir": "asc",
        "srtKey": "eventId",
    },
]


MOCK_GET_USER_RESPONSE = """
{
    "totalCount": 1,
    "users": [
        {
            "userId": 123456,
            "userUid": "123412341234123412",
            "status": "Active",
            "username": "test.testerson@example.com",
            "email": "test.testerson@example.com",
            "firstName": "Test",
            "lastName": "Testerson",
            "quotaInBytes": -1,
            "orgId": 1111,
            "orgUid": "81111247111106706",
            "orgName": "Testers",
            "userExtRef": null,
            "notes": null,
            "active": true,
            "blocked": false,
            "emailPromo": true,
            "invited": false,
            "orgType": "ENTERPRISE",
            "usernameIsAnEmail": true,
            "creationDate": "2019-09-30T21:03:08.587Z",
            "modificationDate": "2020-04-10T11:49:49.987Z",
            "passwordReset": false,
            "localAuthenticationOnly": false,
            "licenses": ["admin.securityTools"]
        }
    ]
}"""


MOCK_GET_ALL_ORGS_RESPONSE = """
{
    "totalCount": 1,
    "orgs":
    [
        {
            "orgId": 9999,
            "orgUid": "890854247383109999",
            "orgName": "TestCortexOrg",
            "orgExtRef": null,
            "notes": null,
            "status": "Active",
            "active": true,
            "blocked": false,
            "parentOrgId": 2686,
            "parentOrgUid": "00007871952600000",
            "type": "ENTERPRISE",
            "classification": "BASIC",
            "externalId": "000054247383100000",
            "hierarchyCounts": {},
            "configInheritanceCounts": {},
            "creationDate": "2019-03-04T22:21:49.749Z",
            "modificationDate": "2020-02-26T19:21:57.684Z",
            "deactivationDate": null,
            "registrationKey": "0000-H74U-0000-8MMM",
            "reporting":
            {
                "orgManagers": []
            },
            "customConfig": true,
            "settings":
            {
                "maxSeats": null,
                "maxBytes": null
            },
            "settingsInherited":
            {
                "maxSeats": "",
                "maxBytes": ""
            },
            "settingsSummary":
            {
                "maxSeats": "",
                "maxBytes": ""
            }
        }
    ]
}"""


MOCK_GET_ALL_DEPARTING_EMPLOYEES_RESPONSE = """
{
    "items": [
        {
            "type$": "DEPARTING_EMPLOYEE_V2",
            "tenantId": 1000,
            "userId": "890973079883949999",
            "userName": "test@example.com",
            "displayName": "Name",
            "notes": "",
            "createdAt": "2019-10-25T13:31:14.1199010Z",
            "status": "OPEN",
            "cloudUsernames": ["test@cloud.com"],
            "totalBytes": 139856482,
            "numEvents": 11
        },
        {
            "type$": "DEPARTING_EMPLOYEE_V2",
            "tenantId": 1000,
            "userId": "123412341234123412",
            "userName": "user1@example.com",
            "displayName": "Name",
            "notes": "",
            "createdAt": "2019-10-25T13:31:14.1199010Z",
            "status": "OPEN",
            "cloudUsernames": ["test@example.com"],
            "totalBytes": 139856482,
            "numEvents": 11,
            "departureDate": "2020-07-20"
        },
        {
            "type$": "DEPARTING_EMPLOYEE_V2",
            "tenantId": 1000,
            "userId": "890973079883949999",
            "userName": "test@example.com",
            "displayName": "Name",
            "notes": "",
            "createdAt": "2019-10-25T13:31:14.1199010Z",
            "status": "OPEN",
            "cloudUsernames": ["test@example.com"],
            "totalBytes": 139856482,
            "numEvents": 11
        }
    ],
    "totalCount": 3
}
"""


MOCK_GET_ALL_HIGH_RISK_EMPLOYEES_RESPONSE = """
{
  "type$": "HIGH_RISK_SEARCH_RESPONSE_V2",
  "items": [
    {
      "type$": "HIGH_RISK_EMPLOYEE_V2",
      "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
      "userId": "91209844444444444",
      "userName": "karen@example.com",
      "displayName": "Karen",
      "notes": "High risk notes",
      "createdAt": "2020-05-22T17:47:42.7054310Z",
      "status": "OPEN",
      "cloudUsernames": [
        "karen+test@example.com",
        "karen+manager@example.com"
      ],
      "totalBytes": 816122,
      "numEvents": 13,
      "riskFactors": [
        "PERFORMANCE_CONCERNS",
        "SUSPICIOUS_SYSTEM_ACTIVITY",
        "POOR_SECURITY_PRACTICES"
      ]
    },
    {
      "type$": "HIGH_RISK_EMPLOYEE_V2",
      "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
      "userId": "94222222975202822222",
      "userName": "james.test@example.com",
      "displayName": "James Test",
      "notes": "tests and more tests",
      "createdAt": "2020-05-28T12:39:57.2058370Z",
      "status": "OPEN",
      "cloudUsernames": [
        "james.test+test@example.com"
      ]
    },
    {
      "type$": "HIGH_RISK_EMPLOYEE_V2",
      "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
      "userId": "123412341234123412",
      "userName": "user1@example.com",
      "displayName": "User 1",
      "notes": "Test Notes",
      "createdAt": "2020-05-22T17:47:42.4836920Z",
      "status": "OPEN",
      "cloudUsernames": [
        "test@example.com",
        "abc123@example.com"
      ],
      "riskFactors": [
        "PERFORMANCE_CONCERNS"
      ]
    }
  ],
  "totalCount": 3,
  "rollups": [
    {
      "type$": "HIGH_RISK_FILTER_ROLLUP_V2",
      "filterType": "OPEN",
      "totalCount": 3
    },
    {
      "type$": "HIGH_RISK_FILTER_ROLLUP_V2",
      "filterType": "EXFILTRATION_24_HOURS",
      "totalCount": 0
    },
    {
      "type$": "HIGH_RISK_FILTER_ROLLUP_V2",
      "filterType": "EXFILTRATION_30_DAYS",
      "totalCount": 1
    }
  ],
  "filterType": "OPEN",
  "pgSize": 10,
  "pgNum": 1,
  "srtKey": "NUM_EVENTS",
  "srtDirection": "DESC"
}
"""


MOCK_CREATE_USER_RESPONSE = """
{
    "userId": 291999,
    "userUid": "960849588659999999",
    "status": "Active",
    "username": "new.user@example.com",
    "email": "new.user@example.com",
    "firstName": null,
    "lastName": null,
    "quotaInBytes": -1,
    "orgId": 2689,
    "orgUid": "890854247383106706",
    "orgName": "New Users Org",
    "userExtRef": null,
    "notes": null,
    "active": true,
    "blocked": false,
    "emailPromo": true,
    "invited": true,
    "orgType": "ENTERPRISE",
    "usernameIsAnEmail": null,
    "creationDate": "2020-06-29T19:23:04.285Z",
    "modificationDate": "2020-06-29T19:23:04.306Z",
    "passwordReset": false,
    "localAuthenticationOnly": false,
    "licenses": []
}
"""

MOCK_GET_DETECTIONLIST_RESPONSE = """
{
    "type$": "DEPARTING_EMPLOYEE_V2",
    "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
    "userId": "942897397520286581",
    "userName": "new.user@example.com",
    "displayName": "New user",
    "notes": "tests and more tests",
    "createdAt": "2020-05-19T21:17:36.0237810Z",
    "status": "OPEN",
    "cloudUsernames": ["new.user.cloud@example.com"]
}
"""


MOCK_ADD_TO_MATTER_RESPONSE = """
{
    "legalHoldMembershipUid":"645579283748927372",
    "active":true,
    "creationDate":"2015-05-16T15:07:44.820-05:00",
    "legalHold":{
      "legalHoldUid":"645576513911664484",
      "name":"Patent Lawsuit"
    },
    "user":{
      "userUid":"123412341234123412",
      "username":"user1@example.com",
      "email":"user1@example.com",
      "userExtRef":null
    }
}
"""

MOCK_GET_ALL_MATTERS_RESPONSE = """
{
    "legalHolds":[
      {
        "legalHoldUid":"645576513911664484",
        "name":"Patent Lawsuit",
        "description":"Lawsuit from Acme Inc demanding we license their software patents.",
        "notes":"Engineering is still reviewing what, if any, of our components are actually infringing.",
        "holdExtRef":"Case 13a-32f",
        "active":true,
        "creationDate":"2015-05-16T15:07:44.820-05:00",
        "lastModified":"2015-05-16T15:07:44.820-05:00",
        "holdPolicyUid":"23456753135798456",
        "creator":{
          "userUid":"123412341234123412",
          "username":"user1@example.com",
          "email":"user1@example.com",
          "userExtRef":null
        }
      }
    ]
}
"""

MOCK_GET_ALL_MATTER_CUSTODIANS_RESPONSE = """
{
    "legalHoldMemberships":[
          {
            "legalHoldMembershipUid":"645579283748927372",
            "active":true,
            "creationDate":"2015-05-16T15:07:44.820-05:00",
            "legalHold":{
              "legalHoldUid":"645576513911664484",
              "name":"Patent Lawsuit"
            },
            "user":{
              "userUid":"123412341234123412",
              "username":"user1@example.com",
              "email":"user1@example.com",
              "userExtRef":null
            }
          }
        ]
}
"""

_TEST_USER_ID = "123412341234123412"  # value found in GET_USER_RESPONSE
_TEST_USERNAME = "user1@example.com"
_TEST_ORG_NAME = "TestCortexOrg"


@pytest.fixture
def code42_sdk_mock(mocker):
    code42_mock = mocker.MagicMock(spec=SDKClient)
    get_user_response = create_mock_code42_sdk_response(mocker, MOCK_GET_USER_RESPONSE)
    get_org_response = create_mock_code42_sdk_response_generator(
        mocker, [MOCK_GET_ALL_ORGS_RESPONSE]
    )
    code42_mock.users.get_by_username.return_value = get_user_response
    code42_mock.orgs.get_all.return_value = get_org_response
    return code42_mock


@pytest.fixture
def code42_alerts_mock(code42_sdk_mock, mocker):
    return create_alerts_mock(code42_sdk_mock, mocker)


@pytest.fixture
def code42_file_events_mock(code42_sdk_mock, mocker):
    return create_file_events_mock(code42_sdk_mock, mocker)


@pytest.fixture
def code42_fetch_incidents_mock(code42_sdk_mock, mocker):
    code42_mock = create_alerts_mock(code42_sdk_mock, mocker)
    code42_mock = create_file_events_mock(code42_mock, mocker)
    return code42_mock


@pytest.fixture
def code42_users_mock(code42_sdk_mock, mocker):
    create_user_response = create_mock_code42_sdk_response(mocker, MOCK_CREATE_USER_RESPONSE)
    code42_sdk_mock.users.create_user.return_value = create_user_response
    return code42_sdk_mock


def create_alerts_mock(c42_sdk_mock, mocker):
    alert_details_response = create_mock_code42_sdk_response(mocker, MOCK_ALERT_DETAILS_RESPONSE)
    c42_sdk_mock.alerts.get_details.return_value = alert_details_response
    alerts_response = create_mock_code42_sdk_response(mocker, MOCK_ALERTS_RESPONSE)
    c42_sdk_mock.alerts.search.return_value = alerts_response
    return c42_sdk_mock


def create_file_events_mock(c42_sdk_mock, mocker):
    search_file_events_response = create_mock_code42_sdk_response(
        mocker, MOCK_SECURITY_EVENT_RESPONSE
    )
    c42_sdk_mock.securitydata.search_file_events.return_value = search_file_events_response
    return c42_sdk_mock


@pytest.fixture
def code42_departing_employee_mock(code42_sdk_mock, mocker):
    all_departing_employees_response = create_mock_code42_sdk_response_generator(
        mocker, [MOCK_GET_ALL_DEPARTING_EMPLOYEES_RESPONSE]
    )
    code42_sdk_mock.detectionlists.departing_employee.get_all.return_value = (
        all_departing_employees_response
    )
    return code42_sdk_mock


@pytest.fixture
def code42_high_risk_employee_mock(code42_sdk_mock, mocker):
    all_high_risk_employees_response = create_mock_code42_sdk_response_generator(
        mocker, [MOCK_GET_ALL_HIGH_RISK_EMPLOYEES_RESPONSE]
    )
    code42_sdk_mock.detectionlists.high_risk_employee.get_all.return_value = (
        all_high_risk_employees_response
    )
    return code42_sdk_mock


@pytest.fixture
def code42_departing_employee_get_mock(code42_sdk_mock, mocker):
    single_departing_employee = json.loads(MOCK_GET_ALL_DEPARTING_EMPLOYEES_RESPONSE)["items"][0]
    response = create_mock_code42_sdk_response(mocker, json.dumps(single_departing_employee))
    code42_sdk_mock.detectionlists.departing_employee.get.return_value = response
    return code42_sdk_mock


@pytest.fixture
def code42_high_risk_employee_get_mock(code42_sdk_mock, mocker):
    single_high_risk_employee = json.loads(MOCK_GET_ALL_HIGH_RISK_EMPLOYEES_RESPONSE)["items"][0]
    response = create_mock_code42_sdk_response(mocker, json.dumps(single_high_risk_employee))
    code42_sdk_mock.detectionlists.high_risk_employee.get.return_value = response
    return code42_sdk_mock


@pytest.fixture
def code42_legal_hold_mock(code42_sdk_mock, mocker):
    code42_sdk_mock.legalhold.get_all_matters.return_value = create_mock_code42_sdk_response_generator(
        mocker, [MOCK_GET_ALL_MATTERS_RESPONSE]
    )
    code42_sdk_mock.legalhold.get_all_matter_custodians.return_value = (
        create_mock_code42_sdk_response_generator(mocker, [MOCK_GET_ALL_MATTER_CUSTODIANS_RESPONSE])
    )
    code42_sdk_mock.legalhold.add_to_matter.return_value = (
        create_mock_code42_sdk_response(mocker, MOCK_ADD_TO_MATTER_RESPONSE)
    )
    return code42_sdk_mock


def create_mock_code42_sdk_response(mocker, response_text):
    response_mock = mocker.MagicMock(spec=Response)
    response_mock.text = response_text
    return Py42Response(response_mock)


def create_mock_code42_sdk_response_generator(mocker, response_pages):
    return (create_mock_code42_sdk_response(mocker, page) for page in response_pages)


def create_client(sdk):
    return Code42Client(sdk=sdk, base_url=MOCK_URL, auth=MOCK_AUTH, verify=False, proxy=False)


def get_empty_detectionlist_response(mocker, base_text):
    no_employees_response_text = json.loads(base_text)
    no_employees_response_text["items"] = []
    no_employees_response_text = json.dumps(no_employees_response_text)
    return create_mock_code42_sdk_response_generator(mocker, [no_employees_response_text])


def get_empty_legalhold_matters_response(mocker, base_text):
    no_matters_response_text = json.loads(base_text)
    no_matters_response_text["legalHolds"] = []
    no_matters_response_text = json.dumps(no_matters_response_text)
    return create_mock_code42_sdk_response_generator(mocker, [no_matters_response_text])


def get_empty_legalhold_custodians_response(mocker, base_text):
    no_members_response_text = json.loads(base_text)
    no_members_response_text["legalHoldMemberships"] = []
    no_members_response_text = json.dumps(no_members_response_text)
    return create_mock_code42_sdk_response_generator(mocker, [no_members_response_text])


def assert_departingemployee_outputs_match_response(outputs_list, response_items):
    assert_detection_list_outputs_match_response_items(outputs_list, response_items)
    for i in range(0, len(outputs_list)):
        assert outputs_list[i]["DepartureDate"] == response_items[i].get("departureDate")


def assert_detection_list_outputs_match_response_items(outputs_list, response_items):
    assert len(outputs_list) == len(response_items)
    for i in range(0, len(outputs_list)):
        assert outputs_list[i]["Username"] == response_items[i]["userName"]
        assert outputs_list[i]["UserID"] == response_items[i]["userId"]
        assert outputs_list[i]["Note"] == response_items[i]["notes"]


"""TESTS"""


def test_get_file_category_value_handles_screaming_snake_case():
    actual = get_file_category_value("SOURCE_CODE")
    expected = FileCategory.SOURCE_CODE
    assert actual == expected


def test_get_file_category_value_handles_capitalized_case():
    actual = get_file_category_value("Pdf")
    expected = FileCategory.PDF
    assert actual == expected


def test_get_file_category_value_handles_lower_case():
    actual = get_file_category_value("pdf")
    expected = FileCategory.PDF
    assert actual == expected


def test_get_file_category_value_handles_upper_case():
    actual = get_file_category_value("PDF")
    expected = FileCategory.PDF
    assert actual == expected


def test_get_file_category_value_handles_pascal_case():
    actual = get_file_category_value("SourceCode")
    expected = FileCategory.SOURCE_CODE
    assert actual == expected


def test_get_file_category_value_handles_hungarian_case():
    actual = get_file_category_value("sourceCode")
    expected = FileCategory.SOURCE_CODE
    assert actual == expected


def test_get_file_category_value_handles_hyphenated_case():
    actual = get_file_category_value("source-code")
    expected = FileCategory.SOURCE_CODE
    assert actual == expected


def test_client_lazily_inits_sdk(mocker, code42_sdk_mock):
    sdk_factory_mock = mocker.patch("py42.sdk.from_local_account")
    response_json_mock = """{"total": 1, "users": [{"username": "Test"}]}"""
    code42_sdk_mock.users.get_by_username.return_value = create_mock_code42_sdk_response(
        mocker, response_json_mock
    )
    sdk_factory_mock.return_value = code42_sdk_mock

    # test that sdk does not init during ctor
    client = Code42Client(sdk=None, base_url=MOCK_URL, auth=MOCK_AUTH, verify=False, proxy=False)
    assert client._sdk is None

    # test that sdk init from first method call
    client.get_user("Test")
    assert client._sdk is not None


def test_client_when_no_alert_found_raises_alert_not_found(mocker, code42_sdk_mock):
    response_json = """{"alerts": []}"""
    code42_sdk_mock.alerts.get_details.return_value = create_mock_code42_sdk_response(
        mocker, response_json
    )
    client = create_client(code42_sdk_mock)
    with pytest.raises(Code42AlertNotFoundError):
        client.get_alert_details("mock-id")


def test_client_when_no_user_found_raises_user_not_found(mocker, code42_sdk_mock):
    response_json = """{"totalCount": 0, "users": []}"""
    code42_sdk_mock.users.get_by_username.return_value = create_mock_code42_sdk_response(
        mocker, response_json
    )
    client = create_client(code42_sdk_mock)
    with pytest.raises(Code42UserNotFoundError):
        client.get_user("test@example.com")


def test_client_add_to_matter_when_no_legal_hold_matter_found_raises_matter_not_found(code42_sdk_mock, mocker):

    code42_sdk_mock.legalhold.get_all_matters.return_value = (
        get_empty_legalhold_matters_response(mocker, MOCK_GET_ALL_MATTERS_RESPONSE)
    )

    client = create_client(code42_sdk_mock)
    with pytest.raises(Code42LegalHoldMatterNotFoundError):
        client.add_user_to_legal_hold_matter("TESTUSERNAME", "TESTMATTERNAME")


def test_client_add_to_matter_when_no_user_found_raises_user_not_found(mocker, code42_sdk_mock):
    response_json = '{"totalCount":0, "users":[]}'
    code42_sdk_mock.users.get_by_username.return_value = create_mock_code42_sdk_response(mocker, response_json)
    client = create_client(code42_sdk_mock)
    with pytest.raises(Code42UserNotFoundError):
        client.add_user_to_legal_hold_matter("TESTUSERNAME", "TESTMATTERNAME")


def test_client_remove_from_matter_when_no_legal_hold_matter_found_raises_exception(code42_sdk_mock, mocker):
    code42_sdk_mock.legalhold.get_all_matters.return_value = (
        get_empty_legalhold_matters_response(mocker, MOCK_GET_ALL_MATTERS_RESPONSE)
    )

    client = create_client(code42_sdk_mock)
    with pytest.raises(Code42LegalHoldMatterNotFoundError):
        client.remove_user_from_legal_hold_matter("TESTUSERNAME", "TESTMATTERNAME")


def test_client_remove_from_matter_when_no_user_found_raises_user_not_found(mocker, code42_sdk_mock):
    response_json = '{"totalCount":0, "users":[]}'
    code42_sdk_mock.users.get_by_username.return_value = create_mock_code42_sdk_response(mocker, response_json)
    client = create_client(code42_sdk_mock)
    with pytest.raises(Code42UserNotFoundError):
        client.remove_user_from_legal_hold_matter("TESTUSERNAME", "TESTMATTERNAME")


def test_client_remove_from_matter_when_no_membership_raises_invalid_legal_hold_membership(code42_legal_hold_mock, mocker):
    code42_legal_hold_mock.legalhold.get_all_matter_custodians.return_value = (
        get_empty_legalhold_custodians_response(mocker, MOCK_GET_ALL_MATTER_CUSTODIANS_RESPONSE)
    )
    client = create_client(code42_legal_hold_mock)
    with pytest.raises(Code42InvalidLegalHoldMembershipError):
        client.remove_user_from_legal_hold_matter("TESTUSERNAME", "TESTMATTERNAME")


def test_build_query_payload():
    query = build_query_payload(MOCK_SECURITY_DATA_SEARCH_QUERY)
    assert query.sort_key == MOCK_FILE_EVENT_QUERY_PAYLOAD["srtKey"]
    assert query.page_number == MOCK_FILE_EVENT_QUERY_PAYLOAD["pgNum"]
    assert json.loads((str(query))) == MOCK_FILE_EVENT_QUERY_PAYLOAD


def test_map_observation_to_security_query():
    response = json.loads(MOCK_ALERT_DETAILS_RESPONSE)
    alert = response["alerts"][0]
    actor = alert["actor"]
    observations = alert["observations"]
    actual_queries = [
        json.loads(str(map_observation_to_security_query(o, actor))) for o in observations
    ]
    assert actual_queries[0] == MOCK_OBSERVATION_QUERIES[0]
    assert actual_queries[1] == MOCK_OBSERVATION_QUERIES[1]
    assert actual_queries[2] == MOCK_OBSERVATION_QUERIES[2]


def test_map_to_code42_event_context():
    response = json.loads(MOCK_SECURITY_EVENT_RESPONSE)
    file_events = response["fileEvents"]
    for i in range(0, len(file_events)):
        context = map_to_code42_event_context(file_events[i])
        assert context == MOCK_CODE42_EVENT_CONTEXT[i]


def test_map_to_code42_alert_context():
    response = json.loads(MOCK_ALERT_DETAILS_RESPONSE)
    alerts = response["alerts"]
    for i in range(0, len(alerts)):
        context = map_to_code42_alert_context(alerts[i])
        assert context == MOCK_CODE42_ALERT_CONTEXT[i]


def test_map_to_file_context():
    response = json.loads(MOCK_SECURITY_EVENT_RESPONSE)
    file_events = response["fileEvents"]
    for i in range(0, len(file_events)):
        context = map_to_file_context(file_events[i])
        assert context == MOCK_FILE_CONTEXT[i]


def test_alert_get_command(code42_alerts_mock):
    client = create_client(code42_alerts_mock)
    cmd_res = alert_get_command(client, {"id": "4576576e-13cb-4f88-be3a-ee77739de649"})
    assert cmd_res.raw_response["ruleId"] == "4576576e-13cb-4f88-be3a-ee77739de649"
    assert cmd_res.outputs == [MOCK_CODE42_ALERT_CONTEXT[0]]
    assert cmd_res.outputs_prefix == "Code42.SecurityAlert"
    assert cmd_res.outputs_key_field == "ID"


def test_alert_resolve_command(code42_alerts_mock):
    client = create_client(code42_alerts_mock)
    cmd_res = alert_resolve_command(client, {"id": "4576576e-13cb-4f88-be3a-ee77739de649"})
    assert cmd_res.raw_response["ruleId"] == "4576576e-13cb-4f88-be3a-ee77739de649"
    assert cmd_res.outputs == [MOCK_CODE42_ALERT_CONTEXT[0]]
    assert cmd_res.outputs_prefix == "Code42.SecurityAlert"
    assert cmd_res.outputs_key_field == "ID"


def test_departingemployee_add_command(code42_sdk_mock):
    client = create_client(code42_sdk_mock)
    date = "2020-01-01"
    note = "Dummy note"
    cmd_res = departingemployee_add_command(
        client, {"username": _TEST_USERNAME, "departuredate": date, "note": note}
    )
    add_func = code42_sdk_mock.detectionlists.departing_employee.add
    assert cmd_res.raw_response == _TEST_USER_ID
    assert cmd_res.outputs_prefix == "Code42.DepartingEmployee"
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.outputs["DepartureDate"] == date
    assert cmd_res.outputs["Note"] == note
    assert cmd_res.outputs["Username"] == _TEST_USERNAME
    assert cmd_res.outputs["UserID"] == _TEST_USER_ID
    assert cmd_res.outputs["CaseID"] == _TEST_USER_ID
    add_func.assert_called_once_with(_TEST_USER_ID, departure_date=date)
    code42_sdk_mock.detectionlists.update_user_notes.assert_called_once_with(_TEST_USER_ID, note)


def test_departingemployee_remove_command(code42_sdk_mock):
    client = create_client(code42_sdk_mock)
    cmd_res = departingemployee_remove_command(client, {"username": _TEST_USERNAME})
    assert cmd_res.raw_response == _TEST_USER_ID
    assert cmd_res.outputs_prefix == "Code42.DepartingEmployee"
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.outputs["Username"] == _TEST_USERNAME
    assert cmd_res.outputs["UserID"] == _TEST_USER_ID
    assert cmd_res.outputs["CaseID"] == _TEST_USER_ID
    code42_sdk_mock.detectionlists.departing_employee.remove.assert_called_once_with(_TEST_USER_ID)


def test_departingemployee_get_all_command(code42_departing_employee_mock):
    client = create_client(code42_departing_employee_mock)
    cmd_res = departingemployee_get_all_command(client, {})
    expected_raw_response = json.loads(MOCK_GET_ALL_DEPARTING_EMPLOYEES_RESPONSE)["items"]
    assert cmd_res.outputs_prefix == "Code42.DepartingEmployee"
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.raw_response == json.loads(MOCK_GET_ALL_DEPARTING_EMPLOYEES_RESPONSE)["items"]
    # Tests outputs
    assert_departingemployee_outputs_match_response(cmd_res.outputs, expected_raw_response)


def test_departingemployee_get_all_command_gets_employees_from_multiple_pages(
    code42_departing_employee_mock, mocker
):
    # Setup get all departing employees
    page = MOCK_GET_ALL_DEPARTING_EMPLOYEES_RESPONSE
    # Setup 3 pages of employees
    employee_page_generator = (
        create_mock_code42_sdk_response(mocker, page) for page in [page, page, page]
    )
    code42_departing_employee_mock.detectionlists.departing_employee.get_all.return_value = (
        employee_page_generator
    )
    client = create_client(code42_departing_employee_mock)
    cmd_res = departingemployee_get_all_command(client, {})
    assert cmd_res.outputs_prefix == "Code42.DepartingEmployee"
    assert cmd_res.outputs_key_field == "UserID"

    # Expect to have employees from 3 pages in the result
    expected_page = json.loads(MOCK_GET_ALL_DEPARTING_EMPLOYEES_RESPONSE)["items"]
    expected = expected_page + expected_page + expected_page
    assert cmd_res.raw_response == expected
    assert_departingemployee_outputs_match_response(cmd_res.outputs, cmd_res.raw_response)


def test_departingemployee_get_all_command_gets_number_of_employees_equal_to_results_param(
    code42_departing_employee_mock, mocker
):

    # Setup get all departing employees
    page = MOCK_GET_ALL_DEPARTING_EMPLOYEES_RESPONSE
    # Setup 3 pages of employees
    employee_page_generator = (
        create_mock_code42_sdk_response(mocker, page) for page in [page, page, page]
    )
    code42_departing_employee_mock.detectionlists.departing_employee.get_all.return_value = (
        employee_page_generator
    )
    client = create_client(code42_departing_employee_mock)

    cmd_res = departingemployee_get_all_command(client, {"results": 1})
    assert len(cmd_res.raw_response) == 1
    assert len(cmd_res.outputs) == 1


def test_departingemployee_get_all_command_when_no_employees(
    code42_departing_employee_mock, mocker
):
    no_employees_response = get_empty_detectionlist_response(
        mocker, MOCK_GET_ALL_DEPARTING_EMPLOYEES_RESPONSE
    )
    code42_departing_employee_mock.detectionlists.departing_employee.get_all.return_value = (
        no_employees_response
    )
    client = create_client(code42_departing_employee_mock)
    cmd_res = departingemployee_get_all_command(client, {})
    assert cmd_res.outputs_prefix == "Code42.DepartingEmployee"
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.raw_response == {}
    assert cmd_res.outputs == {"Results": []}
    assert code42_departing_employee_mock.detectionlists.departing_employee.get_all.call_count == 1


def test_departingemployee_get_command(code42_departing_employee_get_mock):
    client = create_client(code42_departing_employee_get_mock)
    cmd_res = departingemployee_get_command(
        client, {"username": _TEST_USERNAME}
    )
    get_func = code42_departing_employee_get_mock.detectionlists.departing_employee.get
    get_func.assert_called_once_with(_TEST_USER_ID)
    assert cmd_res.raw_response == _TEST_USERNAME
    assert cmd_res.outputs_prefix == "Code42.DepartingEmployee"
    assert cmd_res.outputs_key_field == "UserID"
    expected = json.loads(MOCK_GET_ALL_DEPARTING_EMPLOYEES_RESPONSE)["items"][0]
    assert_departingemployee_outputs_match_response([cmd_res.outputs], [expected])


def test_highriskemployee_get_command(code42_high_risk_employee_get_mock):
    client = create_client(code42_high_risk_employee_get_mock)
    cmd_res = highriskemployee_get_command(
        client, {"username": _TEST_USERNAME}
    )
    get_func = code42_high_risk_employee_get_mock.detectionlists.high_risk_employee.get
    get_func.assert_called_once_with(_TEST_USER_ID)
    assert cmd_res.raw_response == _TEST_USERNAME
    assert cmd_res.outputs_prefix == "Code42.HighRiskEmployee"
    assert cmd_res.outputs_key_field == "UserID"
    expected = json.loads(MOCK_GET_ALL_HIGH_RISK_EMPLOYEES_RESPONSE)["items"][0]
    assert_detection_list_outputs_match_response_items([cmd_res.outputs], [expected])


def test_highriskemployee_add_command(code42_high_risk_employee_mock):
    client = create_client(code42_high_risk_employee_mock)
    cmd_res = highriskemployee_add_command(
        client, {"username": _TEST_USERNAME, "note": "Dummy note"}
    )
    assert cmd_res.raw_response == _TEST_USER_ID
    assert cmd_res.outputs_prefix == "Code42.HighRiskEmployee"
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.outputs["UserID"] == _TEST_USER_ID
    assert cmd_res.outputs["Username"] == _TEST_USERNAME
    code42_high_risk_employee_mock.detectionlists.high_risk_employee.add.assert_called_once_with(
        _TEST_USER_ID
    )
    code42_high_risk_employee_mock.detectionlists.update_user_notes.assert_called_once_with(
        _TEST_USER_ID, "Dummy note"
    )


def test_highriskemployee_remove_command(code42_sdk_mock):
    client = create_client(code42_sdk_mock)
    cmd_res = highriskemployee_remove_command(client, {"username": _TEST_USERNAME})
    assert cmd_res.raw_response == _TEST_USER_ID
    assert cmd_res.outputs_prefix == "Code42.HighRiskEmployee"
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.outputs["UserID"] == _TEST_USER_ID
    assert cmd_res.outputs["Username"] == _TEST_USERNAME
    code42_sdk_mock.detectionlists.high_risk_employee.remove.assert_called_once_with(_TEST_USER_ID)


def test_highriskemployee_get_all_command(code42_high_risk_employee_mock):
    client = create_client(code42_high_risk_employee_mock)
    cmd_res = highriskemployee_get_all_command(client, {})
    expected_response = json.loads(MOCK_GET_ALL_HIGH_RISK_EMPLOYEES_RESPONSE)["items"]
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.outputs_prefix == "Code42.HighRiskEmployee"
    assert cmd_res.raw_response == expected_response
    assert code42_high_risk_employee_mock.detectionlists.high_risk_employee.get_all.call_count == 1
    assert_detection_list_outputs_match_response_items(cmd_res.outputs, expected_response)


def test_highriskemployee_get_all_command_gets_employees_from_multiple_pages(
    code42_high_risk_employee_mock, mocker
):
    # Setup get all high risk employees
    page = MOCK_GET_ALL_HIGH_RISK_EMPLOYEES_RESPONSE
    # Setup 3 pages of employees
    employee_page_generator = (
        create_mock_code42_sdk_response(mocker, page) for page in [page, page, page]
    )
    code42_high_risk_employee_mock.detectionlists.high_risk_employee.get_all.return_value = (
        employee_page_generator
    )
    client = create_client(code42_high_risk_employee_mock)

    cmd_res = highriskemployee_get_all_command(client, {"username": _TEST_USERNAME})
    expected_response = json.loads(MOCK_GET_ALL_HIGH_RISK_EMPLOYEES_RESPONSE)["items"] * 3
    assert cmd_res.outputs_prefix == "Code42.HighRiskEmployee"
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.raw_response == expected_response
    assert_detection_list_outputs_match_response_items(cmd_res.outputs, expected_response)


def test_highriskemployee_get_all_command_when_given_risk_tags_only_gets_employees_with_tags(
    code42_high_risk_employee_mock
):
    client = create_client(code42_high_risk_employee_mock)
    cmd_res = highriskemployee_get_all_command(
        client,
        {"risktags": "PERFORMANCE_CONCERNS,SUSPICIOUS_SYSTEM_ACTIVITY,POOR_SECURITY_PRACTICES"},
    )
    expected_response = [json.loads(MOCK_GET_ALL_HIGH_RISK_EMPLOYEES_RESPONSE)["items"][0]]
    assert cmd_res.outputs_prefix == "Code42.HighRiskEmployee"
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.raw_response == expected_response
    assert code42_high_risk_employee_mock.detectionlists.high_risk_employee.get_all.call_count == 1
    assert_detection_list_outputs_match_response_items(cmd_res.outputs, expected_response)


def test_highriskemployee_get_all_command_gets_number_of_employees_equal_to_results_param(
    code42_high_risk_employee_mock, mocker
):
    # Setup get all high risk employees
    page = MOCK_GET_ALL_HIGH_RISK_EMPLOYEES_RESPONSE
    # Setup 3 pages of employees
    employee_page_generator = (
        create_mock_code42_sdk_response(mocker, page) for page in [page, page, page]
    )
    code42_high_risk_employee_mock.detectionlists.high_risk_employee.get_all.return_value = (
        employee_page_generator
    )
    client = create_client(code42_high_risk_employee_mock)
    cmd_res = highriskemployee_get_all_command(client, {"results": 1})
    assert len(cmd_res.raw_response) == 1
    assert len(cmd_res.outputs) == 1


def test_highriskemployee_get_all_command_when_no_employees(code42_high_risk_employee_mock, mocker):
    no_employees_response = get_empty_detectionlist_response(
        mocker, MOCK_GET_ALL_HIGH_RISK_EMPLOYEES_RESPONSE
    )
    code42_high_risk_employee_mock.detectionlists.high_risk_employee.get_all.return_value = (
        no_employees_response
    )
    client = create_client(code42_high_risk_employee_mock)
    cmd_res = highriskemployee_get_all_command(
        client,
        {"risktags": "PERFORMANCE_CONCERNS,SUSPICIOUS_SYSTEM_ACTIVITY,POOR_SECURITY_PRACTICES"},
    )
    assert cmd_res.outputs_prefix == "Code42.HighRiskEmployee"
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.outputs == {"Results": []}
    assert cmd_res.raw_response == {}
    assert code42_high_risk_employee_mock.detectionlists.high_risk_employee.get_all.call_count == 1


def test_highriskemployee_add_risk_tags_command(code42_sdk_mock):
    tags = "FLIGHT_RISK"
    client = create_client(code42_sdk_mock)
    cmd_res = highriskemployee_add_risk_tags_command(
        client, {"username": _TEST_USERNAME, "risktags": tags}
    )
    assert cmd_res.raw_response == _TEST_USER_ID
    assert cmd_res.outputs_prefix == "Code42.HighRiskEmployee"
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.outputs["UserID"] == _TEST_USER_ID
    assert cmd_res.outputs["Username"] == _TEST_USERNAME
    assert cmd_res.outputs["RiskTags"] == tags
    code42_sdk_mock.detectionlists.add_user_risk_tags.assert_called_once_with(
        _TEST_USER_ID, [tags]
    )


def test_highriskemployee_remove_risk_tags_command(code42_sdk_mock):
    client = create_client(code42_sdk_mock)
    cmd_res = highriskemployee_remove_risk_tags_command(
        client, {"username": _TEST_USERNAME, "risktags": "FLIGHT_RISK,CONTRACT_EMPLOYEE"}
    )
    assert cmd_res.raw_response == _TEST_USER_ID
    assert cmd_res.outputs_prefix == "Code42.HighRiskEmployee"
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.outputs["UserID"] == _TEST_USER_ID
    assert cmd_res.outputs["Username"] == _TEST_USERNAME
    assert cmd_res.outputs["RiskTags"] == "FLIGHT_RISK,CONTRACT_EMPLOYEE"
    code42_sdk_mock.detectionlists.remove_user_risk_tags.assert_called_once_with(
        _TEST_USER_ID, ["FLIGHT_RISK", "CONTRACT_EMPLOYEE"]
    )


def test_legalhold_add_user_command(code42_legal_hold_mock):
    client = create_client(code42_legal_hold_mock)
    cmd_res = legal_hold_add_user_command(
        client, {"username": _TEST_USERNAME, "mattername": "Patent Lawsuit"}
    )
    assert cmd_res.raw_response == json.loads(MOCK_ADD_TO_MATTER_RESPONSE)
    assert cmd_res.outputs_prefix == "Code42.LegalHold"
    assert cmd_res.outputs_key_field == "MatterID"
    assert cmd_res.outputs["UserID"] == _TEST_USER_ID
    assert cmd_res.outputs["MatterName"] == "Patent Lawsuit"
    assert cmd_res.outputs["MatterID"] == "645576513911664484"
    code42_legal_hold_mock.legalhold.add_to_matter.assert_called_once_with("123412341234123412",
                                                                           "645576513911664484")


def test_legalhold_remove_user_command(code42_legal_hold_mock):
    client = create_client(code42_legal_hold_mock)
    cmd_res = legal_hold_remove_user_command(
        client, {"username": _TEST_USERNAME, "mattername": "Patent Lawsuit"}
    )
    assert cmd_res.outputs_prefix == "Code42.LegalHold"
    assert cmd_res.outputs_key_field == "MatterID"
    assert cmd_res.outputs["UserID"] == _TEST_USER_ID
    assert cmd_res.outputs["MatterName"] == "Patent Lawsuit"
    assert cmd_res.outputs["MatterID"] == "645576513911664484"
    code42_legal_hold_mock.legalhold.remove_from_matter.assert_called_once_with("645579283748927372")


def test_user_create_command(code42_users_mock):
    client = create_client(code42_users_mock)
    cmd_res = user_create_command(
        client,
        {
            "orgname": _TEST_ORG_NAME,
            "username": "new.user@example.com",
            "email": "new.user@example.com",
        },
    )
    assert cmd_res.outputs_prefix == "Code42.User"
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.raw_response == json.loads(MOCK_CREATE_USER_RESPONSE)
    assert cmd_res.outputs["UserID"] == "960849588659999999"
    assert cmd_res.outputs["Username"] == "new.user@example.com"
    assert cmd_res.outputs["Email"] == "new.user@example.com"


def test_user_create_command_when_org_not_found_raises_org_not_found(mocker, code42_users_mock):
    response_json = """{"total": 0, "orgs": []}"""
    code42_users_mock.orgs.get_all.return_value = create_mock_code42_sdk_response_generator(
        mocker, [response_json]
    )
    client = create_client(code42_users_mock)
    with pytest.raises(Code42OrgNotFoundError):
        user_create_command(
            client,
            {
                "orgname": _TEST_ORG_NAME,
                "username": "new.user@example.com",
                "email": "new.user@example.com",
            }
        )


def test_user_block_command(code42_users_mock):
    client = create_client(code42_users_mock)
    cmd_res = user_block_command(client, {"username": "new.user@example.com"})
    assert cmd_res.raw_response == 123456
    assert cmd_res.outputs["UserID"] == 123456
    assert cmd_res.outputs_prefix == "Code42.User"
    code42_users_mock.users.block.assert_called_once_with(123456)


def test_user_unblock_command(code42_users_mock):
    client = create_client(code42_users_mock)
    cmd_res = user_unblock_command(client, {"username": "new.user@example.com"})
    assert cmd_res.raw_response == 123456
    assert cmd_res.outputs["UserID"] == 123456
    assert cmd_res.outputs_prefix == "Code42.User"
    code42_users_mock.users.unblock.assert_called_once_with(123456)


def test_user_deactivate_command(code42_users_mock):
    client = create_client(code42_users_mock)
    cmd_res = user_deactivate_command(client, {"username": "new.user@example.com"})
    assert cmd_res.raw_response == 123456
    assert cmd_res.outputs["UserID"] == 123456
    assert cmd_res.outputs_prefix == "Code42.User"
    code42_users_mock.users.deactivate.assert_called_once_with(123456)


def test_user_reactivate_command(code42_users_mock):
    client = create_client(code42_users_mock)
    cmd_res = user_reactivate_command(client, {"username": "new.user@example.com"})
    assert cmd_res.raw_response == 123456
    assert cmd_res.outputs["UserID"] == 123456
    assert cmd_res.outputs_prefix == "Code42.User"
    code42_users_mock.users.reactivate.assert_called_once_with(123456)


def test_security_data_search_command(code42_file_events_mock):
    client = create_client(code42_file_events_mock)
    cmd_res = securitydata_search_command(client, MOCK_SECURITY_DATA_SEARCH_QUERY)
    code42_res = cmd_res[0]
    file_res = cmd_res[1]

    assert code42_res.outputs_prefix == "Code42.SecurityData"
    assert code42_res.outputs_key_field == "EventID"
    assert file_res.outputs_prefix == "File"

    actual_query = code42_file_events_mock.securitydata.search_file_events.call_args[0][0]
    filter_groups = json.loads(str(actual_query))["groups"]
    expected_query_items = [
        ("md5Checksum", "d41d8cd98f00b204e9800998ecf8427e"),
        ("osHostName", "DESKTOP-0001"),
        ("deviceUserName", "user3@example.com"),
        ("exposure", "ApplicationRead"),
    ]
    expected_file_events = json.loads(MOCK_SECURITY_EVENT_RESPONSE)["fileEvents"]

    # Assert that the  correct query gets made
    assert len(filter_groups) == len(expected_query_items)
    for i in range(0, len(filter_groups)):
        _filter = filter_groups[i]["filters"][0]
        assert _filter["term"] == expected_query_items[i][0]
        assert _filter["value"] == expected_query_items[i][1]

    assert len(code42_res.raw_response) == len(code42_res.outputs) == 3
    assert code42_res.raw_response == expected_file_events

    # Assert that the Outputs are mapped from the file events.
    for i in range(0, len(expected_file_events)):
        mapped_event = map_to_code42_event_context(expected_file_events[i])
        output_item = code42_res.outputs[i]
        assert output_item == mapped_event


def test_securitydata_search_command_when_not_given_any_queryable_args_raises_error(code42_file_events_mock):
    client = create_client(code42_file_events_mock)
    with pytest.raises(Code42MissingSearchArgumentsError):
        securitydata_search_command(client, {})


def test_download_file_command_when_given_md5(code42_sdk_mock, mocker):
    fr = mocker.patch("Code42.fileResult")
    client = create_client(code42_sdk_mock)
    _ = download_file_command(client, {"hash": "b6312dbe4aa4212da94523ccb28c5c16"})
    code42_sdk_mock.securitydata.stream_file_by_md5.assert_called_once_with(
        "b6312dbe4aa4212da94523ccb28c5c16"
    )
    assert fr.call_count == 1


def test_download_file_command_when_given_sha256(code42_sdk_mock, mocker):
    fr = mocker.patch("Code42.fileResult")
    _hash = "41966f10cc59ab466444add08974fde4cd37f88d79321d42da8e4c79b51c2149"
    client = create_client(code42_sdk_mock)
    _ = download_file_command(client, {"hash": _hash})
    code42_sdk_mock.securitydata.stream_file_by_sha256.assert_called_once_with(_hash)
    assert fr.call_count == 1


def test_download_file_when_given_other_hash_raises_unsupported_hash(code42_sdk_mock, mocker):
    mocker.patch("Code42.fileResult")
    _hash = "41966f10cc59ab466444add08974fde4cd37f88d79321d42da8e4c79b51c214941966f10cc59ab466444add08974fde4cd37" \
            "f88d79321d42da8e4c79b51c2149"
    client = create_client(code42_sdk_mock)
    with pytest.raises(Code42UnsupportedHashError):
        _ = download_file_command(client, {"hash": _hash})


def test_fetch_when_no_significant_file_categories_ignores_filter(
    code42_fetch_incidents_mock, mocker
):
    response_text = MOCK_ALERT_DETAILS_RESPONSE.replace(
        '"isSignificant": true', '"isSignificant": false'
    )
    alert_details_response = create_mock_code42_sdk_response(mocker, response_text)
    code42_fetch_incidents_mock.alerts.get_details.return_value = alert_details_response
    client = create_client(code42_fetch_incidents_mock)
    _, _, _ = fetch_incidents(
        client=client,
        last_run={"last_fetch": None},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=None,
        fetch_limit=10,
        include_files=True,
        integration_context=None,
    )
    actual_query = str(code42_fetch_incidents_mock.securitydata.search_file_events.call_args[0][0])
    assert "fileCategory" not in actual_query
    assert "IMAGE" not in actual_query


def test_fetch_incidents_handles_single_severity(code42_fetch_incidents_mock):
    client = create_client(code42_fetch_incidents_mock)
    fetch_incidents(
        client=client,
        last_run={"last_fetch": None},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter="High",
        fetch_limit=10,
        include_files=True,
        integration_context=None,
    )
    assert "HIGH" in str(code42_fetch_incidents_mock.alerts.search.call_args[0][0])


def test_fetch_incidents_handles_multi_severity(code42_fetch_incidents_mock):
    client = create_client(code42_fetch_incidents_mock)
    fetch_incidents(
        client=client,
        last_run={"last_fetch": None},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=["High", "Low"],
        fetch_limit=10,
        include_files=True,
        integration_context=None,
    )
    call_args = str(code42_fetch_incidents_mock.alerts.search.call_args[0][0])
    assert Severity.HIGH in call_args
    assert Severity.LOW in call_args


def test_fetch_when_include_files_includes_files(code42_fetch_incidents_mock):
    client = create_client(code42_fetch_incidents_mock)
    _, incidents, _ = fetch_incidents(
        client=client,
        last_run={"last_fetch": None},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=["High", "Low"],
        fetch_limit=10,
        include_files=True,
        integration_context=None,
    )
    for i in incidents:
        _json = json.loads(i["rawJSON"])
        assert len(_json["fileevents"])


def test_fetch_when_not_include_files_excludes_files(code42_fetch_incidents_mock):
    client = create_client(code42_fetch_incidents_mock)
    _, incidents, _ = fetch_incidents(
        client=client,
        last_run={"last_fetch": None},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=["High", "Low"],
        fetch_limit=10,
        include_files=False,
        integration_context=None,
    )
    for i in incidents:
        _json = json.loads(i["rawJSON"])
        assert not _json.get("fileevents")


def test_fetch_incidents_first_run(code42_fetch_incidents_mock):
    client = create_client(code42_fetch_incidents_mock)
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": None},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=None,
        fetch_limit=10,
        include_files=True,
        integration_context=None,
    )
    assert len(incidents) == 3
    assert next_run["last_fetch"]


def test_fetch_incidents_next_run(code42_fetch_incidents_mock):
    mock_date = "2020-01-01T00:00:00.000Z"
    mock_timestamp = int(time.mktime(time.strptime(mock_date, "%Y-%m-%dT%H:%M:%S.000Z")))
    client = create_client(code42_fetch_incidents_mock)
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": mock_timestamp},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=None,
        fetch_limit=10,
        include_files=True,
        integration_context=None,
    )
    assert len(incidents) == 3
    assert next_run["last_fetch"]


def test_fetch_incidents_fetch_limit(code42_fetch_incidents_mock):
    mock_date = "2020-01-01T00:00:00.000Z"
    mock_timestamp = int(time.mktime(time.strptime(mock_date, "%Y-%m-%dT%H:%M:%S.000Z")))
    client = create_client(code42_fetch_incidents_mock)
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": mock_timestamp},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=None,
        fetch_limit=2,
        include_files=True,
        integration_context=None,
    )
    assert len(incidents) == 2
    assert next_run["last_fetch"]
    assert len(remaining_incidents) == 1
    # Run again to get the last incident
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": mock_timestamp},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=None,
        fetch_limit=2,
        include_files=True,
        integration_context={"remaining_incidents": remaining_incidents},
    )
    assert len(incidents) == 1
    assert next_run["last_fetch"]
    assert not remaining_incidents


@pytest.mark.parametrize(
    "query",
    [MOCK_SECURITY_DATA_SEARCH_QUERY_EXPOSURE_TYPE_ALL,
     MOCK_SECURITY_DATA_SEARCH_QUERY_EXPOSURE_TYPE_ALL_WITH_OTHERS
     ]
)
def test_security_data_search_command_searches_exposure_exists_when_all_is_specified(
        code42_file_events_mock, query
):
    client = create_client(code42_file_events_mock)
    cmd_res = securitydata_search_command(client, query)
    code42_res = cmd_res[0]
    file_res = cmd_res[1]

    assert code42_res.outputs_prefix == "Code42.SecurityData"
    assert code42_res.outputs_key_field == "EventID"
    assert file_res.outputs_prefix == "File"

    actual_query = code42_file_events_mock.securitydata.search_file_events.call_args[0][0]

    # Assert that the  correct query gets made
    filter_groups = json.loads(str(actual_query))["groups"]
    expected_query_items = [
        ("md5Checksum", "d41d8cd98f00b204e9800998ecf8427e"),
        ("osHostName", "DESKTOP-0001"),
        ("deviceUserName", "user3@example.com"),
        ("exposure", None),
    ]

    # Assert that the  correct query gets made
    assert len(filter_groups) == len(expected_query_items)
    for i in range(0, len(filter_groups)):
        _filter = filter_groups[i]["filters"][0]
        assert _filter["term"] == expected_query_items[i][0]
        assert _filter["value"] == expected_query_items[i][1]

    assert len(filter_groups) == 4


def test_security_data_search_command_searches_exposure_exists_when_no_exposure_type_is_specified(
        code42_file_events_mock,
):
    client = create_client(code42_file_events_mock)
    cmd_res = securitydata_search_command(client, MOCK_SECURITY_DATA_SEARCH_QUERY_WITHOUT_EXPOSURE_TYPE)
    code42_res = cmd_res[0]
    file_res = cmd_res[1]

    assert code42_res.outputs_prefix == "Code42.SecurityData"
    assert code42_res.outputs_key_field == "EventID"
    assert file_res.outputs_prefix == "File"

    actual_query = code42_file_events_mock.securitydata.search_file_events.call_args[0][0]

    # Assert that the  correct query gets made
    filter_groups = json.loads(str(actual_query))["groups"]
    expected_query_items = [
        ("md5Checksum", "d41d8cd98f00b204e9800998ecf8427e"),
        ("osHostName", "DESKTOP-0001"),
        ("deviceUserName", "user3@example.com"),
    ]

    # Assert that the  correct query gets made
    assert len(filter_groups) == len(expected_query_items)
    for i in range(0, len(filter_groups)):
        _filter = filter_groups[i]["filters"][0]
        assert _filter["term"] == expected_query_items[i][0]
        assert _filter["value"] == expected_query_items[i][1]

    assert len(filter_groups) == 3
