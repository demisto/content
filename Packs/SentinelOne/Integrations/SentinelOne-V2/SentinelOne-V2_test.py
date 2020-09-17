import demistomock as demisto
from importlib import import_module


sentinelone_v2 = import_module('SentinelOne-V2')
fetch_incidents = sentinelone_v2.fetch_incidents
main = sentinelone_v2.main

# disable-secrets-detection-start
INCIDENTS_FOR_FETCH = [
    {
        "CustomFields": None,
        "ShardID": 0,
        "account": "",
        "activated": "0001-01-01T00:00:00Z",
        "attachment": None,
        "autime": 0,
        "canvases": None,
        "category": "",
        "closeNotes": "",
        "closeReason": "",
        "closed": "0001-01-01T00:00:00Z",
        "closingUserId": "",
        "created": "0001-01-01T00:00:00Z",
        "details": "",
        "droppedCount": 0,
        "dueDate": "0001-01-01T00:00:00Z",
        "hasRole": False,
        "id": "",
        "investigationId": "",
        "isPlayground": False,
        "labels": None,
        "lastOpen": "0001-01-01T00:00:00Z",
        "linkedCount": 0,
        "linkedIncidents": None,
        "modified": "0001-01-01T00:00:00Z",
        "name": "Sentinel One Threat: Malware",
        "notifyTime": "0001-01-01T00:00:00Z",
        "occurred": "2019-09-15T14:25:48.988Z",
        "openDuration": 0,
        "owner": "",
        "parent": "",
        "phase": "",
        "playbookId": "",
        "previousRoles": None,
        "rawCategory": "",
        "rawCloseReason": "",
        "rawJSON": "{\"accountId\": \"412243337337583618\", \"accountName\": \"SentinelOne\", \"agentComputerName\": "
                   "\"EC2AMAZ-AJ0KDDD\", \"agentDomain\": \"WORKGROUP\", \"agentId\": \"657613730168123596\", "
                   "\"agentInfected\": False, \"agentIp\": \"3.136.231.41\", \"agentIsActive\": True, "
                   "\"agentIsDecommissioned\": False, \"agentMachineType\": \"server\", \"agentNetworkStatus\": "
                   "\"disconnected\", \"agentOsType\": \"windows\", \"agentVersion\": \"3.2.3.37\", \"annotation\": "
                   "None, \"annotationUrl\": None, \"browserType\": None, \"certId\": \"\", \"classification\": "
                   "\"Malware\", \"classificationSource\": \"Static\", \"classifierName\": \"STATIC\", "
                   "\"cloudVerdict\": \"provider_unknown\", \"collectionId\": \"715789430041423412\", \"createdAt\": "
                   "\"2019-09-15T14:25:49.944443Z\", \"createdDate\": \"2019-09-15T14:25:48.988000Z\", "
                   "\"description\": \"malware detected - not mitigated yet (static engine)\", \"engines\": ["
                   "\"pre_execution\"], \"fileContentHash\": \"3e7704f5668bc4330c686ccce2dd6f99696863bd\", "
                   "\"fileCreatedDate\": None, \"fileDisplayName\": \"Ncat Netcat Portable - CHIP-Installer.exe\", "
                   "\"fileExtensionType\": \"Executable\", \"fileIsDotNet\": None, \"fileIsExecutable\": False, "
                   "\"fileIsSystem\": False, \"fileMaliciousContent\": None, \"fileObjectId\": \"43A5D890AC420DKC\", "
                   "\"filePath\": \"\\\\Device\\\\HarddiskVolume1\\\\Users\\\\Administrator\\\\Downloads\\\\Ncat "
                   "Netcat Portable - CHIP-Installer.exe\", \"fileSha256\": None, \"fileVerificationType\": "
                   "\"PathNotFound\", \"fromCloud\": False, \"fromScan\": False, \"id\": \"715789434420276799\", "
                   "\"indicators\": [25, 24, 23, 6], \"isCertValid\": False, \"isInteractiveSession\": False, "
                   "\"isPartialStory\": False, \"maliciousGroupId\": \"B9343BEED7D7713C\", "
                   "\"maliciousProcessArguments\": None, \"markedAsBenign\": None, \"mitigationMode\": \"protect\", "
                   "\"mitigationReport\": {\"kill\": {\"status\": \"success\"}, \"network_quarantine\": {\"status\": "
                   "None}, \"quarantine\": {\"status\": \"success\"}, \"remediate\": {\"status\": None}, "
                   "\"rollback\": {\"status\": None}}, \"mitigationStatus\": \"mitigated\", \"publisher\": \"\", "
                   "\"rank\": 0, \"resolved\": False, \"siteId\": \"475482421366727777\", \"siteName\": \"demisto\", "
                   "\"threatAgentVersion\": \"3.2.3.37\", \"threatName\": \"Ncat Netcat Portable - "
                   "CHIP-Installer.exe\", \"updatedAt\": \"2019-09-15T14:25:50.181148Z\", \"username\": \"\", "
                   "\"whiteningOptions\": [\"hash\", \"path\"]}",
        "rawName": "",
        "rawPhase": "",
        "rawType": "",
        "reason": "",
        "reminder": "0001-01-01T00:00:00Z",
        "roles": None,
        "runStatus": "",
        "severity": 0,
        "sla": 0,
        "sortValues": None,
        "sourceBrand": "",
        "sourceInstance": "",
        "status": 0,
        "type": "",
        "version": 0
    },
    {
        "CustomFields": None,
        "ShardID": 0,
        "account": "",
        "activated": "0001-01-01T00:00:00Z",
        "attachment": None,
        "autime": 0,
        "canvases": None,
        "category": "",
        "closeNotes": "",
        "closeReason": "",
        "closed": "0001-01-01T00:00:00Z",
        "closingUserId": "",
        "created": "0001-01-01T00:00:00Z",
        "details": "",
        "droppedCount": 0,
        "dueDate": "0001-01-01T00:00:00Z",
        "hasRole": False,
        "id": "",
        "investigationId": "",
        "isPlayground": False,
        "labels": None,
        "lastOpen": "0001-01-01T00:00:00Z",
        "linkedCount": 0,
        "linkedIncidents": None,
        "modified": "0001-01-01T00:00:00Z",
        "name": "Sentinel One Threat: Malware",
        "notifyTime": "0001-01-01T00:00:00Z",
        "occurred": "2019-09-16T09:36:02.331Z",
        "openDuration": 0,
        "owner": "",
        "parent": "",
        "phase": "",
        "playbookId": "",
        "previousRoles": None,
        "rawCategory": "",
        "rawCloseReason": "",
        "rawJSON": "{\"accountId\": \"412243337337583618\", \"accountName\": \"SentinelOne\", \"agentComputerName\": "
                   "\"EC2AMAZ-AJ0KDDD\", \"agentDomain\": \"WORKGROUP\", \"agentId\": \"657613730168123596\", "
                   "\"agentInfected\": False, \"agentIp\": \"3.136.231.41\", \"agentIsActive\": True, "
                   "\"agentIsDecommissioned\": False, \"agentMachineType\": \"server\", \"agentNetworkStatus\": "
                   "\"disconnected\", \"agentOsType\": \"windows\", \"agentVersion\": \"3.2.3.37\", \"annotation\": "
                   "None, \"annotationUrl\": None, \"browserType\": None, \"certId\": \"\", \"classification\": "
                   "\"Malware\", \"classificationSource\": \"Engine\", \"classifierName\": \"STATIC\", "
                   "\"cloudVerdict\": \"black\", \"collectionId\": \"433377888883088367\", \"createdAt\": "
                   "\"2019-09-16T09:36:02.411027Z\", \"createdDate\": \"2019-09-16T09:36:02.331000Z\", "
                   "\"description\": \"malware detected - not mitigated yet (static engine)\", \"engines\": ["
                   "\"reputation\"], \"fileContentHash\": \"3395856ce81f2b7382dee72602f798b642f14444\", "
                   "\"fileCreatedDate\": None, \"fileDisplayName\": \"Unconfirmed 742374.crdownload\", "
                   "\"fileExtensionType\": \"Unknown\", \"fileIsDotNet\": None, \"fileIsExecutable\": False, "
                   "\"fileIsSystem\": False, \"fileMaliciousContent\": None, \"fileObjectId\": \"A19CF2DDC726C111\", "
                   "\"filePath\": \"\\\\Device\\\\HarddiskVolume1\\\\Users\\\\Administrator\\\\Downloads"
                   "\\\\Unconfirmed 742374.crdownload\", \"fileSha256\": None, \"fileVerificationType\": "
                   "\"NotSigned\", \"fromCloud\": False, \"fromScan\": False, \"id\": \"716368352944665999\", "
                   "\"indicators\": [], \"isCertValid\": False, \"isInteractiveSession\": False, \"isPartialStory\": "
                   "False, \"maliciousGroupId\": \"FAF42748C2B39DDD\", \"maliciousProcessArguments\": None, "
                   "\"markedAsBenign\": None, \"mitigationMode\": \"protect\", \"mitigationReport\": {\"kill\": {"
                   "\"status\": \"success\"}, \"network_quarantine\": {\"status\": None}, \"quarantine\": {"
                   "\"status\": \"success\"}, \"remediate\": {\"status\": None}, \"rollback\": {\"status\": None}}, "
                   "\"mitigationStatus\": \"mitigated\", \"publisher\": \"\", \"rank\": 7, \"resolved\": False, "
                   "\"siteId\": \"475482421366727777\", \"siteName\": \"demisto\", \"threatAgentVersion\": "
                   "\"3.2.3.37\", \"threatName\": \"Unconfirmed 742374.crdownload\", \"updatedAt\": "
                   "\"2019-09-16T09:36:02.636239Z\", \"username\": \"EC2AMAZ-AJ0KDDD\\\\Administrator\", "
                   "\"whiteningOptions\": [\"hash\"]}",
        "rawName": "",
        "rawPhase": "",
        "rawType": "",
        "reason": "",
        "reminder": "0001-01-01T00:00:00Z",
        "roles": None,
        "runStatus": "",
        "severity": 0,
        "sla": 0,
        "sortValues": None,
        "sourceBrand": "",
        "sourceInstance": "",
        "status": 0,
        "type": "",
        "version": 0
    },
    {
        "CustomFields": None,
        "ShardID": 0,
        "account": "",
        "activated": "0001-01-01T00:00:00Z",
        "attachment": None,
        "autime": 0,
        "canvases": None,
        "category": "",
        "closeNotes": "",
        "closeReason": "",
        "closed": "0001-01-01T00:00:00Z",
        "closingUserId": "",
        "created": "0001-01-01T00:00:00Z",
        "details": "",
        "droppedCount": 0,
        "dueDate": "0001-01-01T00:00:00Z",
        "hasRole": False,
        "id": "",
        "investigationId": "",
        "isPlayground": False,
        "labels": None,
        "lastOpen": "0001-01-01T00:00:00Z",
        "linkedCount": 0,
        "linkedIncidents": None,
        "modified": "0001-01-01T00:00:00Z",
        "name": "Sentinel One Threat: Malware",
        "notifyTime": "0001-01-01T00:00:00Z",
        "occurred": "2019-10-14T19:44:24.647Z",
        "openDuration": 0,
        "owner": "",
        "parent": "",
        "phase": "",
        "playbookId": "",
        "previousRoles": None,
        "rawCategory": "",
        "rawCloseReason": "",
        "rawJSON": "{\"accountId\": \"412243337337583618\", \"accountName\": \"SentinelOne\", \"agentComputerName\": "
                   "\"TLVWIN9131VVV\", \"agentDomain\": \"PALOALTONETWORK\", \"agentId\": \"657738871640371666\", "
                   "\"agentInfected\": False, \"agentIp\": \"77.125.26.100\", \"agentIsActive\": True, "
                   "\"agentIsDecommissioned\": False, \"agentMachineType\": \"laptop\", \"agentNetworkStatus\": "
                   "\"connected\", \"agentOsType\": \"windows\", \"agentVersion\": \"3.2.3.37\", \"annotation\": "
                   "None, \"annotationUrl\": None, \"browserType\": None, \"certId\": \"\", \"classification\": "
                   "\"Malware\", \"classificationSource\": \"Static\", \"classifierName\": \"LOGIC\", "
                   "\"cloudVerdict\": None, \"collectionId\": \"736969199281920555\", \"createdAt\": "
                   "\"2019-10-14T19:46:14.666494Z\", \"createdDate\": \"2019-10-14T19:44:24.647000Z\", "
                   "\"description\": \"malware detected - not mitigated yet\", \"engines\": [\"data_files\"], "
                   "\"fileContentHash\": \"ffffffffffffffffffffffffffffffffffffffff\", \"fileCreatedDate\": None, "
                   "\"fileDisplayName\": \"19.152.0801.0008\", \"fileExtensionType\": \"Unknown\", \"fileIsDotNet\": "
                   "None, \"fileIsExecutable\": False, \"fileIsSystem\": False, \"fileMaliciousContent\": None, "
                   "\"fileObjectId\": \"DC1471176A586CAA\", \"filePath\": "
                   "\"\\\\Device\\\\HarddiskVolume4\\\\Users\\\\ooooooooo\\\\AppData\\\\Local\\\\Microsoft"
                   "\\\\OneDrive\\\\19.152.0801.0008\", \"fileSha256\": None, \"fileVerificationType\": "
                   "\"NotSigned\", \"fromCloud\": False, \"fromScan\": False, \"id\": \"736969199273531999\", "
                   "\"indicators\": [83], \"isCertValid\": False, \"isInteractiveSession\": False, "
                   "\"isPartialStory\": False, \"maliciousGroupId\": \"CA1BD9CFD7148222\", "
                   "\"maliciousProcessArguments\": \"/q /c rmdir /s /q "
                   "\\\"C:\\\\Users\\\\ooooooooo\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\19.152.0801.0008"
                   "\\\"\", \"markedAsBenign\": None, \"mitigationMode\": \"protect\", \"mitigationReport\": {"
                   "\"kill\": {\"status\": \"success\"}, \"network_quarantine\": {\"status\": None}, \"quarantine\": "
                   "{\"status\": \"success\"}, \"remediate\": {\"status\": None}, \"rollback\": {\"status\": None}}, "
                   "\"mitigationStatus\": \"mitigated\", \"publisher\": \"\", \"rank\": None, \"resolved\": False, "
                   "\"siteId\": \"475482421366727777\", \"siteName\": \"demisto\", \"threatAgentVersion\": "
                   "\"3.2.3.37\", \"threatName\": \"19.152.0801.0008\", \"updatedAt\": "
                   "\"2019-10-14T19:46:15.271542Z\", \"username\": \"PALOALTONETWORK\\\\ooooooooo\", "
                   "\"whiteningOptions\": [\"file_type\", \"path\"]}",
        "rawName": "",
        "rawPhase": "",
        "rawType": "",
        "reason": "",
        "reminder": "0001-01-01T00:00:00Z",
        "roles": None,
        "runStatus": "",
        "severity": 0,
        "sla": 0,
        "sortValues": None,
        "sourceBrand": "",
        "sourceInstance": "",
        "status": 0,
        "type": "",
        "version": 0
    },
    {
        "CustomFields": None,
        "ShardID": 0,
        "account": "",
        "activated": "0001-01-01T00:00:00Z",
        "attachment": None,
        "autime": 0,
        "canvases": None,
        "category": "",
        "closeNotes": "",
        "closeReason": "",
        "closed": "0001-01-01T00:00:00Z",
        "closingUserId": "",
        "created": "0001-01-01T00:00:00Z",
        "details": "",
        "droppedCount": 0,
        "dueDate": "0001-01-01T00:00:00Z",
        "hasRole": False,
        "id": "",
        "investigationId": "",
        "isPlayground": False,
        "labels": None,
        "lastOpen": "0001-01-01T00:00:00Z",
        "linkedCount": 0,
        "linkedIncidents": None,
        "modified": "0001-01-01T00:00:00Z",
        "name": "Sentinel One Threat: Malware",
        "notifyTime": "0001-01-01T00:00:00Z",
        "occurred": "2020-06-13T22:59:02Z",
        "openDuration": 0,
        "owner": "",
        "parent": "",
        "phase": "",
        "playbookId": "",
        "previousRoles": None,
        "rawCategory": "",
        "rawCloseReason": "",
        "rawJSON": "{\"accountId\": \"412243337337583618\", \"accountName\": \"SentinelOne\", \"agentComputerName\": "
                   "\"TLVWIN9131VVV\", \"agentDomain\": \"PALOALTONETWORK\", \"agentId\": \"657738871640371666\", "
                   "\"agentInfected\": False, \"agentIp\": \"77.125.26.100\", \"agentIsActive\": True, "
                   "\"agentIsDecommissioned\": False, \"agentMachineType\": \"laptop\", \"agentNetworkStatus\": "
                   "\"connected\", \"agentOsType\": \"windows\", \"agentVersion\": \"3.2.3.37\", \"annotation\": "
                   "None, \"annotationUrl\": None, \"browserType\": None, \"certId\": \"\", \"classification\": "
                   "\"Malware\", \"classificationSource\": \"Static\", \"classifierName\": \"LOGIC\", "
                   "\"cloudVerdict\": None, \"collectionId\": \"736969199281920555\", \"createdAt\": "
                   "\"2019-10-14T19:46:14.666494Z\", \"createdDate\": \"2019-10-14T19:44:24.647000Z\", "
                   "\"description\": \"malware detected - not mitigated yet\", \"engines\": [\"data_files\"], "
                   "\"fileContentHash\": \"ffffffffffffffffffffffffffffffffffffffff\", \"fileCreatedDate\": None, "
                   "\"fileDisplayName\": \"19.152.0801.0008\", \"fileExtensionType\": \"Unknown\", \"fileIsDotNet\": "
                   "None, \"fileIsExecutable\": False, \"fileIsSystem\": False, \"fileMaliciousContent\": None, "
                   "\"fileObjectId\": \"DC1471176A586CAA\", \"filePath\": "
                   "\"\\\\Device\\\\HarddiskVolume4\\\\Users\\\\ooooooooo\\\\AppData\\\\Local\\\\Microsoft"
                   "\\\\OneDrive\\\\19.152.0801.0008\", \"fileSha256\": None, \"fileVerificationType\": "
                   "\"NotSigned\", \"fromCloud\": False, \"fromScan\": False, \"id\": \"736969199273531999\", "
                   "\"indicators\": [83], \"isCertValid\": False, \"isInteractiveSession\": False, "
                   "\"isPartialStory\": False, \"maliciousGroupId\": \"CA1BD9CFD7148222\", "
                   "\"maliciousProcessArguments\": \"/q /c rmdir /s /q "
                   "\\\"C:\\\\Users\\\\ooooooooo\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\19.152.0801.0008"
                   "\\\"\", \"markedAsBenign\": None, \"mitigationMode\": \"protect\", \"mitigationReport\": {"
                   "\"kill\": {\"status\": \"success\"}, \"network_quarantine\": {\"status\": None}, \"quarantine\": "
                   "{\"status\": \"success\"}, \"remediate\": {\"status\": None}, \"rollback\": {\"status\": None}}, "
                   "\"mitigationStatus\": \"mitigated\", \"publisher\": \"\", \"rank\": None, \"resolved\": False, "
                   "\"siteId\": \"475482421366727777\", \"siteName\": \"demisto\", \"threatAgentVersion\": "
                   "\"3.2.3.37\", \"threatName\": \"19.152.0801.0008\", \"updatedAt\": "
                   "\"2019-10-14T19:46:15.271542Z\", \"username\": \"PALOALTONETWORK\\\\ooooooooo\", "
                   "\"whiteningOptions\": [\"file_type\", \"path\"]}",
        "rawName": "",
        "rawPhase": "",
        "rawType": "",
        "reason": "",
        "reminder": "0001-01-01T00:00:00Z",
        "roles": None,
        "runStatus": "",
        "severity": 0,
        "sla": 0,
        "sortValues": None,
        "sourceBrand": "",
        "sourceInstance": "",
        "status": 0,
        "type": "",
        "version": 0
    }
]

RAW_THREATS_RESPONSE = {
    "data": [
        {
            "accountId": "412243337337583618",
            "accountName": "SentinelOne",
            "agentComputerName": "TLVWIN9131VVV",
            "agentDomain": "PALOALTONETWORK",
            "agentId": "657738871640371666",
            "agentInfected": False,
            "agentIp": "77.125.26.100",
            "agentIsActive": True,
            "agentIsDecommissioned": False,
            "agentMachineType": "laptop",
            "agentNetworkStatus": "connected",
            "agentOsType": "windows",
            "agentVersion": "3.2.3.37",
            "annotation": None,
            "annotationUrl": None,
            "browserType": None,
            "certId": "",
            "classification": "Malware",
            "classificationSource": "Static",
            "classifierName": "LOGIC",
            "cloudVerdict": None,
            "collectionId": "736969199281920555",
            "createdAt": "2019-10-14T19:46:14.666494Z",
            "createdDate": "2019-10-14T19:44:24.647000Z",
            "description": "malware detected - not mitigated yet",
            "engines": ["data_files"],
            "fileContentHash": "ffffffffffffffffffffffffffffffffffffffff",
            "fileCreatedDate": None,
            "fileDisplayName": "19.152.0801.0008",
            "fileExtensionType": "Unknown",
            "fileIsDotNet": None,
            "fileIsExecutable": False,
            "fileIsSystem": False,
            "fileMaliciousContent": None,
            "fileObjectId": "DC1471176A586CAA",
            "filePath": "\\Device\\HarddiskVolume4\\Users\\ooooooooo\\AppData\\Local\\Microsoft\\OneDrive\\19.152.0801"
                        ".0008",
            "fileSha256": None,
            "fileVerificationType": "NotSigned",
            "fromCloud": False,
            "fromScan": False,
            "id": "736969199273531999",
            "indicators": [83],
            "isCertValid": False,
            "isInteractiveSession": False,
            "isPartialStory": False,
            "maliciousGroupId": "CA1BD9CFD7148222",
            "maliciousProcessArguments": "/q /c rmdir /s /q \"C:\\Users\\ooooooooo\\AppData\\Local\\Microsoft\\OneDrive"
                                         "\\19.152.0801.0008\"",
            "markedAsBenign": None,
            "mitigationMode": "protect",
            "mitigationReport": {
                "kill": {
                    "status": "success"
                },
                "network_quarantine": {
                    "status": None
                },
                "quarantine": {
                    "status": "success"
                },
                "remediate": {
                    "status": None
                },
                "rollback": {
                    "status": None
                }
            },
            "mitigationStatus": "mitigated",
            "publisher": "",
            "rank": None,
            "resolved": False,
            "siteId": "475482421366727777",
            "siteName": "demisto",
            "threatAgentVersion": "3.2.3.37",
            "threatName": "19.152.0801.0008",
            "updatedAt": "2019-10-14T19:46:15.271542Z",
            "username": "PALOALTONETWORK\\ooooooooo",
            "whiteningOptions": ["file_type", "path"]
        },
        {
            "accountId": "412243337337583618",
            "accountName": "SentinelOne",
            "agentComputerName": "EC2AMAZ-AJ0KDDD",
            "agentDomain": "WORKGROUP",
            "agentId": "657613730168123596",
            "agentInfected": False,
            "agentIp": "3.136.231.41",
            "agentIsActive": True,
            "agentIsDecommissioned": False,
            "agentMachineType": "server",
            "agentNetworkStatus": "disconnected",
            "agentOsType": "windows",
            "agentVersion": "3.2.3.37",
            "annotation": None,
            "annotationUrl": None,
            "browserType": None,
            "certId": "",
            "classification": "Malware",
            "classificationSource": "Engine",
            "classifierName": "STATIC",
            "cloudVerdict": "black",
            "collectionId": "433377888883088367",
            "createdAt": "2019-09-16T09:36:02.411027Z",
            "createdDate": "2019-09-16T09:36:02.331000Z",
            "description": "malware detected - not mitigated yet (static engine)",
            "engines": ["reputation"],
            "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14444",
            "fileCreatedDate": None,
            "fileDisplayName": "Unconfirmed 742374.crdownload",
            "fileExtensionType": "Unknown",
            "fileIsDotNet": None,
            "fileIsExecutable": False,
            "fileIsSystem": False,
            "fileMaliciousContent": None,
            "fileObjectId": "A19CF2DDC726C111",
            "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 742374.crdownload",
            "fileSha256": None,
            "fileVerificationType": "NotSigned",
            "fromCloud": False,
            "fromScan": False,
            "id": "716368352944665999",
            "indicators": [],
            "isCertValid": False,
            "isInteractiveSession": False,
            "isPartialStory": False,
            "maliciousGroupId": "FAF42748C2B39DDD",
            "maliciousProcessArguments": None,
            "markedAsBenign": None,
            "mitigationMode": "protect",
            "mitigationReport": {
                "kill": {
                    "status": "success"
                },
                "network_quarantine": {
                    "status": None
                },
                "quarantine": {
                    "status": "success"
                },
                "remediate": {
                    "status": None
                },
                "rollback": {
                    "status": None
                }
            },
            "mitigationStatus": "mitigated",
            "publisher": "",
            "rank": 7,
            "resolved": False,
            "siteId": "475482421366727777",
            "siteName": "demisto",
            "threatAgentVersion": "3.2.3.37",
            "threatName": "Unconfirmed 742374.crdownload",
            "updatedAt": "2019-09-16T09:36:02.636239Z",
            "username": "EC2AMAZ-AJ0KDDD\\Administrator",
            "whiteningOptions": ["hash"]
        },
        {
            "accountId": "412243337337583618",
            "accountName": "SentinelOne",
            "agentComputerName": "EC2AMAZ-AJ0KDDD",
            "agentDomain": "WORKGROUP",
            "agentId": "657613730168123596",
            "agentInfected": False,
            "agentIp": "3.136.231.41",
            "agentIsActive": True,
            "agentIsDecommissioned": False,
            "agentMachineType": "server",
            "agentNetworkStatus": "disconnected",
            "agentOsType": "windows",
            "agentVersion": "3.2.3.37",
            "annotation": None,
            "annotationUrl": None,
            "browserType": None,
            "certId": "",
            "classification": "Malware",
            "classificationSource": "Static",
            "classifierName": "STATIC",
            "cloudVerdict": "provider_unknown",
            "collectionId": "715789430041423412",
            "createdAt": "2019-09-15T14:25:49.944443Z",
            "createdDate": "2019-09-15T14:25:48.988000Z",
            "description": "malware detected - not mitigated yet (static engine)",
            "engines": ["pre_execution"],
            "fileContentHash": "3e7704f5668bc4330c686ccce2dd6f99696863bd",
            "fileCreatedDate": None,
            "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
            "fileExtensionType": "Executable",
            "fileIsDotNet": None,
            "fileIsExecutable": False,
            "fileIsSystem": False,
            "fileMaliciousContent": None,
            "fileObjectId": "43A5D890AC420DKC",
            "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - "
                        "CHIP-Installer.exe",
            "fileSha256": None,
            "fileVerificationType": "PathNotFound",
            "fromCloud": False,
            "fromScan": False,
            "id": "715789434420276799",
            "indicators": [25, 24, 23, 6],
            "isCertValid": False,
            "isInteractiveSession": False,
            "isPartialStory": False,
            "maliciousGroupId": "B9343BEED7D7713C",
            "maliciousProcessArguments": None,
            "markedAsBenign": None,
            "mitigationMode": "protect",
            "mitigationReport": {
                "kill": {
                    "status": "success"
                },
                "network_quarantine": {
                    "status": None
                },
                "quarantine": {
                    "status": "success"
                },
                "remediate": {
                    "status": None
                },
                "rollback": {
                    "status": None
                }
            },
            "mitigationStatus": "mitigated",
            "publisher": "",
            "rank": 0,
            "resolved": False,
            "siteId": "475482421366727777",
            "siteName": "demisto",
            "threatAgentVersion": "3.2.3.37",
            "threatName": "Ncat Netcat Portable - CHIP-Installer.exe",
            "updatedAt": "2019-09-15T14:25:50.181148Z",
            "username": "",
            "whiteningOptions": ["hash", "path"]
        },
        {
            "accountId": "412243337337583618",
            "accountName": "SentinelOne",
            "agentComputerName": "EC2AMAZ-AJ0KDDD",
            "agentDomain": "WORKGROUP",
            "agentId": "657613730168123596",
            "agentInfected": False,
            "agentIp": "3.136.231.41",
            "agentIsActive": True,
            "agentIsDecommissioned": False,
            "agentMachineType": "server",
            "agentNetworkStatus": "disconnected",
            "agentOsType": "windows",
            "agentVersion": "3.2.3.37",
            "annotation": None,
            "annotationUrl": None,
            "browserType": None,
            "certId": "",
            "classification": "Malware",
            "classificationSource": "Static",
            "classifierName": "STATIC",
            "cloudVerdict": "provider_unknown",
            "collectionId": "715789430041423412",
            "createdAt": "2019-09-15T14:25:49.944443Z",
            "createdDate": "2020-06-13T22:59:02Z",
            "description": "malware detected - not mitigated yet (static engine)",
            "engines": ["pre_execution"],
            "fileContentHash": "3e7704f5668bc4330c686ccce2dd6f99696863bd",
            "fileCreatedDate": None,
            "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
            "fileExtensionType": "Executable",
            "fileIsDotNet": None,
            "fileIsExecutable": False,
            "fileIsSystem": False,
            "fileMaliciousContent": None,
            "fileObjectId": "43A5D890AC420DKC",
            "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - "
                        "CHIP-Installer.exe",
            "fileSha256": None,
            "fileVerificationType": "PathNotFound",
            "fromCloud": False,
            "fromScan": False,
            "id": "715789434420276799",
            "indicators": [25, 24, 23, 6],
            "isCertValid": False,
            "isInteractiveSession": False,
            "isPartialStory": False,
            "maliciousGroupId": "B9343BEED7D7713C",
            "maliciousProcessArguments": None,
            "markedAsBenign": None,
            "mitigationMode": "protect",
            "mitigationReport": {
                "kill": {
                    "status": "success"
                },
                "network_quarantine": {
                    "status": None
                },
                "quarantine": {
                    "status": "success"
                },
                "remediate": {
                    "status": None
                },
                "rollback": {
                    "status": None
                }
            },
            "mitigationStatus": "mitigated",
            "publisher": "",
            "rank": 0,
            "resolved": False,
            "siteId": "475482421366727777",
            "siteName": "demisto",
            "threatAgentVersion": "3.2.3.37",
            "threatName": "Ncat Netcat Portable - CHIP-Installer.exe",
            "updatedAt": "2019-09-15T14:25:50.181148Z",
            "username": "",
            "whiteningOptions": ["hash", "path"]
        }
    ]
}
# disable-secrets-detection-end


def test_fetch_incidents_filtered_by_rank(mocker, requests_mock):
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://usea1.sentinelone.net',
        'fetch_time': '3 years',
        'fetch_threat_rank': '5'
    })
    mocker.patch.object(demisto, 'getLastRun', return_value={'time': 1284629762000})
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'incidents')
    requests_mock.get('https://usea1.sentinelone.net/web/api/v2.0/threats', json=RAW_THREATS_RESPONSE)
    main()
    fetch_incidents()

    assert demisto.incidents.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    incidents = demisto.incidents.call_args[0][0]
    # with 'fetch_threat_rank' equal to 5 only one of the 3 incidents from INCIDENTS_FOR_FETCH should be returned
    # in this case the one with a rank of 7
    assert len(incidents) == 1
    threat_incident = incidents[0]
    assert threat_incident.get('occurred', '') == '2019-09-16T09:36:02.331000Z'


def test_fetch_incidents_all_inclusive(mocker, requests_mock):
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://usea1.sentinelone.net',
        'fetch_time': '3 years',
        'fetch_threat_rank': '0'
    })
    mocker.patch.object(demisto, 'getLastRun', return_value={'time': 1284629762000})
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'incidents')
    requests_mock.get('https://usea1.sentinelone.net/web/api/v2.0/threats', json=RAW_THREATS_RESPONSE)
    main()
    fetch_incidents()

    assert demisto.incidents.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    incidents = demisto.incidents.call_args[0][0]
    # with 'fetch_threat_rank' equal to 0 all 3 incidents from INCIDENTS_FOR_FETCH should be returned
    assert len(incidents) == 4
    threat_incident = incidents[0]
    assert threat_incident.get('occurred', '') == '2019-10-14T19:44:24.647000Z'
    threat_incident = incidents[1]
    assert threat_incident.get('occurred', '') == '2019-09-16T09:36:02.331000Z'
    threat_incident = incidents[2]
    assert threat_incident.get('occurred', '') == '2019-09-15T14:25:48.988000Z'
    threat_incident = incidents[3]
    assert threat_incident.get('occurred', '') == '2020-06-13T22:59:02Z'
