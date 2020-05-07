EXPECTED_ALERT_RSLT = {
    "FireEyeHelix.Alert(val.ID && val.ID === obj.ID)": {
        "ID": 123,
        "AlertTypeID": 1793,
        "Name": "HX",
        "AssigneeID": None,
        "AssigneeName": None,
        "CreatorID": "id",
        "CreatorName": "System User",
        "UpdaterID": "id",
        "UpdaterName": "George",
        "CreatedTime": "2019-03-30T19:40:16.132456Z",
        "ModifiedTime": "2019-10-20T12:35:02.132456Z",
        "ProcessPath": "c:\\windows\\microsoft.net\\framework\\v7.0.30319\\csc.exe",
        "Process": None,
        "ParentProcess": None,
        "Confidence": "high",
        "SHA1": "sha1",
        "MD5": "md5",
        "Hostname": "helix.apps.fireeye.com",
        "PID": 11,
        "Size": None,
        "Virus": "gen:variant.ursu",
        "Result": "quarantined",
        "MalwareType": "malware",
        "FileName": "c:\\users\\demon\\appdata\\local\\temp",
        "RegPath": None,
        "EventTime": None,
        "IOCNames": None,
        "SourceIPv4": None,
        "SourceIPv6": None,
        "DestinationIPv4": None,
        "DestinationIPv6": None,
        "DestinationPort": None,
        "URI": None,
        "Domain": None,
        "UserAgent": None,
        "HttpMethod": None,
        "EventsCount": 2,
        "NotesCount": 0,
        "ClosedState": "Unknown",
        "ClosedReason": "",
        "Description": "FireEye HX detected and quarantined malware on this system.",
        "FirstEventTime": "2019-03-30T14:07:34.132456ZZ",
        "LastEventTime": "2019-03-31T14:08:07.132456ZZ",
        "ExternalIP": [],
        "InternalIP": [],
        "Message": "FIREEYE H",
        "Products": {
            "hx": 2
        },
        "Risk": "Medium",
        "Severity": "Medium",
        "State": "Open",
        "Tags": [
            "fireeye"
        ],
        "Type": "fireeye_rule"
    }
}

EXPECTED_ALERTS_RSLT = {
    "FireEyeHelix.Alert(val.ID && val.ID === obj.ID)": [
        {
            "ID": 123,
            "AlertTypeID": 1793,
            "Name": "HX",
            "AssigneeID": None,
            "AssigneeName": None,
            "CreatorID": "id",
            "CreatorName": "System User",
            "UpdaterID": "id",
            "UpdaterName": "George",
            "CreatedTime": "2019-03-30T19:40:16.132456Z",
            "ModifiedTime": "2019-10-20T12:35:02.132456Z",
            "ProcessPath": "c:\\windows\\microsoft.net\\framework\\v7.0.30319\\csc.exe",
            "Process": None,
            "ParentProcess": None,
            "Confidence": "high",
            "SHA1": "sha1",
            "MD5": "md5",
            "Hostname": "helix.apps.fireeye.com",
            "PID": 11,
            "Size": None,
            "Virus": "gen:variant.ursu",
            "Result": "quarantined",
            "MalwareType": "malware",
            "FileName": "c:\\users\\demon\\appdata\\local\\temp",
            "RegPath": None,
            "EventTime": None,
            "IOCNames": None,
            "SourceIPv4": None,
            "SourceIPv6": None,
            "DestinationIPv4": None,
            "DestinationIPv6": None,
            "DestinationPort": None,
            "URI": None,
            "Domain": None,
            "UserAgent": None,
            "HttpMethod": None,
            "EventsCount": 2,
            "NotesCount": 0,
            "ClosedState": "Unknown",
            "ClosedReason": "",
            "Description": "FireEye HX detected and quarantined malware on this system.",
            "FirstEventTime": "2019-03-30T14:07:34.132456ZZ",
            "LastEventTime": "2019-03-31T14:08:07.132456ZZ",
            "ExternalIP": [],
            "InternalIP": [],
            "Message": "FIREEYE H",
            "Products": {
                "hx": 2
            },
            "Risk": "Medium",
            "Severity": "Medium",
            "State": "Open",
            "Tags": [
                "fireeye"
            ],
            "Type": "fireeye_rule"
        },
        {
            "ID": 32,
            "AlertTypeID": 18,
            "Name": "HX",
            "AssigneeID": None,
            "AssigneeName": None,
            "CreatorID": "ab",
            "CreatorName": "System User",
            "UpdaterID": "e7",
            "UpdaterName": "George",
            "CreatedTime": "2019-03-30T19:40:17.132456Z",
            "ModifiedTime": "2019-10-23T20:35:02.132456Z",
            "ProcessPath": "c:\\windows\\system32\\cmd.exe",
            "Process": "cmd.exe",
            "ParentProcess": "services.exe",
            "Confidence": None,
            "SHA1": None,
            "MD5": "md5",
            "Hostname": "helix.apps.fireeye.com",
            "PID": 99,
            "Size": None,
            "Virus": None,
            "Result": "alert",
            "MalwareType": None,
            "FileName": None,
            "RegPath": None,
            "EventTime": "2019-03-30T14:11:31.000Z",
            "IOCNames": "cobalt strike",
            "SourceIPv4": None,
            "SourceIPv6": None,
            "DestinationIPv4": None,
            "DestinationIPv6": None,
            "DestinationPort": None,
            "URI": None,
            "Domain": None,
            "UserAgent": None,
            "HttpMethod": None,
            "EventsCount": 2,
            "NotesCount": 0,
            "ClosedState": "Unknown",
            "ClosedReason": "",
            "Description": "This rule alerts on IOC.",
            "FirstEventTime": "2019-03-25T14:09:45.132456Z",
            "LastEventTime": "2019-03-25T14:11:31.132456Z",
            "ExternalIP": [],
            "InternalIP": [],
            "Message": "FIREEYE HX [IOC Process Event]",
            "Products": {
                "hx": 2
            },
            "Risk": "Medium",
            "Severity": "Medium",
            "State": "Open",
            "Tags": [
                "fireeye",
                "helixhxrule"
            ],
            "Type": "fireeye_rule"
        }
    ],
    "FireEyeHelix.Alert(val.Count).Count": 115
}

EXPECTED_AGGREGATIONS_SINGLE_RSLT = [
    {'subject': 'Test 1', 'DocCount': 1},
    {'subject': 'Test 2', 'DocCount': 2},
    {'subject': 'Test 3', 'DocCount': 3},
    {'subject': 'Test 4', 'DocCount': 4}
]

EXPECTED_AGGREGATIONS_MULTI_RSLT = [
    {'srcipv4': '192.168.0.1', 'to': 'test1@demisto.com', 'subject': 'accepted', 'DocCount': 1},
    {'srcipv4': '192.168.0.2', 'to': 'test2@demisto.com', 'subject': 'resume', 'DocCount': 2},
    {'srcipv4': '192.168.0.3', 'to': 'test3@demisto.com', 'subject': 'position', 'DocCount': 3}
]

EXPECTED_CASES_NY_ALERT_RSLT = {
    "FireEyeHelix.Case(val.ID && val.ID === obj.ID)": [
        {
            "ID": 35,
            "Name": "demisto test case",
            "AlertsCount": None,
            "AssigneeID": None,
            "AssigneeName": None,
            "CreatorID": "id",
            "CreatorName": "name",
            "UpdaterID": "id",
            "UpdaterName": "name",
            "CreatedTime": "created_at",
            "ModifiedTime": "updated_at",
            "Description": "",
            "EventsCount": 10,
            "InfoLinks": [],
            "NotesCount": 0,
            "Priority": "Critical",
            "PriorityOrder": 4,
            "Severity": 10,
            "State": "Testing",
            "Status": "Declared",
            "Tags": [],
            "TotalDaysUnresolved": "16 23:52:09.819390"
        }
    ]
}

EXPECTED_ENDPOINTS_BY_ALERT_RSLT = {
    "FireEyeHelix.Endpoint(val.ID && val.ID === obj.ID)": [
        {
            "ID": 191,
            "CustomerID": "demisto",
            "DeviceID": "device_id",
            "Domain": "WORKGROUP",
            "Hostname": "Demisto",
            "MACAddress": "mac_address",
            "OS": "Windows 10 Pro",
            "IP": "primary_ip_address",
            "UpdatedTime": "updated_at",
            "ContainmentState": "normal"
        }
    ],
    "FireEyeHelix.Endpoint(val.Count).Count": 1
}

EXPECTED_EVENTS_BY_ALERT_RSLT = {
    "FireEyeHelix.Event(val.ID && val.ID === obj.ID)": [
        {
            "ID": "101",
            "Type": "processevent",
            "Result": "alert",
            "MatchedAt": "2019-08-11t06:51:40.000z",
            "Confidence": None,
            "Status": None,
            "EventTime": "2019-09-13T06:51:59.000Z",
            "DetectedRuleID": [
                "99"
            ],
            "PID": 404,
            "Process": "net1",
            "ProcessPath": "c:\\windows\\system32\\net1.exe",
            "FileName": None,
            "FilePath": None,
            "DeviceName": None,
            "Size": None,
            "Virus": None,
            "MalwareType": None,
            "CreatedTime": None,
            "Class": "fireeye_hx_alert",
            "MD5": "md5",
            "SHA1": None,
            "Protocol": None,
            "SourceIPv4": None,
            "SourceIPv6": None,
            "SourcePort": None,
            "SourceLongitude": None,
            "DestinationIPv4": None,
            "SourceLatitude": None,
            "DestinationIPv6": None,
            "DestinationPort": None,
            "ReportTime": "2019-09-13t06:53:08.000",
            "FalsePositive": False,
            "Domain": None,
            "From": None,
            "SourceDomain": None,
            "SourceISP": None,
            "DestinationISP": None,
            "RcpTo": None,
            "To": None,
            "InReplyTo": None,
            "Attachment": None
        }
    ],
    "FireEyeHelix.Event(val.Count).Count": 10
}

EXPECTED_RULES_RSLT = {
    "FireEyeHelix.Rule(val.ID && val.ID === obj.ID)": [
        {
            "ID": "1.1.1",
            "RulePack": "1.1.1",
            "Description": "demisto",
            "Internal": True,
            "Deleted": False,
            "Enabled": True,
            "Supported": False,
            "CreatorID": "demisto",
            "CreatorName": "Demisto",
            "UpdatedByID": "demisto",
            "UpdatedByName": "Demisto",
            "Risk": "Medium",
            "Confidence": "Medium",
            "Severity": "Medium",
            "Tags": ["demisto", "malware", "http", "md-info"],
            "Type": "alert"
        }
    ],
    "FireEyeHelix.Rule(val.Count)": None
}

EXPECTED_RULE_RSLT = {
    "FireEyeHelix.Rule(val.ID && val.ID === obj.ID)": [
        {
            "ID": "1.1.1",
            "RulePack": "1.1.1",
            "Description": "demisto",
            "Internal": True,
            "Deleted": False,
            "Enabled": True,
            "Supported": False,
            "CreatorID": "demisto",
            "CreatorName": "Demisto",
            "UpdatedByID": "demisto",
            "UpdatedByName": "Demisto",
            "Risk": "Medium",
            "Confidence": "Medium",
            "Severity": "Medium",
            "Tags": ["demisto", "malware", "http", "md-info"],
            "Type": "alert"
        }
    ]
}

EXPECTED_SINGLE_LIST_ITEM_RSLT = {
    "FireEyeHelixList(val.ID && val.ID === 3232).Item": {
        "ID": 163,
        "Value": "aTest list",
        "Type": "misc",
        "Risk": "Medium",
        "Notes": "test ok",
        "ListID": 3232
    }
}

EXPECTED_LIST_ITEMS_RSLT = {
    "FireEyeHelixList(val.ID && val.ID === 3232).Item(val.ID === obj.ID)": [
        {
            "ID": 163,
            "Value": "Test list",
            "Type": "misc",
            "Risk": "Low",
            "Notes": "",
            "ListID": 3232
        }
    ],
    "FireEyeHelixList(val.ID && val.ID === 3232).Count(val.Count)": 1
}

EXPECTED_LIST_ITEMS_UPDATE_RSLT = {
    "FireEyeHelixList(val.ID && val.ID === 3232).Item(val.ID === obj.ID)": {
        "ID": 163,
        "Value": "aTest list",
        "Type": "misc",
        "Risk": "Medium",
        "Notes": "test ok",
        "ListID": 3232
    }
}

EXPECTED_SEARCH_RSLT = {
    "FireEyeHelixSearch(val.MQL && val.MQL === obj.MQL)": {
        "MQL": "domain:google.com and meta_ts>=2019-10-25T09:07:43.810Z {page_size:2 offset:1 limit:1} | groupby subject sep=`|%$,$%|`",  # noqa: E501
        "Result": [
            {
                "ID": "demisto",
                "Type": "trace",
                "Result": None,
                "MatchedAt": None,
                "Confidence": None,
                "Status": "delivered",
                "EventTime": "2019-10-28T10:43:11.000Z",
                "DetectedRuleID": None,
                "PID": None,
                "Process": None,
                "ProcessPath": None,
                "FileName": None,
                "FilePath": None,
                "DeviceName": None,
                "Size": None,
                "Virus": None,
                "MalwareType": None,
                "CreatedTime": None,
                "Class": "fireeye_etp",
                "MD5": None,
                "SHA1": None,
                "Protocol": None,
                "SourceIPv4": "8.8.8.8",
                "SourceIPv6": None,
                "SourcePort": None,
                "SourceLongitude": -122.0785140991211,
                "DestinationIPv4": None,
                "SourceLatitude": 37.40599060058594,
                "DestinationIPv6": None,
                "DestinationPort": None,
                "ReportTime": None,
                "FalsePositive": None,
                "Domain": "mx.google.com",
                "From": "de@demisto.com",
                "SourceDomain": "google.com",
                "SourceISP": "google llc",
                "DestinationISP": None,
                "RcpTo": None,
                "To": "demisto@demisto.com",
                "InReplyTo": "demisto",
                "Attachment": None
            },
            {
                "ID": "demisto",
                "Type": "trace",
                "Result": None,
                "MatchedAt": None,
                "Confidence": None,
                "Status": "delivered",
                "EventTime": "2019-10-29T05:08:39.000Z",
                "DetectedRuleID": None,
                "PID": None,
                "Process": None,
                "ProcessPath": None,
                "FileName": None,
                "FilePath": None,
                "DeviceName": None,
                "Size": None,
                "Virus": None,
                "MalwareType": None,
                "CreatedTime": None,
                "Class": "fireeye_etp",
                "MD5": None,
                "SHA1": None,
                "Protocol": None,
                "SourceIPv4": "8.8.8.8",
                "SourceIPv6": None,
                "SourcePort": None,
                "SourceLongitude": -122.0785140991211,
                "DestinationIPv4": None,
                "SourceLatitude": 37.40599060058594,
                "DestinationIPv6": None,
                "DestinationPort": None,
                "ReportTime": None,
                "FalsePositive": None,
                "Domain": "gmr-mx.google.com",
                "From": "dem@demisto.com",
                "SourceDomain": "google.com",
                "SourceISP": "google llc",
                "DestinationISP": None,
                "RcpTo": None,
                "To": "demisto@demisto.com",
                "InReplyTo": "demisto@demisto.com",
                "Attachment": None
            }
        ],
        "GroupBy": [
            {
                "subject": "google alert - gold",
                "DocCount": 3
            },
            {
                "subject": "accepted: meeting",
                "DocCount": 1
            },
            {
                "subject": "invitation: Declined",
                "DocCount": 1
            }
        ]
    }
}

EXPECTED_SEARCH_ARCHIVE_RSLT = {
    "FireEyeHelixSearch(val.ID === obj.ID)": [
        {
            "ID": "82",
            "PercentComplete": 100.0,
            "Query": "domain:[google,com] | groupby eventtype",
            "State": "completed"
        },
        {
            "ID": "83",
            "PercentComplete": 100.0,
            "Query": "domain:[google] | groupby eventtype",
            "State": "completed"
        }
    ]
}

EXPECTED_SEARCH_ARCHIVE_STATUS_RSLT = {
    "FireEyeHelixSearch(val.ID === obj.ID)": [
        {
            "ID": "82",
            "PercentComplete": 100.0,
            "Query": "domain:[google,com] | groupby eventtype",
            "State": "completed"
        },
        {
            "ID": "82",
            "PercentComplete": 100.0,
            "Query": "domain:[google,com] | groupby eventtype",
            "State": "completed"
        }
    ]
}

EXPECTED_SEARCH_ARCHIVE_RESULTS_RSLT = {
    "FireEyeHelixSearch(val.ID && val.ID === obj.ID)": {
        "MQL": "domain:[google,com] | groupby eventtype sep=`|%$,$%|`",
        "ID": 82,
        "Result": [
            {
                "ID": "evenid",
                "Type": "trace",
                "Result": None,
                "MatchedAt": None,
                "Confidence": None,
                "Status": "delivered",
                "EventTime": "2019-10-06T10:48:13.000Z",
                "DetectedRuleID": None,
                "PID": None,
                "Process": None,
                "ProcessPath": None,
                "FileName": None,
                "FilePath": None,
                "DeviceName": None,
                "Size": None,
                "Virus": None,
                "MalwareType": None,
                "CreatedTime": None,
                "Class": "fireeye_etp",
                "MD5": None,
                "SHA1": None,
                "Protocol": None,
                "SourceIPv4": "8.8.8.8",
                "SourceIPv6": None,
                "SourcePort": None,
                "SourceLongitude": -0.12574,
                "DestinationIPv4": None,
                "SourceLatitude": 51.8594,
                "DestinationIPv6": None,
                "DestinationPort": None,
                "ReportTime": None,
                "FalsePositive": None,
                "Domain": "domain.com",
                "From": "squidward@demisto.com",
                "SourceDomain": "",
                "SourceISP": "",
                "DestinationISP": None,
                "RcpTo": None,
                "To": "demisto@demisto.com",
                "InReplyTo": "squidward <squidward@demisto.com>",
                "Attachment": None
            },
            {
                "ID": "demisto",
                "Type": "trace",
                "Result": None,
                "MatchedAt": None,
                "Confidence": None,
                "Status": "delivered",
                "EventTime": "2019-10-06T11:02:01.000Z",
                "DetectedRuleID": None,
                "PID": None,
                "Process": None,
                "ProcessPath": None,
                "FileName": None,
                "FilePath": None,
                "DeviceName": None,
                "Size": None,
                "Virus": None,
                "MalwareType": None,
                "CreatedTime": None,
                "Class": "fireeye_etp",
                "MD5": None,
                "SHA1": None,
                "Protocol": None,
                "SourceIPv4": "8.8.8.8",
                "SourceIPv6": None,
                "SourcePort": None,
                "SourceLongitude": -75.19625,
                "DestinationIPv4": None,
                "SourceLatitude": 40.282958,
                "DestinationIPv6": None,
                "DestinationPort": None,
                "ReportTime": None,
                "FalsePositive": None,
                "Domain": "demisto.com",
                "From": "squidward@demisto.com",
                "SourceDomain": "squidward.com",
                "SourceISP": "squidward",
                "DestinationISP": None,
                "RcpTo": None,
                "To": "squidward@demisto.com",
                "InReplyTo": "\"squidward\" <fsquidward@demisto.com>",
                "Attachment": None
            },
            {
                "ID": "dwasdkffv",
                "Type": "trace",
                "Result": None,
                "MatchedAt": None,
                "Confidence": None,
                "Status": "delivered",
                "EventTime": "2019-10-06T11:02:18.000Z",
                "DetectedRuleID": None,
                "PID": None,
                "Process": None,
                "ProcessPath": None,
                "FileName": None,
                "FilePath": None,
                "DeviceName": None,
                "Size": None,
                "Virus": None,
                "MalwareType": None,
                "CreatedTime": None,
                "Class": "fireeye_etp",
                "MD5": None,
                "SHA1": None,
                "Protocol": None,
                "SourceIPv4": "8.8.8.8",
                "SourceIPv6": None,
                "SourcePort": None,
                "SourceLongitude": -93.119,
                "DestinationIPv4": None,
                "SourceLatitude": 33.5,
                "DestinationIPv6": None,
                "DestinationPort": None,
                "ReportTime": None,
                "FalsePositive": None,
                "Domain": "demisto.com",
                "From": "squidward@demisto.com",
                "SourceDomain": "demisto.com",
                "SourceISP": "demistos",
                "DestinationISP": None,
                "RcpTo": None,
                "To": "squidward@demisto.com",
                "InReplyTo": "squidward <squidward@demisto.com>",
                "Attachment": None
            },
            {
                "ID": "93730",
                "Type": "trace",
                "Result": None,
                "MatchedAt": None,
                "Confidence": None,
                "Status": "delivered",
                "EventTime": "2019-10-06T11:03:00.000Z",
                "DetectedRuleID": None,
                "PID": None,
                "Process": None,
                "ProcessPath": None,
                "FileName": None,
                "FilePath": None,
                "DeviceName": None,
                "Size": None,
                "Virus": None,
                "MalwareType": None,
                "CreatedTime": None,
                "Class": "fireeye_etp",
                "MD5": None,
                "SHA1": None,
                "Protocol": None,
                "SourceIPv4": "8.8.8.8",
                "SourceIPv6": None,
                "SourcePort": None,
                "SourceLongitude": -84.377,
                "DestinationIPv4": None,
                "SourceLatitude": 33.770843,
                "DestinationIPv6": None,
                "DestinationPort": None,
                "ReportTime": None,
                "FalsePositive": None,
                "Domain": "demisto.com",
                "From": "squidward@demisto.com",
                "SourceDomain": "demisto.com",
                "SourceISP": "the demisto group",
                "DestinationISP": None,
                "RcpTo": None,
                "To": "squidward@demisto.com",
                "InReplyTo": "geroge <hello@demisto.com>",
                "Attachment": None
            }
        ],
        "GroupBy": []
    }
}

EXPECTED_NOTES_GET_RSLT = {
    "FireEyeHelix.Note(val.ID && val.ID === obj.ID)": [
        {
            "ID": 9,
            "CreatedTime": "2019-10-28T07:41:30.396000Z",
            "UpdatedTime": "2019-10-28T07:41:42.000123Z",
            "Message": "This is a note test",
            "CreatorID": "a",
            "CreatorName": "George",
            "AlertID": None
        },
        {
            "ID": 91,
            "CreatedTime": "2019-10-24T13:52:19.021299Z",
            "UpdatedTime": "2019-10-24T13:52:19.021399Z",
            "Message": "What a great note this is",
            "CreatorID": "a",
            "CreatorName": "George",
            "AlertID": None
        }
    ],
    "FireEyeHelix.Note(val.Count && val.AlertID === None).Count": 2
}

EXPECTED_NOTES_CREATE_RSLT = {
    "FireEyeHelix.Note(val.ID && val.ID === obj.ID)": {
        "ID": 9,
        "CreatedTime": "2019-10-28T07:41:30.396000Z",
        "UpdatedTime": "2019-10-28T07:41:42.000123Z",
        "Message": "This is a note test",
        "CreatorID": "a",
        "CreatorName": "George",
        "AlertID": 3232
    }
}
