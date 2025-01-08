EXPECTED_LIST_WORKFLOWS = {
    'Securonix.Workflows(val.Workflow == obj.Workflow)':
        [
            {
                'Workflow': 'SOCTeamReview', 'Type': 'USER', 'Value': 'admin'
            },
            {
                'Workflow': 'ActivityOutlierWorkflow', 'Type': 'USER', 'Value': 'admin'
            },
            {
                'Workflow': 'AccessCertificationWorkflow', 'Type': 'USER', 'Value': 'admin'
            }
        ]
}
EXPECTED_DEFAULT_ASSIGNEE = {
    'Securonix.Workflows(val.Workflow === obj.Workflow)': {
        'Workflow': 'SOCTeamReview',
        'Type': 'USER',
        'Value': 'admin'
    }
}
EXPECTED_POSSIBLE_THREAT_ACTIONS = {
    'Securonix.ThreatActions': [
        "Mark as concern and create incident",
        "Non-Concern",
        "Mark in progress (still investigating)"
    ]
}
EXPECTED_LIST_RESOURCE_GROUPS = {
    'Securonix.ResourceGroups(val.Name === obj.Name)':
        [
            {'Name': 'Bluecoat Proxy', 'Type': 'Bluecoat Proxy'},
            {'Name': 'Ironport Data', 'Type': 'Cisco Ironport Email'},
            {'Name': 'Windchill Data', 'Type': 'Windchill'}
        ]
}
EXPECTED_LIST_USERS = {
    'Securonix.Users(val.EmployeeID === obj.EmployeeID)':
        {
            'ApproverEmployeeId': ['1082', '1082'],
            'CostCenterCode': ['ILEGCCC13', 'ILEGCCC13'],
            'Criticality': ['Low', 'Low'],
            'Department': ['SAP Administrator', 'Legal Department'],
            'Division': ['Global Technology', 'Legal'],
            'Email': ["momo@demisto.com", "foo@demisto.com"],
            'EmployeeID': ['1644', '1631'],
            'EmployeeType': ['FT', 'FT'],
            'EnableDate': ['2018-08-15T12:50:11Z', '2018-08-15T12:50:11Z'],
            'FirstName': ['Tan', 'Lauren'],
            'HireDate': ['2009-08-08T00:00:00Z', '2009-08-08T00:00:00Z'],
            'JobCode': ['R1', 'R1'],
            'LastName': ['Gul', 'Clarke'],
            'Location': ['ALABAMA', 'ALABAMA'],
            'ManagerEmployeeId': ['1084', '1066'],
            'ManagerFirstname': ['Axel', 'Kyla'],
            'ManagerLastname': ['Figueroa', 'Clay'],
            'Masked': ['false', 'false'],
            'Riskscore': ['0.0', '0.0'],
            'SkipEncryption': ['false', 'false'],
            'Status': ['1', '1'],
            'Title': ['Sr. Legal Advisor', 'Sr. Legal Advisor'],
            'User': None,
            'WorkPhone': '216-564-5141'
        }
}
EXPECTED_LIST_INCIDENT = {
    'Securonix.Incidents(val.IncidentID === obj.IncidentID)':
        [
            {
                'ViolatorText': 'Cyndi Converse',
                'LastUpdateDate': 1566293234026,
                'ViolatorID': '96',
                'IncidentType': 'RISK MODEL',
                'IncidentID': '100181',
                'IncidentStatus': 'COMPLETED',
                'Riskscore': 0.0,
                'AssignedUser': 'Account Access 02',
                'AssignedGroup': 'Administrators',
                'Priority': 'None',
                'Reason': ['Resource: Symantec Email DLP'],
                'ViolatorSubText': '1096',
                'Entity': 'Users',
                'WorkflowName': 'SOCTeamReview',
                'Url': "https://source_url.com",
                'IsWhitelisted': False,
                'Watchlisted': False,
                "Policystarttime": 1692950376801,
                "Policyendtime": 1695613655539,
                "Solrquery": "index = violation and ( ( @policyname = \"Response-*PB?-Resources-\\AutoPlay\" and @resourcename=\"Activityres17-Resource-549829\" )  ) AND @tenantname=\"Response-Automation\" AND datetime between \"02/07/2023 15:52:12\" \"02/07/2023 15:52:13\""  # noqa: E501
            }
        ]
}
EXPECTED_GET_INCIDENT = {
    'Securonix.Incidents(val.IncidentID === obj.IncidentID)': [
        {
            "ViolatorText": "Cyndi Converse",
            "LastUpdateDate": 1566232568502,
            "ViolatorID": "96",
            "IncidentType": "Policy",
            "IncidentID": "100107",
            "IncidentStatus": "COMPLETED",
            "Riskscore": 0.0,
            "AssignedUser": "Admin Admin",
            "Priority": "low",
            "Reason": [
                "Resource: Symantec Email DLP",
                "Policy: Emails with large File attachments",
                "Threat: Data egress attempts"
            ],
            "ViolatorSubText": "1096",
            "Entity": "Users",
            "WorkflowName": "SOCTeamReview",
            "Url": "https://source_url.com",
            "IsWhitelisted": False,
            "Watchlisted": False,
            "Policystarttime": 1692950376801,
            "Policyendtime": 1695613655539,
            "Solrquery": "index = violation and ( ( @policyname = \"Response-*PB?-Resources-\\AutoPlay\" and @resourcename=\"Activityres17-Resource-549829\" )  ) AND @tenantname=\"Response-Automation\" AND datetime between \"02/07/2023 15:52:12\" \"02/07/2023 15:52:13\""  # noqa: E501
        }
    ]
}
EXPECTED_CREATE_INCIDENT = {
    'Securonix.Incidents(val.IncidentID === obj.IncidentID)': [
        {
            "ViolatorText": "jon doe",
            "LastUpdateDate": 1579686449882,
            "Casecreatetime": 1579686449882,
            "ViolatorID": "3",
            "IncidentType": "Policy",
            "IncidentID": "30053",
            "IncidentStatus": "Open",
            "Riskscore": 0.0,
            "AssignedUser": "Admin Admin",
            "Priority": "Low",
            "Reason": [
                "Resource: BLUECOAT",
                "Policy: Uploads to personal websites",
                "Threat: Data egress via network uploads"
            ],
            "ViolatorSubText": "1003",
            "Entity": "Users",
            "WorkflowName": "SOCTeamReview",
            "Url": "url.com",
            "IsWhitelisted": False,
            "Watchlisted": True,
            'TenantInfo': {
                'tenantid': 1,
                'tenantname': 'Securonix',
                'tenantcolor': '#000000',
                'tenantshortcode': 'SE'
            },
            "StatusCompleted": False,
            "SandBoxPolicy": False,
            "ParentCaseId": ''
        }
    ]
}
EXPECTED_PERFORM_ACTION_ON_INCIDENT = {}
EXPECTED_LIST_WATCHLISTS = {
    'Securonix.WatchlistsNames':
        [
            'Domain_Admin',
            'Privileged_Users',
            'Privileged_Accounts',
            'Recent_Hires'
        ]
}
EXPECTED_GET_WATCHLIST = {
    'Securonix.Watchlists(val.Watchlistname === obj.Watchlistname)':
        {
            'Watchlistname': "Flight RiskUsers",
            'Type': None,
            'TenantID': '1',
            'TenantName': 'Securonix',
            'Events':
                [
                    {
                        'DirectImport': 'false',
                        'Hour': '0',
                        'Ignored': 'false',
                        'Invalid': 'false',
                        'InvalidEventAction': '0',
                        'Id': '-1',
                        'Userid': '-1',
                        'Result': {
                            'entry':
                                [
                                    {'key': 'reason', 'value': ''},
                                    {'key': 'expirydate', 'value': '1540674976881'},
                                    {'key': 'u_employeeid', 'value': '1002'},
                                    {'key': 'u_department', 'value': 'Mainframe and Midrange Administration'},
                                    {'key': 'u_workphone', 'value': '9728351246'},
                                    {'key': 'u_division', 'value': 'Global Technology'},
                                    {'key': 'confidencefactor', 'value': '0.0'},
                                    {'key': 'entityname', 'value': '1002'},
                                    {'key': 'u_jobcode', 'value': 'R1'},
                                    {'key': 'u_hiredate', 'value': '1249707600000'},
                                    {'key': 'type', 'value': 'Users'},
                                    {'key': 'u_costcentername', 'value': 'IINFCCC12'}
                                ]
                        }
                    }
                ]
        }
}
EXPECTED_CREATE_WATCHLIST = {
    'Securonix.Watchlists(val.Watchlistname === obj.Watchlistname && val.TenantName === obj.TenantName)': {
        "Watchlistname": "test234"
    }
}
EXPECTED_ENTITY_IN_WATCHLIST = {
    'Securonix.EntityInWatchlist(val.Entityname === obj.Entityname)': {
        'Watchlistname': 'test234',
        'Entityname': '1002'
    }
}
EXPECTED_ADD_ENTITY_TO_WATCHLIST = {}
EXPECTED_LIST_THREATS = {
    'Securonix.Threat(val.EntityID === obj.EntityID && val.Resourcename === obj.Resourcename && val.Resourcetype '
    '=== obj.Resourcetype && val.Resourcegroupname === obj.Resourcegroupname && val.Policies.toString() === '
    'obj.Policies.toString())': [{
        "TenantID": 2,
        "Tenantname": "Response-Automation",
        "Violator": "Activityaccount",
        "EntityID": "VIOLATOR5-1673852881421",
        "Resourcegroupname": "RES-PLAYBOOK-DS-AUTOMATION",
        "ThreatName": "TM_Response-PB-ActivityAccount-Manual",
        "Category": "NONE",
        "Resourcename": "RES10-RESOURCE-302184",
        "Resourcetype": "Res-Playbook",
        "GenerationTime": "Mon, 16 Jan 2023 @ 01:53:31 AM",
        "GenerationTime_Epoch": 1673855611090,
        "Policies": [
            "Response-PB-ActivityAccount-Manual"
        ]
    }]
}

EXPECTED_GET_INCIDENT_ACTIVITY_HISTORY_6_4 = {'Securonix.IncidentHistory': [
    {
        "caseid": "2849604490",
        "actiontaken": "CREATED",
        "status": "Open",
        "comment": [
            {
                "Comments": "Incident created while executing playbook - Create Security Incident"
            }
        ],
        "eventTime": "Jan 12, 2023 7:25:38 AM",
        "username": "Admin Admin",
        "currentassignee": "API_TEST_SS",
        "commentType": [
            "text"
        ],
        "currWorkflow": "SOCTeamReview",
        "isPlayBookOutAvailable": False,
        "creator": "admin"
    },
    {
        "caseid": "2849604490",
        "actiontaken": "In Progress",
        "status": "In Progress",
        "comment": [],
        "eventTime": "Jan 12, 2023 8:16:22 AM",
        "lastStatus": "Open",
        "username": "Test User",
        "currentassignee": "API_TEST_SS",
        "pastassignee": "API_TEST_SS",
        "commentType": [],
        "prevWorkflow": "Test_XSOAR",
        "currWorkflow": "Test_XSOAR",
        "isPlayBookOutAvailable": False,
        "creator": "test_user"
    },
    {
        "caseid": "2849604490",
        "actiontaken": "Closed",
        "status": "Completed",
        "comment": [],
        "eventTime": "Jan 12, 2023 8:16:48 AM",
        "lastStatus": "In Progress",
        "username": "Test User",
        "currentassignee": "API_TEST_SS",
        "pastassignee": "API_TEST_SS",
        "commentType": [],
        "prevWorkflow": "Test_XSOAR",
        "currWorkflow": "Test_XSOAR",
        "isPlayBookOutAvailable": False,
        "creator": "test_user"
    }
]}

EXPECTED_GET_INCIDENT_ATTACHMENT_HISTORY_6_4 = [
    {'Contents': '', 'ContentsFormat': 'text', 'Type': 3, 'File': 'test.txt',
     'FileID': '6c8964a3-aebd-4a4e-9d12-63b08c82372f'}]

EXPECTED_LIST_VIOLATION_DATA_6_4 = [
    {
        "Timeline_By_Month": "1672552800000",
        "Resourcegroupname": "SNX-IEE-AEE-51",
        "Eventid": "test-event-id",
        "Ipaddress": "0.0.0.0",
        "Week": "3",
        "Year": "2023",
        "Riskthreatname": "Abnormal DNS record type queries",
        "Eventlatitude": "1.2931",
        "Userid": "-1",
        "Dayofmonth": "16",
        "Jobid": "36819",
        "Resourcegroupid": "439",
        "Datetime": "1673869861092",
        "Timeline_By_Hour": "1673888400000",
        "Accountname": "YOST",
        "Hour": "5",
        "Emailrecipientdomain": "test_domain",
        "Postalcode": "PO,1,3,5,6,7,14",
        "TenantID": "3",
        "ID": "-1",
        "Timeline_By_Minute": "1673869800000",
        "GenerationTime": "01/16/2023 05:52:22",
        "Eventlongitude": "103.8558",
        "Eventcity": "Singapore",
        "Violator": "RTActivityAccount",
        "Transactionstring1": "Logon failure",
        "Categorizedtime": "Early Morning",
        "Rawevent": "test raw event",
        "Jobstarttime": "1673869810000",
        "Resourcetype": "Snx-Automation-Rt",
        "Dayofyear": "16",
        "Categoryseverity": "0",
        "Month": "0",
        "Invalid": "false",
        "Timeline": "1673848800000",
        "Dayofweek": "2",
        "Emailrecipient": "example.com",
        "Timeline_By_Week": "1673762400000",
        "Tenantname": "test_tenant",
        "Policyname": "Snx-IEE-RiskBoosterMatchCriteria",
        "Resourcename": "Windows",
        "Emailsender": "example.com",
        "Category": "ACCOUNT MISUSE",
        "Eventcountry": "Singapore",
        "Eventregion": "Asia",
        "Resourcecomments": "ingestion_2.0",
    }
]

EXPECTED_LIST_ACTIVITY = {
    "Securonix.Activity(val.command_name === obj.command_name)": {
        "queryId": "spotter_web_service_00000000-0000-0000-0000-000000000001",
        "totalDocuments": 4,
        "command_name": "securonix-list-activity-data"
    },
    "Securonix.ActivityData(val.EventID === obj.EventID)": [
        {
            "Accountname": "ACCOUNT_001",
            "Accountresourcekey": "00000000000~000000000.0000.com~pipe_line_test~0000~-1",
            "Agentfilename": "test.txt",
            "Categorybehavior": "Account Create",
            "Categoryobject": "Account Management",
            "Categoryseverity": "0",
            "Collectionmethod": "file",
            "Collectiontimestamp": "1690803374000",
            "Destinationusername": "TEST134044",
            "Devicehostname": "HOST.com",
            "EventID": "00000000-0000-0000-0000-000000000001",
            "Eventoutcome": "Success",
            "Filepath": "N/A",
            "Ingestionnodeid": "CONSOLE",
            "Jobstarttime": "1690803374000",
            "Message": "A user account was created.",
            "Publishedtime": "1690803374572",
            "Receivedtime": "1690803420706",
            "Resourcename": "HOST.com",
            "Sourceusername": "USER",
            "TenantID": "2",
            "Tenantname": "Response-Automation",
            "Timeline": "1670911200000"
        },
        {
            "_Indexed_At_Tdt": "Thu Aug 29 15:04:10 UTC 2024",
            "_Version_": "0000000000000000001",
            "Accountname": "ACCOUNT_002",
            "Accountresourcekey": "00000000000~000000000.0000.com~pipe_line_test~0000~-2",
            "Agentfilename": "test.txt",
            "Baseeventid": "0001",
            "Categorizedtime": "Afternoon",
            "Categorybehavior": "Account Create",
            "Categoryobject": "Account Management",
            "Categoryoutcome": "Success",
            "Categoryseverity": "0",
            "Collectionmethod": "file",
            "Collectiontimestamp": "1690803374000",
            "Customnumber1": "3.0",
            "Customstring13": "String",
            "Customtime1": "1595257341000",
            "Customtime2": "1595257341000",
            "Datetime": "1724766983279",
            "Dayofmonth": "27",
            "Dayofweek": "3",
            "Dayofyear": "240",
            "Destinationntdomain": "XYZ",
            "Destinationprocessname": "Test123",
            "Destinationservicename": "Test123",
            "Destinationuserid": "0-0-0-00-0000000000-00002",
            "Destinationusername": "TEST134044",
            "Destinationuserprivileges": "Impersonation",
            "Devicecustomstring4": "Custom",
            "Deviceeventcategory": "Category",
            "Devicehostname": "HOST.com",
            "Ehash": "00000000000000000000000000000000000000000000000000000000000000001",
            "EventID": "00000000-0000-0000-0000-000000000002",
            "Eventoutcome": "Success",
            "Filepath": "N/A",
            "Filepermission": "Yes",
            "Hour": "13",
            "ID": "-1",
            "Ingestionnodeid": "CONSOLE",
            "Ipaddress": "0.0.0.2",
            "Ipaddress_Long": "000000002",
            "Jobid": "002",
            "Jobstarttime": "1690803374000",
            "Message": "A user account was created.",
            "Minute": "29",
            "Month": "7",
            "Oldfileid": "002",
            "Oldfilepath": "-",
            "Others": "additionaldetails19=-",
            "Poprocessedtime": "1724766960000",
            "Publishedtime": "1690803374572",
            "Rawevent": "0000000000000002|0.0.0.2|002|Temp2024",
            "Raweventsize": "2346",
            "Receivedtime": "1690803420500",
            "Resourcegroupid": "3955",
            "Resourcegroupname": "Group_2",
            "Resourcehostname": "0.0.0.2",
            "Resourcehostname_Long": "172433163",
            "Resourcename": "HOST.com",
            "Resourcetype": "Type",
            "ResourceGroupCategory": "os",
            "ResourceGroupFunctionality": "Computer",
            "ResourceGroupTypeID": "120",
            "ResourceGroupTimezoneoffset": "UTC",
            "ResourceGroupVendor": "Vendor",
            "Sessionid": "0x0",
            "Sourceaddress": "0.0.0.2",
            "Sourceaddress_Long": "172433207",
            "Sourcehostname": "HOST.com",
            "Sourcentdomain": "-",
            "Sourceport": "0001",
            "Sourceprocessname": "-",
            "Sourceuserid": "0-1-0-0",
            "Sourceusername": "USER",
            "TenantID": "2",
            "Tenantname": "Response-Automation",
            "Timeline_By_Hour": "1724763600000",
            "Timeline_By_Minute": "1724766960000",
            "Timeline_By_Month": "1722488400000",
            "Timeline_By_Week": "1724562000000",
            "Timestamp": "Tue Aug 27 14:24:25 UTC 2024",
            "Transactionstring1": "Events",
            "Transactionstring2": "{00000000-0000-0000-0000-000000000000}",
            "Transactionstring3": "-",
            "Userid": "-1",
            "Week": "35",
            "Year": "2024",
            "Timeline": "1670911200000"
        },
        {
            "Accountname": "ACCOUNT_002",
            "Accountresourcekey": "00000000000~000000000.0000.com~pipe_line_test~0000~-2",
            "Agentfilename": "test.txt",
            "Categorybehavior": "Account Create",
            "Categoryobject": "Account Management",
            "Categoryseverity": "0",
            "Collectionmethod": "file",
            "Collectiontimestamp": "1690803374000",
            "Destinationusername": "TEST134044",
            "Devicehostname": "HOST.com",
            "EventID": "00000000-0000-0000-0000-000000000002",
            "Eventoutcome": "Success",
            "Filepath": "N/A",
            "Ingestionnodeid": "CONSOLE",
            "Jobstarttime": "1690803374000",
            "Message": "A user account was created.",
            "Publishedtime": "1690803374572",
            "Receivedtime": "1690803420500",
            "Resourcename": "HOST.com",
            "Sourceusername": "USER",
            "TenantID": "2",
            "Tenantname": "Response-Automation",
            "Timeline": "1670911200000"
        }
    ]
}

EXPECTED_LIST_ACTIVITY_NO_DATA = {
    "Securonix.Activity(val.command_name === obj.command_name)": {
        "queryId": "spotter_web_service_00000000-0000-0000-0000-000000000001",
        "totalDocuments": 4,
        "message": "All records have been retrieved. No more results to be fetched.",
        "command_name": "securonix-list-activity-data"
    }
}

EXPECTED_LIST_WHITELISTS_ENTRY = {
    'Securonix.Whitelist(val.WhitelistName === obj.WhitelistName && val.TenantName === obj.TenantName)': [
        {
            "WhitelistName": "Dummy Whitelist 1",
            "WhitelistType": "Automated",
            "TenantName": "test_tenant"
        },
        {
            "WhitelistName": "Dummy Whitelist 2",
            "WhitelistType": "Automated",
            "TenantName": "test_tenant"
        }]
}
EXPECTED_GET_WHITELIST_ENTRY = {
    'Securonix.Whitelist(val.WhitelistName === obj.WhitelistName && val.TenantName === obj.TenantName)': {
        "WhitelistName": "test_whitelist",
        "Entries": [{
            "Entity/Attribute": "TEST123",
            "ExpiryDate": "09/28/2035 21:21:19"
        }]
    }
}

EXPECTED_ADD_WHITELIST_ENTRY_6_4 = "Entity added to global whitelist Successfully."
EXPECTED_CREATE_WHITELIST = {}

EXPECTED_CREATE_LOOKUP_TABLE = "Lookup Table test_table created successfully."
EXPECTED_DELETE_LOOKUP_TABLE_CONFIG_AND_DATA = {
    'Securonix.LookupTable(val.lookupTableName === obj.lookupTableName)': {
        'lookupTableName': 'test',
        'isDeleted': True
    }
}

EXPECTED_LOOKUP_TABLE_LIST = {
    'Securonix.LookupTable(val.lookupTableName === obj.lookupTableName)': [
        {
            'tenantName': 'All Tenants',
            'lookupTableName': 'NonBusinessDomains',
            'totalRecords': 2213,
            'scope': 'global',
            'type': 'system'
        },
        {
            'tenantName': 'All Tenants',
            'lookupTableName': 'CompressedFileExtensions',
            'totalRecords': 240,
            'scope': 'meta',
            'type': 'system'
        }
    ]
}
EXPECTED_LOOKUP_TABLE_ENTRY_ADD = {}
EXPECTED_DELETE_WHITELIST_ENTRY = {}

EXPECTED_LOOKUP_TABLE_ENTRIES_LIST = {'Securonix.LookupTableEntries(val.lookupuniquekey === obj.lookupuniquekey)': [
    {
        "entry": [
            {
                "key": "fieldname",
                "value": "destinationport"
            },
            {
                "key": "vendor",
                "value": "Cisco Netflow"
            },
            {
                "key": "categoryobject",
                "value": "Network"
            },
            {
                "key": "categoryoutcome",
                "value": "Attempt"
            },
            {
                "key": "categorybehavior",
                "value": "Connection Statistics"
            },
            {
                "key": "key",
                "value": "0"
            }
        ],
        "defaultenrichedevent": [
            "0",
            "Attempt",
            "Cisco Netflow",
            "Connection Statistics",
            "Network",
            "destinationport"
        ],
        "lookupuniquekey": "-1^~CATEGORIZATION_FLOW|0",
        "lookupname": "Categorization_Flow",
        "tenantid": -1,
        "tenantname": "All Tenants",
        "key": "0",
        "timestamp": "Jan 23, 2023 7:01:33 AM"
    },
    {
        "entry": [
            {
                "key": "fieldname",
                "value": "destinationport"
            },
            {
                "key": "vendor",
                "value": "Cisco Netflow"
            },
            {
                "key": "categoryobject",
                "value": "Network"
            },
            {
                "key": "categoryoutcome",
                "value": "Attempt"
            },
            {
                "key": "categorybehavior",
                "value": "Connection Statistics"
            },
            {
                "key": "key",
                "value": "1"
            }
        ],
        "defaultenrichedevent": [
            "1",
            "Attempt",
            "Cisco Netflow",
            "Connection Statistics",
            "Network",
            "destinationport"
        ],
        "lookupuniquekey": "-1^~CATEGORIZATION_FLOW|1",
        "lookupname": "Categorization_Flow",
        "tenantid": -1,
        "tenantname": "All Tenants",
        "key": "1",
        "timestamp": "Jan 23, 2023 7:01:33 AM"
    }
]
}

EXPECTED_GET_INCIDENT_WORKFLOW = "Incident 123456 workflow is TestWorkFlow."

EXPECTED_GET_INCIDENT_STATUS = "Incident 123456 status is TestStatus."

EXPECTED_GET_INCIDENT_AVAILABLE_ACTIONS = "Incident 123456 available actions: ['CLAIM', 'COMPLETED']."

EXPECTED_FETCH_INCIDENT = {
    "violatorText": "Cyndi Converse",
    "lastUpdateDate": 1566232568502,
    "violatorId": "96",
    "incidentType": "Policy",
    "incidentId": "100107",
    "incidentStatus": "COMPLETED",
    "riskscore": 0.0,
    "assignedUser": "Admin Admin",
    "priority": "low",
    "reason": [
        "Resource: Symantec Email DLP",
        "Policy: Emails with large File attachments",
        "Threat: Data egress attempts",
        {
            "Policies": {
                "stage1": {
                    "s1": ["TestEmailTemplate1", "TestEmailTemplate2"]
                },
                "stage2": {
                    "s2": ["TestEmailtemplate3"]
                }
            }
        }
    ],
    'close_sx_incident': False,
    'mirror_direction': None,
    'mirror_instance': '',
    'mirror_tags': '',
    'policy_list': ['TestEmailTemplate1', 'TestEmailTemplate2', 'TestEmailtemplate3'],
    'policy_stages_json': {'stage1:s1': ['TestEmailTemplate1', 'TestEmailTemplate2'],
                           'stage2:s2': ['TestEmailtemplate3']},
    'policy_stages_table': [{'Policies': 'TestEmailTemplate1, TestEmailTemplate2',
                            'Stage Name': 'stage1:s1'},
                            {'Policies': 'TestEmailtemplate3', 'Stage Name': 'stage2:s2'}],
    "violatorSubText": "1096",
    "entity": "Users",
    "workflowName": "SOCTeamReview",
    "url": "https://source_url.com",
    "isWhitelisted": False,
    "watchlisted": False,
    "policystarttime": 1692950376801,
    "policyendtime": 1695613655539,
    "solrquery": "index = violation and ( ( @policyname = \"Response-*PB?-Resources-\\AutoPlay\" and @resourcename=\"Activityres17-Resource-549829\" )  ) AND @tenantname=\"Response-Automation\" AND datetime between \"02/07/2023 15:52:12\" \"02/07/2023 15:52:13\""  # noqa: E501
}

EXPECTED_ADD_COMMENT_TO_INCIDENT = "Comment was added to the incident 123456 successfully."

EXPECTED_XSOAR_STATE_MAPPING = {
    'ACTIVE': {
        'action': 'Start Investigation',
        'status': 'in progress'
    },
    'DONE': {
        'action': 'Close Incident',
        'status': 'completed'
    }
}

EXPECTED_DELETE_LOOKUP_ENTRIES_DELETE = {}
