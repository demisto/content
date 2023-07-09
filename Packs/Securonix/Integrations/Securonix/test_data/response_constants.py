from requests.models import Response

RESPONSE_LIST_WORKFLOWS = {
    "result": {
        "workflows":
            [
                {
                    "workflow": "SOCTeamReview",
                    "type": "USER",
                    "value": "admin"
                },
                {
                    "workflow": "ActivityOutlierWorkflow",
                    "type": "USER",
                    "value": "admin"
                },
                {
                    "workflow": "AccessCertificationWorkflow",
                    "type": "USER",
                    "value": "admin"
                }
            ]
    }
}
RESPONSE_DEFAULT_ASSIGNEE = {
    "result": {
        "type": "USER",
        "value": "admin"
    }
}
RESPONSE_POSSIBLE_THREAT_ACTIONS = {
    "result": [
        "Mark as concern and create incident",
        "Non-Concern",
        "Mark in progress (still investigating)"
    ]
}
RESPONSE_LIST_RESOURCE_GROUPS = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" \
                                "<resourceGroups>" \
                                "<resourceGroup>" \
                                "<name>Bluecoat Proxy</name>" \
                                "<type>Bluecoat Proxy</type>" \
                                "</resourceGroup>" \
                                "<resourceGroup>" \
                                "<name>Ironport Data</name>" \
                                "<type>Cisco Ironport Email</type>" \
                                "</resourceGroup>" \
                                "<resourceGroup>" \
                                "<name>Windchill Data</name>" \
                                "<type>Windchill</type>" \
                                "</resourceGroup>" \
                                "</resourceGroups>"
RESPONSE_LIST_USERS = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" \
                      "<users>" \
                      "<user>" \
                      "<approverEmployeeId>1082</approverEmployeeId> " \
                      "<costCenterCode>ILEGCCC13</costCenterCode>" \
                      "<criticality>Low</criticality>" \
                      "<department>SAP Administrator</department>" \
                      "<division>Global Technology</division>" \
                      "<email>momo@demisto.com</email>" \
                      "<employeeId>1644</employeeId>" \
                      "<employeeType>FT</employeeType>" \
                      "<enableDate>2018-08-15T12:50:11Z</enableDate>" \
                      "<firstName>Tan</firstName>" \
                      "<hireDate>2009-08-08T00:00:00Z</hireDate>" \
                      "<jobCode>R1</jobCode>" \
                      "<lastName>Gul</lastName>" \
                      "<location>ALABAMA</location>" \
                      "<managerEmployeeId>1084</managerEmployeeId>" \
                      "<managerFirstname>Axel</managerFirstname>" \
                      "<managerLastname>Figueroa</managerLastname>" \
                      "<masked>false</masked> <riskscore>0.0</riskscore>" \
                      "<skipEncryption>false</skipEncryption>" \
                      "<status>1</status>" \
                      "<title>Sr. Legal Advisor</title>" \
                      "<user>" \
                      "</user>" \
                      "<approverEmployeeId>1082</approverEmployeeId>" \
                      "<costCenterCode>ILEGCCC13</costCenterCode>" \
                      "<criticality>Low</criticality>" \
                      "<department>Legal Department</department>" \
                      "<division>Legal</division>" \
                      "<email>foo@demisto.com</email>" \
                      "<employeeId>1631</employeeId>" \
                      "<employeeType>FT</employeeType>" \
                      "<enableDate>2018-08-15T12:50:11Z</enableDate>" \
                      "<firstName>Lauren</firstName>" \
                      "<hireDate>2009-08-08T00:00:00Z</hireDate>" \
                      "<jobCode>R1</jobCode>" \
                      "<lastName>Clarke</lastName>" \
                      "<location>ALABAMA</location>" \
                      "<managerEmployeeId>1066</managerEmployeeId>" \
                      "<managerFirstname>Kyla</managerFirstname>" \
                      "<managerLastname>Clay</managerLastname>" \
                      "<masked>false</masked>" \
                      "<riskscore>0.0</riskscore>" \
                      "<skipEncryption>false</skipEncryption>" \
                      "<status>1</status>" \
                      "<title>Sr. Legal Advisor</title>" \
                      "<workPhone>216-564-5141</workPhone>" \
                      "</user>" \
                      "</users>"
RESPONSE_LIST_INCIDENT = {
    "result": {
        "data": {
            "totalIncidents": 1.0,
            "incidentItems": [
                {
                    "violatorText": "Cyndi Converse",
                    "lastUpdateDate": 1566293234026,
                    "violatorId": "96",
                    "incidentType": "RISK MODEL",
                    "incidentId": "100181",
                    "incidentStatus": "COMPLETED",
                    "riskscore": 0.0,
                    "assignedUser": "Account Access 02",
                    "assignedGroup": "Administrators",
                    "priority": "None",
                    "reason": [
                        "Resource: Symantec Email DLP"
                    ],
                    "violatorSubText": "1096",
                    "entity": "Users",
                    "workflowName": "SOCTeamReview",
                    "url": "https://source_url.com",
                    "isWhitelisted": False,
                    "watchlisted": False
                }
            ]
        }
    }
}
RESPONSE_GET_INCIDENT = {
    "result": {
        "data": {
            "totalIncidents": 1.0,
            "incidentItems": [
                {
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
                        "Threat: Data egress attempts"
                    ],
                    "violatorSubText": "1096",
                    "entity": "Users",
                    "workflowName": "SOCTeamReview",
                    "url": "https://source_url.com",
                    "isWhitelisted": False,
                    "watchlisted": False,
                    "solrquery": "index = violation and ( ( @policyname = \"Response-PB-Resources-AutoPlay\" and @resourcename=\"Activityres17-Resource-549829\" )  ) AND @tenantname=\"Response-Automation\" AND datetime between \"02/07/2023 15:52:12\" \"02/07/2023 15:52:13\""
                }
            ]
        }
    }
}
RESPONSE_CREATE_INCIDENT = {
    'status': 'OK',
    'messages': ['Get incident details for incident ID [30053]'],
    'result': {
        'data': {
            'totalIncidents': 1.0,
            'incidentItems': [
                {
                    'violatorText': 'jon doe',
                    'lastUpdateDate': 1579686449882,
                    'violatorId': '3',
                    'incidentType': 'Policy',
                    'incidentId': '30053',
                    'incidentStatus': 'Open',
                    'riskscore': 0.0,
                    'assignedUser': 'Admin Admin',
                    'priority': 'Low',
                    'reason': ['Resource: BLUECOAT', 'Policy: Uploads to personal websites',
                               'Threat: Data egress via network uploads'],
                    'violatorSubText': '1003',
                    'entity': 'Users',
                    'workflowName': 'SOCTeamReview',
                    'url': 'url.com',
                    'isWhitelisted': False,
                    'watchlisted': True,
                    'tenantInfo': {
                        'tenantid': 1,
                        'tenantname': 'Securonix',
                        'tenantcolor': '#000000',
                        'tenantshortcode': 'SE'
                    },
                    'statusCompleted': False,
                    'sandBoxPolicy': False,
                    'parentCaseId': '',
                    'casecreatetime': 1579686449882
                }
            ]
        }
    }
}
RESPONSE_PERFORM_ACTION_ON_INCIDENT = {
    'result': 'submitted'
}
RESPONSE_LIST_WATCHLISTS = {
    "result": [
        "Domain_Admin", "Privileged_Users", "Privileged_Accounts", "Recent_Hires"
    ]
}
RESPONSE_GET_WATCHLIST = {
    "available": "false",
    "error": "false",
    "events": [
        {
            "directImport": "false",
            "hour": "0",
            "ignored": "false",
            "invalid": "false",
            "invalidEventAction": "0",
            "tenantid": "1",
            "tenantname": "Securonix",
            "u_id": "-1",
            "u_userid": "-1",
            "result": {
                "entry": [
                    {
                        "key": "reason",
                        "value": ""
                    },
                    {
                        "key": "expirydate",
                        "value": "1540674976881"
                    },
                    {
                        "key": "u_employeeid",
                        "value": "1002"
                    },
                    {
                        "key": "u_department",
                        "value": "Mainframe and Midrange Administration"
                    },
                    {
                        "key": "u_workphone",
                        "value": "9728351246"
                    },
                    {
                        "key": "u_division",
                        "value": "Global Technology"
                    },
                    {
                        "key": "confidencefactor",
                        "value": "0.0"
                    },
                    {
                        "key": "entityname",
                        "value": "1002"
                    },
                    {
                        "key": "u_jobcode",
                        "value": "R1"
                    },
                    {
                        "key": "u_hiredate",
                        "value": "1249707600000"
                    },
                    {
                        "key": "type", "value": "Users"
                    },
                    {
                        "key": "u_costcentername",
                        "value": "IINFCCC12"
                    }
                ]
            }
        }
    ],
    "from": "1533842667887",
    "offset": "1000",
    "query": "index=watchlist AND watchlistname=\"Flight RiskUsers\"",
    "searchViolations": "false",
    "to": "1536521067887",
    "totalDocuments": "1"
}
RESPONSE_CREATE_WATCHLIST = "New watchlist created successfully…!"
RESPONSE_ENTITY_IN_WATCHLIST = {
    'status': 'OK',
    'messages': ['EntityId provided present in test234?'],
    'result': ['YES']
}
RESPONSE_ADD_ENTITY_TO_WATCHLIST = "Add to watchlist successfull..!"
RESPONSE_FETCH_INCIDENT_ITEM = {
    "assignedGroup": "SECURITYOPERATIONS",
    "casecreatetime": 1579500273595,
    "entity": "Users",
    "incidentId": "10134",
    "incidentStatus": "OPEN",
    "incidentType": "Policy",
    "isWhitelisted": False,
    "lastUpdateDate": 1585227067399,
    "parentCaseId": "",
    "priority": "low",
    "reason": [
        "Resource: BLUECOAT",
        "Policy: Uploads to personal websites",
        "Threat: Data egress via network uploads"
    ],
    "riskscore": 0,
    "sandBoxPolicy": False,
    "statusCompleted": False,
    "tenantInfo": {
        "tenantcolor": "#000000",
        "tenantid": 1,
        "tenantname": "Securonix",
        "tenantshortcode": "SE"
    },
    "url": "demisto.com",
    "violatorId": "12",
    "violatorSubText": "1012",
    "violatorText": "Secret secret",
    "watchlisted": False,
    "workflowName": "SOCTeamReview"
}

RESPONSE_FETCH_INCIDENT_ITEM_VERSION_6_4 = {
    "assignedGroup": "SECURITYOPERATIONS",
    "casecreatetime": 1579500273595,
    "entity": "Users",
    "incidentId": "10134",
    "incidentStatus": "OPEN",
    "incidentType": "Policy",
    "isWhitelisted": False,
    "lastUpdateDate": 1585227067399,
    "parentCaseId": "",
    "priority": "low",
    "reason": [
        "Resource: BLUECOAT",
        {"Policies": ["Uploads to personal websites"]},
        "Threat Model: Data egress via network uploads"
    ],
    "riskscore": 0,
    "sandBoxPolicy": False,
    "statusCompleted": False,
    "tenantInfo": {
        "tenantcolor": "#000000",
        "tenantid": 1,
        "tenantname": "Securonix",
        "tenantshortcode": "SE"
    },
    "url": "demisto.com",
    "violatorId": "12",
    "violatorSubText": "1012",
    "violatorText": "Secret secret",
    "watchlisted": False,
    "workflowName": "SOCTeamReview"
}

RESPONSE_FETCH_INCIDENT_ITEM_NO_THREAT_MODEL = {
    "assignedGroup": "SECURITYOPERATIONS",
    "casecreatetime": 1579500273595,
    "entity": "Users",
    "incidentId": "10134",
    "incidentStatus": "OPEN",
    "incidentType": "Policy",
    "isWhitelisted": False,
    "lastUpdateDate": 1585227067399,
    "parentCaseId": "",
    "priority": "low",
    "reason": [
        "Resource: BLUECOAT"
    ],
    "riskscore": 0,
    "sandBoxPolicy": False,
    "statusCompleted": False,
    "tenantInfo": {
        "tenantcolor": "#000000",
        "tenantid": 1,
        "tenantname": "Securonix",
        "tenantshortcode": "SE"
    },
    "url": "demisto.com",
    "violatorId": "12",
    "violatorSubText": "1012",
    "violatorText": "Secret secret",
    "watchlisted": False,
    "workflowName": "SOCTeamReview"
}
RESPONSE_FETCH_INCIDENT_ITEM_MULTIPLE_REASONS = {
    "assignedGroup": "SECURITYOPERATIONS",
    "casecreatetime": 1579500273595,
    "entity": "Users",
    "incidentId": "10135",
    "incidentStatus": "OPEN",
    "incidentType": "Policy",
    "isWhitelisted": False,
    "lastUpdateDate": 1585227067399,
    "parentCaseId": "",
    "priority": "low",
    "reason": [
        "Resource: BLUECOAT",
        "Policy: Uploads to personal websites",
        "Threat: Data egress via network uploads",
        "Resource: Email Gateway",
        "Policy: Emails Sent to Personal Email",
        "Threat: mock"
    ],
    "riskscore": 0,
    "sandBoxPolicy": False,
    "statusCompleted": False,
    "tenantInfo": {
        "tenantcolor": "#000000",
        "tenantid": 1,
        "tenantname": "Securonix",
        "tenantshortcode": "SE"
    },
    "url": "demisto.com",
    "violatorId": "12",
    "violatorSubText": "1012",
    "violatorText": "Secret secret",
    "watchlisted": False,
    "workflowName": "SOCTeamReview"
}
RESPONSE_FETCH_INCIDENTS = {
    "totalIncidents": 1.0,
    "incidentItems": [
        {
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
                "Threat: Data egress attempts"
            ],
            "violatorSubText": "1096",
            "entity": "Users",
            "workflowName": "SOCTeamReview",
            "url": "https://source_url.com",
            "isWhitelisted": False,
            "watchlisted": False
        }
    ]
}
RESPONSE_FETCH_THREATS = [
    {
        "tenantid": 2,
        "tenantname": "Response-Automation",
        "violator": "Activityaccount",
        "entityid": "VIOLATOR5-1673852881421",
        "resourcegroupname": "RES-PLAYBOOK-DS-AUTOMATION",
        "threatname": "TM_Response-PB-ActivityAccount-Manual",
        "category": "NONE",
        "resourcename": "RES10-RESOURCE-302184",
        "resourcetype": "Res-Playbook",
        "generationtime": "Mon, 16 Jan 2023 @ 01:53:31 AM",
        "generationtime_epoch": 1673855611090,
        "policies": [
            "Response-PB-ActivityAccount-Manual"
        ]
    }
]
RESPONSE_LIST_THREATS = {
    "Response": {
        "Total records": 100,
        "offset": 0,
        "max": 2,
        "threats": [
            {
                "tenantid": 2,
                "tenantname": "Response-Automation",
                "violator": "Activityaccount",
                "entityid": "VIOLATOR5-1673852881421",
                "resourcegroupname": "RES-PLAYBOOK-DS-AUTOMATION",
                "threatname": "TM_Response-PB-ActivityAccount-Manual",
                "category": "NONE",
                "resourcename": "RES10-RESOURCE-302184",
                "resourcetype": "Res-Playbook",
                "generationtime": "Mon, 16 Jan 2023 @ 01:53:31 AM",
                "generationtime_epoch": 1673855611090,
                "policies": [
                    "Response-PB-ActivityAccount-Manual"
                ]
            }
        ]
    }
}

RESPONSE_GET_INCIDENT_ACTIVITY_HISTORY_6_4 = {
    "status": "OK",
    "messages": [
        "Get activity stream details for incident ID [2849604490]"
    ],
    "result": {
        "activityStreamData": [
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
        ]
    }
}

RESPONSE_LIST_VIOLATION_6_4 = {
    "totalDocuments": 585651023,
    "events": [
        {
            "timeline_by_month": "1672552800000",
            "resourcegroupname": "SNX-IEE-AEE-51",
            "eventid": "test-event-id",
            "ipaddress": "0.0.0.0",
            "week": "3",
            "year": "2023",
            "riskthreatname": "Abnormal DNS record type queries",
            "eventlatitude": "1.2931",
            "userid": "-1",
            "dayofmonth": "16",
            "jobid": "36819",
            "resourcegroupid": "439",
            "datetime": "1673869861092",
            "timeline_by_hour": "1673888400000",
            "accountname": "YOST",
            "hour": "5",
            "emailrecipientdomain": "test_domain",
            "postalcode": "PO,1,3,5,6,7,14",
            "tenantid": "3",
            "id": "-1",
            "timeline_by_minute": "1673869800000",
            "generationtime": "01/16/2023 05:52:22",
            "eventlongitude": "103.8558",
            "eventcity": "Singapore",
            "violator": "RTActivityAccount",
            "transactionstring1": "Logon failure",
            "categorizedtime": "Early Morning",
            "rawevent": "test raw event",
            "jobstarttime": "1673869810000",
            "resourcetype": "Snx-Automation-Rt",
            "dayofyear": "16",
            "categoryseverity": "0",
            "month": "0",
            "invalid": "false",
            "timeline": "1673848800000",
            "dayofweek": "2",
            "emailrecipient": "example.com",
            "timeline_by_week": "1673762400000",
            "tenantname": "test_tenant",
            "policyname": "Snx-IEE-RiskBoosterMatchCriteria",
            "resourcename": "Windows",
            "emailsender": "example.com",
            "category": "ACCOUNT MISUSE",
            "eventcountry": "Singapore",
            "eventregion": "Asia",
            "resourcecomments": "ingestion_2.0"
        },
    ],
    "error": False,
    "available": False,
    "queryId": "spotterwebservice-test-id",
    "applicationTz": "CST6CDT",
    "inputParams": {
        "generationtime_from": "01/17/2022 00:00:00",
        "max": "50",
        "query": "index = violation",
        "generationtime_to": "01/17/2023 00:00:20"
    },
    "index": "violation",
    "nextCursorMarker": "test-cursor-marker"
}

RESPONSE_LIST_WHITELISTS_ENTRY = {
    "status": "OK",
    "messages": [
        " WhiteList Name | Whitelist Type | Tenant Name "
    ],
    "result": [
        "Dummy Whitelist 1 | Automated | test_tenant",
        "Dummy Whitelist 2 | Automated | test_tenant"
    ]
}

RESPONSE_GET_WHITELIST_ENTRY = {
    "status": "OK",
    "messages": [
        "whitelistname : Dummy Threat Model MM",
        "Entity/Attribute : Expiry Date"
    ],
    "result": {
        "TEST123": "09/28/2035 21:21:19"
    }
}
RESPONSE_CREATE_WHITELIST = {
    "status": "OK",
    "messages": [
        "New Global whitelist created Successfully ..!",
        "whitelistname : test_whitelist"
    ],
    "result": []
}
RESPONSE_DELETE_LOOKUP_TABLE_CONFIG_AND_DATA = 'test and data deleted successfully'

RESPONSE_ADD_WHITELIST_ENTRY_6_4 = {
    "status": "OK",
    "messages": [
        "entity added to global whitelist Successfully...!"
    ],
    "result": []
}
RESPONSE_DELETE_WHITELIST_ENTRY = {
    "status": "OK",
    "messages": [
        "Whitelist Name : test_ng"
    ],
    "result": [
        "EmployeeId Item removed from whitelist Successfully ..! "
    ]
}

RESPONSE_LOOKUP_TABLE_LIST = [
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
RESPONSE_LOOKUP_TABLE_ENTRY_ADD = "Entries added to  XSOAR_TEST successfully"

RESPONSE_LOOKUP_TABLE_ENTRIES_LIST = [
    {
        "defaultenrichedevent": [
            "0",
            "Attempt",
            "Cisco Netflow",
            "Connection Statistics",
            "Network",
            "destinationport"
        ],
        "value_fieldname": "destinationport",
        "value_vendor": "Cisco Netflow",
        "value_categoryobject": "Network",
        "lookupuniquekey": "-1^~CATEGORIZATION_FLOW|0",
        "value_categoryoutcome": "Attempt",
        "lookupname": "Categorization_Flow",
        "value_categorybehavior": "Connection Statistics",
        "value_key": "0",
        "tenantid": -1,
        "tenantname": "All Tenants",
        "key": "0",
        "timestamp": "Jan 23, 2023 7:01:33 AM"
    },
    {
        "defaultenrichedevent": [
            "1",
            "Attempt",
            "Cisco Netflow",
            "Connection Statistics",
            "Network",
            "destinationport"
        ],
        "value_fieldname": "destinationport",
        "value_vendor": "Cisco Netflow",
        "value_categoryobject": "Network",
        "lookupuniquekey": "-1^~CATEGORIZATION_FLOW|1",
        "value_categoryoutcome": "Attempt",
        "lookupname": "Categorization_Flow",
        "value_categorybehavior": "Connection Statistics",
        "value_key": "1",
        "tenantid": -1,
        "tenantname": "All Tenants",
        "key": "1",
        "timestamp": "Jan 23, 2023 7:01:33 AM"
    }
]

RESPONSE_DELETE_LOOKUP_ENTRIES_DELETE = 'Successfully deleted the given key(s)!'


RESPONSE_GET_INCIDENT_WORKFLOW = {
    "status": "OK",
    "messages": [
        "Get incident workflow for incident ID [123456] - [TestWorkFlow]"
    ],
    "result": {
        "workflow": "TestWorkFlow"
    }
}

RESPONSE_GET_INCIDENT_STATUS = {
    "status": "OK",
    "messages": [
        "Get incident status for incident ID [123456] - [TestStatus]"
    ],
    "result": {
        "status": "TestStatus"
    }
}

RESPONSE_GET_INCIDENT_AVAILABLE_ACTIONS = {
    "status": "OK",
    "messages": [
        "Get possible actions for incident ID [100289], incident status [Open]"
    ],
    "result": [
        {
            "actionDetails": [
                {
                    "title": "Screen1",
                    "sections": {
                        "sectionName": "Comments",
                        "attributes": [
                            {
                                "displayName": "Comments",
                                "attributeType": "textarea",
                                "attribute": "15_Comments",
                                "required": "false"
                            }
                        ]
                    }
                }
            ],
            "actionName": "CLAIM",
            "status": "CLAIMED"
        },
        {
            "actionDetails": [
                {
                    "title": "Screen2",
                    "sections": {
                        "sectionName": "Comments",
                        "attributes": [
                            {
                                "displayName": "Comments",
                                "attributeType": "textarea",
                                "attribute": "15_Comments",
                                "required": "false"
                            }
                        ]
                    }
                }
            ],
            "actionName": "COMPLETED",
            "status": "COMPLETED"
        }
    ]
}

RESPONSE_ADD_COMMENT_TO_INCIDENT = {
    "status": "OK",
    "messages": [
        "Add comment to incident id - [100289]"
    ],
    "result": True
}


def get_mock_create_lookup_table_response():
    RESPONSE_CREATE_LOOKUP_TABLE = Response()
    RESPONSE_CREATE_LOOKUP_TABLE.status_code = 200
    RESPONSE_CREATE_LOOKUP_TABLE._content = b'Lookup Table test_table created successfully'
    return RESPONSE_CREATE_LOOKUP_TABLE


def get_mock_attachment_response():
    RESPONSE_GET_INCIDENT_ATTACHMENT_6_4 = Response()
    RESPONSE_GET_INCIDENT_ATTACHMENT_6_4.headers = {'Content-Disposition': 'attachment;filename=test.txt'}
    RESPONSE_GET_INCIDENT_ATTACHMENT_6_4.status_code = 200
    RESPONSE_GET_INCIDENT_ATTACHMENT_6_4._content = b'test file'
    return RESPONSE_GET_INCIDENT_ATTACHMENT_6_4


DELETE_LOOKUP_TABLE_ENTRIES_INVALID_LOOKUP_NAME = [
    {
        "errorCode": 404,
        "errorMessage": "lookupTableName doesn't exists. Please provide available lookupTableName.",
        "errorType": "Functional"
    }
]

DELETE_LOOKUP_TABLE_ENTRIES_INVALID_LOOKUP_KEYS = [
    {
        "errorCode": 404,
        "errorMessage": "Error deleting the key! Please check the input params!key1",
        "errorType": "Functional"
    }
]

MIRROR_RESPONSE_GET_INCIDENT_ACTIVITY_HISTORY = {
    "status": "OK",
    "messages": [
        "Get activity stream details for incident ID [2849604490]"
    ],
    "result": {
        "activityStreamData": [
            {
                "caseid": "2849604490",
                "actiontaken": "COMMENTS_ADDED",
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
        ]
    }
}

MIRROR_ENTRIES = [
    {'type': None, 'category': None, 'contents': 'This is a comment', 'contentsFormat': None,
     'tags': ['comments', 'work_notes'], 'note': True, 'user': 'Admin'}
]

MIRROR_RESPONSE_GET_INCIDENT_ACTIVITY_HISTORY_ATTACHMENT = {
    "status": "OK",
    "messages": [
        "Get activity stream details for incident ID [5010212504]"
    ],
    "result": {
        "activityStreamData": [
            {
                "caseid": "1234",
                "actiontaken": "CREATED",
                "status": "Open",
                "comment": [
                    {
                        "Comments": "Incident created while executing playbook - ServiceNow - Create Incident"
                    }
                ],
                "eventTime": "Feb 22, 2023 8:39:50 PM",
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
                "caseid": "1234",
                "actiontaken": "ATTACHED_FILE",
                "eventTime": "Feb 23, 2023 9:45:53 AM",
                "attachment": "test.txt",
                "username": "Crest Team",
                "attachmentType": "doc",
                "isPlayBookOutAvailable": False
            }
        ]
    }
}
