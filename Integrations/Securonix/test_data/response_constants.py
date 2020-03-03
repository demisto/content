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
                    "watchlisted": False
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
