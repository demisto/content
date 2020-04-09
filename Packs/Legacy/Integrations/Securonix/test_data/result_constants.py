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
                'Watchlisted': False
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
            "Watchlisted": False
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
            'Watchlistname': 'test',
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
    'Securonix.Watchlists(val.Watchlistname === obj.Watchlistname)': 'test234'
}
EXPECTED_ENTITY_IN_WATCHLIST = {
    'Securonix.EntityInWatchlist(val.Entityname === obj.Entityname)': {
        'Watchlistname': 'test234',
        'Entityname': '1002'
    }
}
EXPECTED_ADD_ENTITY_TO_WATCHLIST = {}
