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
    'Securonix.Workflows(val.Workflow == obj.Workflow)': {
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
    'Securonix.Users(val.EmployeeId === obj.EmployeeId)':
        {
            'ApproverEmployeeId': ['1082', '1082'],
            'CostCenterCode': ['ILEGCCC13', 'ILEGCCC13'],
            'Criticality': ['Low', 'Low'],
            'Department': ['SAP Administrator', 'Legal Department'],
            'Division': ['Global Technology', 'Legal'],
            'Email': ['tan.gul@scnx.com', 'Lauren.Clarke@scnx.com'],
            'EmployeeId': ['1644', '1631'],
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
    'Securonix.Incidents(val.IncidentId === obj.IncidentId)':
        [
            {
                'ViolatorText': 'Cyndi Converse',
                'LastUpdateDate': 1566293234026,
                'ViolatorId': '96',
                'IncidentType': 'RISK MODEL',
                'IncidentId': '100181',
                'IncidentStatus': 'COMPLETED',
                'Riskscore': 0.0,
                'AssignedUser': 'Account Access 02',
                'AssignedGroup': 'Administrators',
                'Priority': 'None',
                'Reason': ['Resource: Symantec Email DLP'],
                'ViolatorSubText': '1096',
                'Entity': 'Users',
                'WorkflowName': 'SOCTeamReview',
                'Url': 'https://saaspocapp2t14wptp.securonix.net/Snypr/'
                       'configurableDashboards/view?&type=incident&id=100181',
                'IsWhitelisted': False,
                'Watchlisted': False
            }
        ]
}
