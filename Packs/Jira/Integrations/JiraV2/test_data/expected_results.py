QUERY_ISSUE_RESULT = {'Ticket(val.Id == obj.Id)':
    [
        {
            'Id': '12652', 'Key': 'VIK-3', 'Summary': 'JiraTestMohitM', 'Status': 'To Do', 'Assignee': 'null(null)',
            'Creator': 'jon doe(email)', 'Priority': 'High', 'ProjectName': 'VikTest', 'DueDate': None,
            'Created': '2019-05-04T00:44:31.743+0300', 'Description': 'hello', 'Labels': ['test', 'debug'], 'LastSeen': None,
            'LastUpdate': '2019-05-15T21:24:07.222+0300'
        }
    ]
}
QUERY_ISSUE_RESULT_WITH_CUSTOM_FIELDS = {'Ticket(val.Id == obj.Id)':
    [
        {
            'Id': '12652', 'Key': 'VIK-3', 'Summary': 'JiraTestMohitM', 'Status': 'To Do', 'Assignee': 'null(null)',
            'Creator': 'jon doe(email)', 'Priority': 'High', 'ProjectName': 'VikTest', 'DueDate': None,
            'Created': '2019-05-04T00:44:31.743+0300', 'Description': 'hello', 'Labels': ['test', 'debug'], 'LastSeen': None,
            'LastUpdate': '2019-05-15T21:24:07.222+0300', 'Owner': 'John Doe'
        }
    ]
}
GET_ISSUE_OUTPUTS_RESULT = {'Ticket(val.Id == obj.Id)':
    [
        {
            'Id': '19141', 'Key': 'VIK-238', 'Summary': 'test master1', 'Status': 'To Do', 'Assignee': 'null(null)',
            'Creator': 'jon doe(email)', 'Priority': 'Medium', 'ProjectName': 'VikTest', 'DueDate': None,
            'Created': '2021-04-04T12:25:48.114+0300', 'Description': 'changing again again\n\nagain gain',
            'Labels': [], 'LastSeen': None,
            'LastUpdate': '2021-04-04T12:49:43.546+0300', 'attachment': 'entry_artifact_5@317.json'
        }
    ]
}
GET_ISSUE_OUTPUTS_RESULT_WITH_APPEND = {'Ticket(val.Id == obj.Id)':
    [
        {
            'Id': '19141', 'Key': 'VIK-238', 'Summary': 'test master1', 'Status': 'To Do', 'Assignee': 'null(null)',
            'Creator': 'jon doe(email)', 'Priority': 'Medium', 'ProjectName': 'VikTest', 'DueDate': None,
            'Created': '2021-04-04T12:25:48.114+0300', 'LastSeen': None, 'LastUpdate': '2021-04-04T12:49:43.546+0300',
            'attachment': 'entry_artifact_5@317.json', 'labels': ['New']
        }
    ]
}

GET_JIRA_ISSUE_RES = {
    "id": "17757",
    "key": "VIK-28",
    "fields": {
        "statuscategorychangedate": "2020-12-17T11:43:56.143+0200",
        "issuetype": {
            "description": "A task that needs to be done.",
        },
        "project": {
            "id": "10005",
            "key": "VIK",
            "name": "VikTest"},

        "created": "2020-12-17T11:43:55.776+0200",
        "priority": {
            "name": "High",
            "id": "2"
        },
        "lastViewed": "2020-12-17T12:38:30.006+0200",
        "labels": [

        ],

        "assignee": "None",
        "updated": "2020-12-17T12:38:30.006+0200",
        "status": {
            "name": "To Do",
            "id": "10000"
        },
        "description": "None",
        "security": "None",
        "attachment": [
            "here is attahchment"
        ],
        "summary": "test_out1666",
        "creator": {
            "emailAddress": "email",
            "displayName": "displayName",
        },

        "reporter": {
            "emailAddress": "email",
            "displayName": "displayName",
        },
        "comment": {
            "comments": [

            ],
            "maxResults": 0,
            "total": 0,
            "startAt": 0
        },

    }
}

JIRA_ATTACHMENT = [{'created': '1996-11-25T16:29:37.277764067Z',
                    'content': 'https://localhost/rest/attachment/content/14848',
                    'self': 'https://localhost/rest/attachment/14848', 'filename': 'download.png'}]

JIRA_ATTACHMENT_ALL = [{'created': '1996-11-25T16:29:37.277764067Z',
                        'content': 'https://localhost/rest/attachment/content/14840',
                        'filename': 'filename1',
                        'self': 'https://localhost/rest/attachment/14840'},
                       {'created': '1992-11-25T16:29:37.277764067Z',
                        'content': 'https://localhost/rest/attachment/content/14841',
                        'filename': 'filename2',
                        'self': 'https://localhost/rest/attachment/14841'},
                       {'created': '2170-11-25T16:29:37.277764067Z',
                        'content': 'https://localhost/rest/attachment/content/14842',
                        'filename': 'filename3',
                        'self': 'https://localhost/rest/attachment/14842'}]

ARGS_FROM_UPDATE_REMOTE_SYS = {
    'lastUpdate': '2020-12-14T12:38:30.006+0200',
    'incidentChanged': True,
    'remoteId': '17757',
    'entries': [{'contents': 'text', 'tags': 'comment', 'type': 4}, {'id': 3}],
}
