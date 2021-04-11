QUERY_ISSUE_RESULT = {'Ticket(val.Id == obj.Id)':
    [
        {
            'Id': '12652', 'Key': 'VIK-3', 'Summary': 'JiraTestMohitM', 'Status': 'To Do', 'Assignee': 'null(null)',
            'Creator': 'jon doe(admin@demistodev.com)'
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
            "emailAddress": "admin@demistodev.com",
            "displayName": "Meir Wahnon",
        },

        "reporter": {
            "emailAddress": "admin@demistodev.com",
            "displayName": "Meir Wahnon",
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

JIRA_ATTACHMENT = [{'created': '1996-11-25T16:29:37.277764067Z', "content": "https://demistodev.atlassian.net/secure/attachment/14848/download.png"}]

JIRA_ATTACHMENT_ALL = [{'created': '1996-11-25T16:29:37.277764067Z', "content": "https://demistodev.atlassian.net/secure/attachment/14848/download.png"},
                       {'created': '1992-11-25T16:29:37.277764067Z', "content": "https://demistodev.atlassian.net/secure/attachment/14848/download1.png"},
                       {'created': '2170-11-25T16:29:37.277764067Z', "content": "https://demistodev.atlassian.net/secure/attachment/14848/download2.png"}]

ARGS_FROM_UPDATE_REMOTE_SYS = {
    'lastUpdate': '2020-12-14T12:38:30.006+0200',
    'incidentChanged': True,
    'remoteId': '17757',
    'entries': [{'contents': 'text', 'tags': 'comment', 'type': 4}, {'id': 3}],
}