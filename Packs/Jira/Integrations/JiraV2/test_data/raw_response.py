QUERY_ISSUE_RESPONSE = {
    "expand": "names,schema",
    "issues": [
        {
            "expand": "operations,versionedRepresentations,editmeta,changelog,renderedFields",
            "fields": {
                "aggregateprogress": {
                    "progress": 0,
                    "total": 0
                },
                "aggregatetimeestimate": None,
                "aggregatetimeoriginalestimate": None,
                "aggregatetimespent": None,
                "assignee": None,
                "components": [],
                "created": "2019-05-04T00:44:31.743+0300",
                "creator": {
                    "accountId": "557058:fb80ffc0-b374-4260-99a0-ea0c140a4e76",
                    "accountType": "atlassian",
                    "active": True,
                    "avatarUrls": {
                        "16x16": "",
                        "24x24": "",
                        "32x32": "",
                        "48x48": ""
                    },
                    "displayName": "jon doe",
                    "emailAddress": "admin@demistodev.com",
                    "self": "https://demistodev.atlassian.net/rest/api/2/user?accountId=id",
                    "timeZone": "Asia"
                },
                "customfield_10000": "{}",
                "customfield_10001": "John Doe",
                "customfield_10002": None,
                "customfield_10003": None,
                "customfield_10004": None,
                "customfield_10005": None,
                "customfield_10006": None,
                "customfield_10007": None,
                "customfield_10008": None,
                "customfield_10009": None,
                "customfield_10013": None,
                "customfield_10014": None,
                "customfield_10015": {
                    "hasEpicLinkFieldDependency": False,
                    "nonEditableReason": {
                        "message": "The Parent Link is only available to Jira Premium users.",
                        "reason": "PLUGIN_LICENSE_ERROR"
                    },
                    "showField": False
                },
                "customfield_10016": None,
                "customfield_10017": "10000_*:*_1_*:*_1023607418_*|*_10001_*:*_1_*:*_0",
                "customfield_10018": None,
                "customfield_10019": "0|i006cf:",
                "customfield_10022": None,
                "customfield_10023": [],
                "customfield_10024": None,
                "customfield_10025": None,
                "customfield_10027": None,
                "customfield_10029": None,
                "customfield_10031": None,
                "customfield_10032": None,
                "customfield_10033": None,
                "customfield_10034": None,
                "customfield_10035": None,
                "customfield_10036": None,
                "customfield_10037": None,
                "customfield_10038": None,
                "customfield_10039": None,
                "customfield_10040": None,
                "customfield_10041": None,
                "customfield_10042": None,
                "customfield_10043": None,
                "description": "hello",
                "duedate": None,
                "environment": None,
                "fixVersions": [],
                "issuelinks": [],
                "issuetype": {
                    "avatarId": 10318,
                    "description": "A task that needs to be done.",
                    "iconUrl": "a",
                    "id": "10001",
                    "name": "Task",
                    "self": "https://demistodev.atlassian.net/rest/api/2/issuetype/10001",
                    "subtask": False
                },
                "labels": [],
                "lastViewed": None,
                "priority": {
                    "iconUrl": "https://demistodev.atlassian.net/images/icons/priorities/high.svg",
                    "id": "2",
                    "name": "High",
                    "self": "https://demistodev.atlassian.net/rest/api/2/priority/2"
                },
                "progress": {
                    "progress": 0,
                    "total": 0
                },
                "project": {
                    "avatarUrls": {
                        "16x16": "",
                        "24x24": "",
                        "32x32": "",
                        "48x48": ""
                    },
                    "id": "10005",
                    "key": "VIK",
                    "name": "VikTest",
                    "projectTypeKey": "software",
                    "self": "https://demistodev.atlassian.net/rest/api/2/project/10005",
                    "simplified": False
                },
                "reporter": {
                    "accountId": "557058:fb80ffc0-b374-4260-99a0-ea0c140a4e76",
                    "accountType": "atlassian",
                    "active": True,
                    "avatarUrls": {
                        "16x16": "",
                        "24x24": "",
                        "32x32": "",
                        "48x48": ""
                    },
                    "displayName": "Meir Wahnon",
                    "emailAddress": "admin@demistodev.com",
                    "self": "https://demistodev.atlassian.net/rest/api/2/user?accountId=id",
                    "timeZone": "Asia/Jerusalem"
                },
                "resolution": {
                    "description": "Work has been completed on this issue.",
                    "id": "10000",
                    "name": "Done",
                    "self": "https://demistodev.atlassian.net/rest/api/2/resolution/10000"
                },
                "resolutiondate": "2019-05-15T21:04:39.147+0300",
                "security": None,
                "status": {
                    "description": "",
                    "iconUrl": "https://demistodev.atlassian.net/images/icons/status_generic.gif",
                    "id": "10000",
                    "name": "To Do",
                    "self": "https://demistodev.atlassian.net/rest/api/2/status/10000",
                    "statusCategory": {
                        "colorName": "blue-gray",
                        "id": 2,
                        "key": "new",
                        "name": "To Do",
                        "self": "https://demistodev.atlassian.net/rest/api/2/statuscategory/2"
                    }
                },
                "statuscategorychangedate": "2019-05-15T21:24:07.222+0300",
                "subtasks": [],
                "summary": "JiraTestMohitM",
                "timeestimate": None,
                "timeoriginalestimate": None,
                "timespent": None,
                "updated": "2019-05-15T21:24:07.222+0300",
                "versions": [],
                "votes": {
                    "hasVoted": False,
                    "self": "https://demistodev.atlassian.net/rest/api/2/issue/VIK-3/votes",
                    "votes": 0
                },
                "watches": {
                    "isWatching": True,
                    "self": "https://demistodev.atlassian.net/rest/api/2/issue/VIK-3/watchers",
                    "watchCount": 1
                },
                "workratio": -1
            },
            "id": "12652",
            "key": "VIK-3",
            "self": "https://demistodev.atlassian.net/rest/api/latest/issue/12652"
        }
    ],
    "maxResults": 1,
    "startAt": 0,
    "total": 1115
}

GET_ISSUE_RESPONSE = {
    'expand': 'renderedFields,names,schema,operations,editmeta,changelog,versionedRepresentations,customfield_10022.requestTypePractice',
    'id': '19141', 'key': 'VIK-238',
    'fields': {'statuscategorychangedate': '2021-04-04T12:25:48.335+0300',
               'issuetype': {'id': '10001',
                             'description': 'A task that needs to be done.',
                             'name': 'Task', 'subtask': False, 'avatarId': 10318, 'hierarchyLevel': 0},
               'timespent': None,
               'project': {'id': '10005',
                           'key': 'VIK', 'name': 'VikTest', 'projectTypeKey': 'software', 'simplified': False,
                           'avatarUrls': {
                               '48x48': ''}},
               'customfield_10031': None, 'customfield_10032': None, 'fixVersions': [],
               'customfield_10033': None,
               'customfield_10034': None, 'aggregatetimespent': None, 'resolution': None,
               'customfield_10035': None,
               'customfield_10036': None, 'customfield_10037': None, 'customfield_10027': None,
               'customfield_10029': None, 'resolutiondate': None, 'workratio': -1, 'lastViewed': None,
               'issuerestriction': {'issuerestrictions': {}, 'shouldDisplay': False},
               'watches': {'self': '',
                           'watchCount': 1, 'isWatching': True},
               'created': '2021-04-04T12:25:48.114+0300',
               'customfield_10022': None,
               'priority': {'self': '',
                            'iconUrl': '',
                            'name': 'Medium', 'id': '3'}, 'customfield_10023': [],
               'customfield_10024': None, 'customfield_10025': None, 'labels': [],
               'customfield_10016': None,
               'customfield_10017': None, 'customfield_10018': None, 'customfield_10019': '0|i00g5j:',
               'aggregatetimeoriginalestimate': None, 'timeestimate': None, 'versions': [],
               'issuelinks': [],
               'assignee': None, 'updated': '2021-04-04T12:49:43.546+0300',
               'status': {'self': '',
                          'description': '',
                          'iconUrl': '',
                          'name': 'To Do', 'id': '10000',
                          'statusCategory': {
                              'self': '',
                              'id': 2, 'key': 'new', 'colorName': 'blue-gray', 'name': 'To Do'}},
               'components': [], 'timeoriginalestimate': None,
               'description': 'changeing again again\n\nagain gain',
               'customfield_10013': None, 'customfield_10014': None,
               'customfield_10015': {'hasEpicLinkFieldDependency': False, 'showField': False,
                                     'nonEditableReason': {'reason': 'PLUGIN_LICENSE_ERROR',
                                                           'message': 'The Parent Link is only available to Jira Premium users.'}},
               'timetracking': {}, 'customfield_10005': None, 'customfield_10006': None,
               'security': None,
               'customfield_10007': None, 'customfield_10008': None, 'customfield_10009': None,
               'attachment': [
                   {'self': '',
                    'content': 'https://someurl.com',
                    'id': '15451',
                    'filename': 'entry_artifact_5@317.json', 'author': {
                       'accountId': '557058:fb80ffc0-b374-4260-99a0-ea0c140a4e76',
                       'emailAddress': 'admin@demistodev.com',
                       'avatarUrls': {
                           '48x48': ''},
                       'displayName': 'Meir Wahnon', 'active': True, 'timeZone': 'Asia/Jerusalem',
                       'accountType': 'atlassian'},
                    'created': '2021-04-04T12:49:42.881+0300', 'size': 8225,
                    'mimeType': 'application/json',
                    }],
               'aggregatetimeestimate': None, 'summary': 'test master1', 
               'creator': {
                    "accountId": "557058:fb80ffc0-b374-4260-99a0-ea0c140a4e76",
                    "accountType": "atlassian",
                    "active": True,
                    "avatarUrls": {
                        "16x16": "",
                        "24x24": "",
                        "32x32": "",
                        "48x48": ""
                    },
                    "displayName": "jon doe",
                    "emailAddress": "admin@demistodev.com",
                    "self": "https://demistodev.atlassian.net/rest/api/2/user?accountId=id",
                    "timeZone": "Asia"
                }
    }
}

FIELDS_RESPONSE = [
    {'id': 'customfield_10001', 'key': 'customfield_10001', 'name': 'Owner', 'untranslatedName': 'Owner',
     'custom': True, 'orderable': True, 'navigable': True, 'searchable': True,
     'clauseNames': ['cf[10001]', 'Owner', 'Owner[User Picker (single user)]'],
     'schema': {'type': 'user', 'custom': 'com.atlassian.jira.plugin.system.customfieldtypes:userpicker',
                'customId': 10001}},
    {'id': 'resolution', 'key': 'resolution', 'name': 'Resolution', 'custom': False, 'orderable': True, 'navigable': True, 'searchable': True, 'clauseNames': ['resolution'], 'schema': {'type': 'resolution', 'system': 'resolution'}},
    {'id': 'resolutiondate', 'key': 'resolutiondate', 'name': 'Resolved', 'custom': False, 'orderable': False, 'navigable': True, 'searchable': True, 'clauseNames': ['resolutiondate', 'resolved'], 'schema': {'type': 'datetime', 'system': 'resolutiondate'}}
]

EXPECTED_RESP={
    'customfield_10001': 'Owner',
    'resolution': 'Resolution',
    'resolutiondate': 'Resolved'
}

GET_ISSUE_WITH_ATTACHMENT_RESPONSE = {
    "expand": "renderedFields,names,schema,operations,editmeta,changelog,versionedRepresentations,customfield_10022.requestTypePractice",
    "id": "20852",
    "self": "https://demistodev.atlassian.net/rest/api/latest/issue/20852",
    "key": "VIK-267",
    "fields": {
        "statuscategorychangedate": "2021-11-17T12:40:09.977+0200",
        "fixVersions": [],
        "lastViewed": "2022-02-14T11:58:21.161+0200",
        "priority": {
            "self": "https://demistodev.atlassian.net/rest/api/2/priority/3",
            "iconUrl": "https://demistodev.atlassian.net/images/icons/priorities/medium.svg",
            "name": "Medium",
            "id": "3"
        },
        "labels": [],
        "aggregatetimeoriginalestimate": None,
        "timeestimate": None,
        "versions": [],
        "issuelinks": [],
        "assignee": None,
        "status": {
            "self": "https://demistodev.atlassian.net/rest/api/2/status/10000",
            "description": "",
            "iconUrl": "https://demistodev.atlassian.net/images/icons/status_generic.gif",
            "name": "To Do",
            "id": "10000",
            "statusCategory": {
                "self": "https://demistodev.atlassian.net/rest/api/2/statuscategory/2",
                "id": 2,
                "key": "new",
                "colorName": "blue-gray",
                "name": "To Do"
            }
        },
        "components": [],
        "creator": {
            "self": "https://demistodev.atlassian.net/rest/api/2/user?accountId=557058%3Afb80ffc0-b374-4260-99a0-ea0c140a4e76",
            "accountId": "557058:fb80ffc0-b374-4260-99a0-ea0c140a4e76",
            "emailAddress": "email",
            "avatarUrls": {
            },
            "displayName": "name",
            "active": True,
            "timeZone": "Asia/Jerusalem",
            "accountType": "atlassian"
        },
        "subtasks": [],
        "reporter": {
            "self": "https://demistodev.atlassian.net/rest/api/2/user?accountId=557058%3Afb80ffc0-b374-4260-99a0-ea0c140a4e76",
            "accountId": "account id",
            "emailAddress": "admin@demistodev.com",
            "avatarUrls": {
            },
            "displayName": "name",
            "active": True,
            "timeZone": "Asia/Jerusalem",
            "accountType": "atlassian"
        },
        "aggregateprogress": {
            "progress": 0,
            "total": 0
        },
        "progress": {
            "progress": 0,
            "total": 0
        },
        "votes": {
            "self": "https://demistodev.atlassian.net/rest/api/2/issue/VIK-267/votes",
            "votes": 0,
            "hasVoted": False
        },
        "worklog": {
            "startAt": 0,
            "maxResults": 20,
            "total": 0,
            "worklogs": []
        },
        "issuetype": {
            "self": "https://demistodev.atlassian.net/rest/api/2/issuetype/10001",
            "id": "10001",
            "description": "A task that needs to be done.",
            "iconUrl": "https://demistodev.atlassian.net/rest/api/2/universal_avatar/view/type/issuetype/avatar/10318?size=medium",
            "name": "Task",
            "subtask": False,
            "avatarId": 10318,
            "hierarchyLevel": 0
        },
        "timespent": None,
        "project": {
            "self": "https://demistodev.atlassian.net/rest/api/2/project/10005",
            "id": "10005",
            "key": "VIK",
            "name": "VikTest",
            "projectTypeKey": "software",
            "simplified": False,
            "avatarUrls": {}
        },

        "workratio": -1,
        "issuerestriction": {
            "issuerestrictions": {},
            "shouldDisplay": False
        },
        "watches": {
            "self": "https://demistodev.atlassian.net/rest/api/2/issue/VIK-267/watchers",
            "watchCount": 1,
            "isWatching": True
        },
        "created": "2021-11-17T12:40:08.900+0200",

        "customfield_10019": "0|i00i5b:",
        "updated": "2022-01-04T15:51:01.316+0200",
        "timeoriginalestimate": None,
        "description": "galb1 [^test11.py]  [^test] ",

        "customfield_10015": {
            "hasEpicLinkFieldDependency": False,
            "showField": False,
            "nonEditableReason": {
                "reason": "PLUGIN_LICENSE_ERROR",
                "message": "The Parent Link is only available to Jira Premium users."
            }
        },
        "timetracking": {},
        "attachment": [
            {"self": "https://demistodev.atlassian.net/rest/api/2/attachment/16188",
             "id": "16188",
             "filename": "test",
             "author": {
                 "self": "https://demistodev.atlassian.net/rest/api/2/user?accountId=557058%3Afb80ffc0-b374-4260-99a0-ea0c140a4e76",
                 "accountId": "account id",
                 "emailAddress": "mail",
                 "avatarUrls": {},
                 "displayName": "name",
                 "active": True,
                 "timeZone": "Asia/Jerusalem",
                 "accountType": "atlassian"
             },
             "created": "2021-11-17T12:40:06.700+0200",
             "size": 4,
             "mimeType": "binary/octet-stream",
             "content": "https://demistodev.atlassian.net/rest/api/2/attachment/content/16188"}
        ]
        }
    }

MD_AND_CONTEXT_OUTPUT = {
    'md': [
        {'id': '20852',
         'key': 'VIK-267',
         'summary': 'o767676',
         'status': 'To Do',
         'priority': 'Medium',
         'project': 'VikTest',
         'duedate': None,
         'created': '2021-11-17T12:40:08.900+0200',
         'assignee': 'null(null)',
         'creator': 'creator',
         'reporter': 'reporter',
         'issueType': 'A task that needs to be done.',
         'labels': [],
         'description': 'galb1 [^test11.py]  [^test] ',
         'ticket_link': 'link',
         'attachment': 'test,test11.py'}
        ],
    'context': [
        {'Id': '20852',
         'Key': 'VIK-267',
         'Summary': 'o767676',
         'Status': 'To Do',
         'Priority': 'Medium',
         'ProjectName': 'VikTest',
         'DueDate': None,
         'Created': '2021-11-17T12:40:08.900+0200',
         'Assignee': 'null(null)',
         'Creator': 'creator',
         'LastSeen': '2022-02-14T11:58:21.161+0200',
         'LastUpdate': '2022-01-04T15:51:01.316+0200',
         'attachment': 'test,test11.py'
         }
    ]
}
