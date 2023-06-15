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
                    "emailAddress": "email",
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
                    "self": "https://localhost/rest/api/2/issuetype/10001",
                    "subtask": False
                },
                "labels": ['test', 'debug'],
                "lastViewed": None,
                "priority": {
                    "iconUrl": "https://localhost/images/icons/priorities/high.svg",
                    "id": "2",
                    "name": "High",
                    "self": "https://localhost/rest/api/2/priority/2"
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
                    "self": "https://localhost/rest/api/2/project/10005",
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
                    "displayName": "displayName",
                    "emailAddress": "email",
                    "self": "https://localhost/rest/api/2/user?accountId=id",
                    "timeZone": "Asia/Jerusalem"
                },
                "resolution": {
                    "description": "Work has been completed on this issue.",
                    "id": "10000",
                    "name": "Done",
                    "self": "https://localhost/rest/api/2/resolution/10000"
                },
                "resolutiondate": "2019-05-15T21:04:39.147+0300",
                "security": None,
                "status": {
                    "description": "",
                    "iconUrl": "https://localhost/images/icons/status_generic.gif",
                    "id": "10000",
                    "name": "To Do",
                    "self": "https://localhost/rest/api/2/status/10000",
                    "statusCategory": {
                        "colorName": "blue-gray",
                        "id": 2,
                        "key": "new",
                        "name": "To Do",
                        "self": "https://localhost/rest/api/2/statuscategory/2"
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
                    "self": "https://localhost/rest/api/2/issue/VIK-3/votes",
                    "votes": 0
                },
                "watches": {
                    "isWatching": True,
                    "self": "https://localhost/rest/api/2/issue/VIK-3/watchers",
                    "watchCount": 1
                },
                "workratio": -1
            },
            "id": "12652",
            "key": "VIK-3",
            "self": "https://localhost/rest/api/latest/issue/12652"
        }
    ],
    "maxResults": 1,
    "startAt": 0,
    "total": 1115
}

GET_ISSUE_RESPONSE = {
    'expand': 'renderedFields,names,schema,operations,editmeta,changelog,versionedRepresentations,customfield_10022.requestTypePractice',
    'id': '19141', 'key': 'VIK-238',
    'fields': {
        'statuscategorychangedate': '2021-04-04T12:25:48.335+0300',
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
        'description': 'changing again again\n\nagain gain',
        'customfield_10013': None, 'customfield_10014': None,
        'customfield_10015': {'hasEpicLinkFieldDependency': False, 'showField': False,
                              'nonEditableReason': {'reason': 'PLUGIN_LICENSE_ERROR',
                                                    'message': 'The Parent Link is only available to Jira Premium users.'}},
        'timetracking': {}, 'customfield_10005': None, 'customfield_10006': None,
        'security': None,
        'customfield_10007': None, 'customfield_10008': None, 'customfield_10009': None,
        'attachment': [
            {'self': 'https://localhost/rest/attachment/15451',
             'content': 'https://localhost/rest/attachment/content/15451',
             'id': '15451',
             'filename': 'entry_artifact_5@317.json', 'author': {
                'accountId': 'accountid',
                'emailAddress': 'email',
                'avatarUrls': {
                    '48x48': ''},
                'displayName': 'displayName', 'active': True, 'timeZone': 'Asia/Jerusalem',
                'accountType': 'atlassian'},
             'created': '2021-04-04T12:49:42.881+0300', 'size': 8225,
             'mimeType': 'application/json',
             }],
        'aggregatetimeestimate': None, 'summary': 'test master1',
        'creator': {
            'accountId': 'accountid',
            'accountType': 'atlassian',
            'active': True,
            'avatarUrls': {
                '16x16': '',
                '24x24': '',
                '32x32': '',
                '48x48': ''
            },
            'displayName': 'jon doe',
            'emailAddress': 'email',
            'self': 'https://localhost/rest/api/2/user?accountId=id',
            'timeZone': 'Asia'
        }
    }
}

GET_ISSUE_RESPONSE_WITH_LABELS = {
    'expand': 'renderedFields,names,schema,operations,editmeta,changelog,versionedRepresentations,customfield_10022.requestTypePractice',
    'id': '19141', 'key': 'VIK-238',
    'fields': {
        'statuscategorychangedate': '2021-04-04T12:25:48.335+0300',
        'issuetype': {'id': '10001',
                      'description': 'A task that needs to be done.',
                      'name': 'Task', 'subtask': False, 'avatarId': 10318, 'hierarchyLevel': 0},
        'timespent': None,
        'project': {'id': '10005',
                    'key': 'VIK', 'name': 'VikTest', 'projectTypeKey': 'software', 'simplified': False,
                    'avatarUrls': {
                        '48x48': ''}},
        'issuerestriction': {'issuerestrictions': {}, 'shouldDisplay': False},
        'watches': {'self': '',
                    'watchCount': 1, 'isWatching': True},
        'created': '2021-04-04T12:25:48.114+0300',
        'customfield_10022': None,
        'priority': {'self': '',
                     'iconUrl': '',
                     'name': 'Medium', 'id': '3'}, 'labels': ['test'],
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
        'description': 'changing again again\n\nagain gain',
        'creator': {
            'accountId': 'accountid',
            'accountType': 'atlassian',
            'active': True,
            'avatarUrls': {
                '16x16': '',
                '24x24': '',
                '32x32': '',
                '48x48': ''
            },
            'displayName': 'jon doe',
            'emailAddress': 'email',
            'self': 'https://localhost/rest/api/2/user?accountId=id',
            'timeZone': 'Asia'
        }
    }
}


FIELDS_RESPONSE = [
    {'id': 'customfield_10001', 'key': 'customfield_10001', 'name': 'Owner', 'untranslatedName': 'Owner',
     'custom': True, 'orderable': True, 'navigable': True, 'searchable': True,
     'clauseNames': ['cf[10001]', 'Owner', 'Owner[User Picker (single user)]'],
     'schema': {'type': 'user', 'custom': 'com.atlassian.jira.plugin.system.customfieldtypes:userpicker',
                'customId': 10001}},
    {'id': 'resolution', 'key': 'resolution', 'name': 'Resolution', 'custom': False, 'orderable': True,
     'navigable': True, 'searchable': True, 'clauseNames': ['resolution'],
     'schema': {'type': 'resolution', 'system': 'resolution'}},
    {'id': 'resolutiondate', 'key': 'resolutiondate', 'name': 'Resolved', 'custom': False, 'orderable': False,
     'navigable': True, 'searchable': True, 'clauseNames': ['resolutiondate', 'resolved'],
     'schema': {'type': 'datetime', 'system': 'resolutiondate'}}
]

EXPECTED_RESP = {
    'customfield_10001': 'Owner',
    'resolution': 'Resolution',
    'resolutiondate': 'Resolved'
}

ATTACHMENTS = {
    "cloud_attachment": {
        "self": "https://localhost/rest/api/2/attachment/16188",
        "id": "16188",
        "filename": "filename",
        "author": {
            "self": "https://localhost/rest/api/2/user?accountId=557058%3Afb80ffc0-b374-4260-99a0"
                    "-ea0c140a4e76",
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
        "content": "https://localhost/rest/api/2/attachment/content/16188"
    },
    "on_prem_attachment": {
        "self": "https://localhost/rest/api/2/attachment/18447",
        "id": "16188",
        "filename": "filename",
        "author": {
            "self": "https://localhost/rest/api/2/user?accountId=557058%3Afb80ffc0-b374-4260-99a0"
                    "-ea0c140a4e76",
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
        "content": "https://localhost/secure/attachment/18447/filename"
    }
}


ORGANIZATIONS = {
    "_links": {
        "base": "https://demistodev.atlassian.net",
        "context": "",
        "self": "https://demistodev.atlassian.net/rest/servicedeskapi/organization"
    },
    "isLastPage": True,
    "limit": 50,
    "size": 2,
    "start": 0,
    "values": [
        {
            "_links": {
                "self": "https://demistodev.atlassian.net/rest/servicedeskapi/organization/23"
            },
            "id": "23",
            "name": "TEST"
        },
        {
            "_links": {
                "self": "https://demistodev.atlassian.net/rest/servicedeskapi/organization/4"
            },
            "id": "4",
            "name": "XSOAR"
        }
    ]
}


PROJECT_ROLES = {
    "Agent":"https://demistodev.atlassian.net/rest/api/2/project/10804/role/11824",
    "Administrator":"https://demistodev.atlassian.net/rest/api/2/project/10804/role/11823",
}


PROJECT_ROLE = {
  "self": "https://demistodev.atlassian.net/rest/api/2/project/10804/role/11823",
  "name": "Administrator",
  "id": 11823,
  "description": "Admins can do most things, like update settings and add other admins.",
  "actors": [
    {
      "id": 44432,
      "displayName": "XSOAR",
      "type": "atlassian-user-role-actor",
      "actorUser": {
        "accountId": "123456789"
      }
    },
    {
      "id": 44430,
      "displayName": "Demisto",
      "type": "atlassian-user-role-actor",
      "actorUser": {
        "accountId": "987654321"
      }
    }
  ],
  "scope": {
    "type": "PROJECT",
    "project": {
      "id": "10804"
    }
  }
}
