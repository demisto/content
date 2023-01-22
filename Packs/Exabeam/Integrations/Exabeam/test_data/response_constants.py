RESPONSE_PEER_GROUPS = [
    "Marketing",
    "usa",
    "101",
    "Program Manager",
    "Channel Administrator",
    "Chief Marketing Officer",
    "",
    "Chief Strategy Officer",
    "CN=Andrew",
    "BitLockerUsersComputers"
]
RESPONSE_USER_LABELS = [
    "privileged_user",
    "service_account"
]
RESPONSE_WATCHLISTS = [
    {
        "category": "UserLabels",
        "title": "Executive Users",
        "watchlistId": "1234"
    },
    {
        "category": "UserLabels",
        "title": "Service Accounts",
        "watchlistId": "1111"
    },
    {
        "category": "Users",
        "title": "user watchlist",
        "watchlistId": "2222"
    },
    {
        "category": "PeerGroups",
        "title": "VP Operations",
        "watchlistId": "3333"
    }
]
RESPONSE_ASSET_DATA = {
    "asset": {
        "assetType": "Windows",
        "compromisedTime": 0,
        "firstSeen": 1530627660000,
        "hostName": "name",
        "ipAddress": "1.2.3.4",
        "lastSeen": 1538324597000
    }
}

RESPONSE_SESSION_INFO = { 'sessionInfo': {
        "numOfAssets": 29,
        "riskScore": 0,
        "numOfAccounts": 1,
        "accounts": [],
        "zones": [],
        "endTime": "1591071360000",
        "numOfZones": 5,
        "startTime": "1591021860000",
        "loginHost": "lt-dummy-888",
        "sessionId": "dummy-20200601143100",
        "numOfReasons": 0,
        "label": "",
        "username": "dummy",
        "numOfSecurityEvents": 0,
        "numOfEvents": 62,
        "initialRiskScore": 0
    }
}

RESPONSE_MODEL_DATA = {
    "agingWindow": 32,
    "alpha": 0.8,
    "binWidth": None,
    "category": "Other",
    "convergenceFilter": "confidence_factor>=0.8",
    "cutOff": 5,
    "description": "Models which security groups users are being added to in the organization",
    "disabled": "FALSE",
    "feature": "group_name",
    "featureName": "group_name",
    "featureType": "group_name",
    "histogramEventTypes": "member-added",
    "iconName": None,
    "maxNumberOfBins": 1000000,
    "modelTemplate": "Account management, groups which users are being added to",
    "modelType": "CATEGORICAL",
    "name": "dummy",
    "scopeType": "ORG",
    "scopeValue": "org",
    "trainIf": "TRUE"
}

RESPONSE_NOTABLE_ASSET_DATA = {
    'assets': [{
        'asset': {
            'hostName': 'host',
            'ipAddress': '1.1.1.1',
            'assetType': 'test',
            'firstSeen': 1591022160000,
            'lastSeen': 1593820320000
        },
        'highestRiskScore': 150,
        'highestRiskSequence': {
            'id': '1111',
            'entityName': 'asset',
            'entityValue': 'test',
            'day': 1593648000000,
            'triggeredRuleCountOpt': 15,
            'riskScoreOpt': 150.0
        },
        'latestAssetComment': {
            'commentId': 'test1111',
            'commentType': 'asset',
            'commentObjectId': 'test',
            'text': 'test',
            'exaUser': 'test',
            'exaUserFullname': '',
            'createTime': 1612275291188,
            'updateTime': 1612275291188,
            'edited': False
        }
    }]
}

RESPONSE_NOTABLE_SESSION_DETAILS = {
    'totalCount': 2, 'sessions': [
        {'sessionId': 'session1', 'username': 'username1', 'startTime': 1593704040000,
         'endTime': 1593727380000, 'initialRiskScore': 0, 'riskScore': 110, 'numOfReasons': 9,
         'loginHost': 'host1', 'label': '', 'accounts': ['account1', 'account2'], 'numOfAccounts': 2,
         'zones': ['zone1', 'zone2'], 'numOfZones': 2, 'numOfAssets': 7, 'numOfEvents': 6,
         'numOfSecurityEvents': 0},
        {'sessionId': 'session2', 'username': 'username2', 'startTime': 1593682380000,
         'endTime': 1593727260000, 'initialRiskScore': 26, 'riskScore': 313, 'numOfReasons': 39, 'loginHost': 'host2',
         'label': '', 'accounts': ['account1', 'account2'], 'numOfAccounts': 2,
         'zones': ['zone1', 'zone2', 'zone3', 'zone4'], 'numOfZones': 4,
         'numOfAssets': 17, 'numOfEvents': 30, 'numOfSecurityEvents': 1, 'riskTransferScore': 126.0}],
     'users': {
         'username2': {'username': 'username2', 'riskScore': 313.18, 'averageRiskScore': 171.41,
                       'pastScores': [287.19, 218.36, 0.0, 0.0, 0.0, 0.0, 0.0], 'lastSessionId': 'session2',
                       'firstSeen': 1591021500000, 'lastSeen': 1593820320000, 'lastActivityType': 'Account is active',
                       'lastActivityTime': 1593818940000,
                       'info': {'location': 'us',
                                'photo': '',
                                'phoneCell': '1234567890',
                                'email': 'test@.com',
                                'employeeType': 'employee', 'fullName': 'user username2',
                                'departmentNumber': '000',
                                'dn': 'test',
                                'country': 'usa', 'division': 'division',
                                'department': 'department',
                                'manager': 'test',
                                'phoneOffice': '1234567890',
                                'employeeNumber': '1234',
                                'title': 'title',
                                'group': 'test'},
                       'labels': [],
                       'pendingRiskTransfers': []},
        'mburgess': {'username': 'username1', 'riskScore': 109.73, 'averageRiskScore': 52.25,
                     'pastScores': [109.7382543963077], 'lastSessionId': 'session1',
                     'firstSeen': 1591025220000, 'lastSeen': 1593727380000, 'lastActivityType': 'Account is active',
                     'lastActivityTime': 1593704040000,
                     'info': {'location': 'us',
                              'photo': '',
                              'phoneCell': '1234567890',
                              'email': 'test@.com',
                              'employeeType': 'employee',
                              'fullName': 'user username1', 'departmentNumber': '000',
                              'dn': 'test',
                              'country': 'usa', 'division': 'division',
                              'department': 'department',
                              'manager': 'test',
                              'phoneOffice': '1234567890',
                              'employeeNumber': '1234',
                              'title': 'title',
                              'group': 'test'}, 'labels': [],
                     'pendingRiskTransfers': []}},
     'executiveUserFlags': {'username1': False, 'username2': False}
}

RESPONSE_NOTABLE_SEQUENCE_DETAILS = [{
    'sequenceId': 'ID',
    'isWhitelisted': False,
    'areAllTriggeredRulesWhiteListed': False,
    'sequenceInfo': {
        'startTime': 1593648000000,
        'endTime': 1593734399999,
        'riskScore': 150,
        'numOfReasons': 8,
        'numOfEvents': 18,
        'numOfUsers': 4,
        'numOfSecurityEvents': 0,
        'numOfZones': 3,
        'numOfAssets': 8,
        'sequenceId': 'ID',
        'assetId': 'ID'},
    'hasBeenPartiallyWhiteListed': False
}]

RESPONSE_NOTABLE_SEQUENCE_EVENTS = [{
    'eventType': 'type1',
    'displayName': 'dn1',
    'count': 1},
    {'eventType': 'type2',
     'displayName': 'dn2',
     'count': 1},
    {'eventType': 'type3',
     'displayName': 'dn3',
     'count': 1},
    {'eventType': 'type4',
     'displayName': 'dn4',
     'count': 1},
    {'eventType': 'type5',
     'displayName': 'dn5',
     'count': 2},
    {'eventType': 'type6',
     'displayName': 'dn6',
     'count': 2},
    {'eventType': 'type7',
     'displayName': 'dn7',
     'count': 8},
    {'eventType': 'type8',
     'displayName': 'dn8',
     'count': 1},
    {'eventType': 'type9',
     'displayName': 'dn9',
     'count': 1}
]

DELETE_RECORD_RESPONSE = {'sessionId': '56a5b19a-4193-4616-9978-0bbabb1e2d60',
                          'recordChanges': [{
                              'changeType': 'removed',
                              'changeId': '4aad5392-20e7-4423-abcb-a9680c566215',
                              'record': {'key': '', 'id': 'test_key'}
                          }],
                          'metadata': {'createdSize': 0, 'updatedSize': 0, 'removedSize': 1, 'duplicates': []}}


RESPONSE_INCIDENT_LIST = {'totalCount': 341, 'offset': 0, 'count': 1, 'maxCount': 10000,
                          'incidents': [{'incidentId': 'SOC-19', 'name': 'phil: Notable AA Session',
                                         'fields': {'updatedAt': 1608020359407, 'priority': 'medium',
                                                    'source': 'Exabeam AA', 'queue': '1', 'startedDate': 1607999470130,
                                                    'incidentType': ['generic', 'ueba'], 'status': 'new',
                                                    'createdAt': 1608020359194, 'createdBy': 'admin',
                                                    'owner': 'unassigned', 'vendor': 'Exabeam', 'updatedBy': 'admin',
                                                    'restrictTo': None, 'sourceId': 'phil-20201215023110'}}]}

