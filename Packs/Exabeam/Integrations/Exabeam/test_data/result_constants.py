EXPECTED_PEER_GROUPS = {
    'Exabeam.PeerGroup(val.Name && val.Name === obj.Name)': [
        {'Name': "Marketing"},
        {'Name': "usa"},
        {'Name': "101"},
        {'Name': "Program Manager"},
        {'Name': "Channel Administrator"},
        {'Name': "Chief Marketing Officer"},
        {'Name': ""},
        {'Name': "Chief Strategy Officer"},
        {'Name': "CN=Andrew"},
        {'Name': "BitLockerUsersComputers"}
    ]
}
EXPECTED_USER_LABELS = {
    'Exabeam.UserLabel(val.Label && val.Label === obj.Label)': [
        {'Label': 'privileged_user'},
        {'Label': 'service_account'}
    ]
}
EXPECTED_WATCHLISTS = {
    'Exabeam.Watchlist(val.WatchlistID && val.WatchlistID === obj.WatchlistID)': [
        {'WatchlistID': '1234', 'Title': 'Executive Users', 'Category': 'UserLabels'},
        {'WatchlistID': '1111', 'Title': 'Service Accounts', 'Category': 'UserLabels'},
        {'WatchlistID': '2222', 'Title': 'user watchlist', 'Category': 'Users'},
        {'WatchlistID': '3333', 'Title': 'VP Operations', 'Category': 'PeerGroups'}
    ]
}
EXPECTED_ASSET_DATA = {
    'Exabeam.Asset(val.IPAddress && val.IPAddress === obj.IPAddress)': {
        'HostName': 'name',
        'IPAddress': '1.2.3.4',
        'AssetType': 'Windows',
        'FirstSeen': '2018-07-03T14:21:00',
        'LastSeen': '2018-09-30T16:23:17',
        'Labels': None
    }
}
EXPECTED_SESSION_INFO = {
    'Exabeam.SessionInfo(val.sessionId && val.sessionId === obj.sessionId)': {
        "numOfAssets": 29,
        "riskScore": 0,
        "numOfAccounts": 1,
        "accounts": [],
        "zones": [],
        "endTime": "2020-06-02T04:16:00",
        "numOfZones": 5,
        "startTime": "2020-06-01T14:31:00",
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

EXPECTED_MODEL_DATA = {
    'Exabeam.Model(val.name && val.name === obj.name)': {
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
}

EXPECTED_NOTABLE_ASSET_DATA = {
    'Exabeam.NotableAsset((val.ipAddress && val.ipAddress === obj.ipAddress) '
    '|| (val.hostName && val.hostName === obj.hostName))': [{
        'highestRiskScore': 150,
        'id': '1111',
        'entityName': 'asset',
        'entityValue': 'test',
        'day': '2020-07-02T00:00:00',
        'triggeredRuleCountOpt': 15,
        'riskScoreOpt': 150.0,
        'commentId': 'test1111',
        'commentType': 'asset',
        'commentObjectId': 'test',
        'text': 'test',
        'exaUser': 'test',
        'createTime': '2021-02-02T14:14:51.188000',
        'updateTime': '2021-02-02T14:14:51.188000',
        'edited': False,
        'HostName': 'host',
        'IPAddress': '1.1.1.1',
        'AssetType': 'test',
        'FirstSeen': '2020-06-01T14:36:00',
        'LastSeen': '2020-07-03T23:52:00',
        'Labels': None,
        'exaUserFullname': '',
        'zone': None,
        'incidentIds': None
    }]
}

EXPECTED_NOTABLE_SESSION_DETAILS = {
    'Exabeam.NotableSession(val.SessionID && val.SessionID === obj.SessionID)':
        {'sessions': [{
            'SessionID': 'session1',
            'InitialRiskScore': 0,
            'LoginHost': 'host1',
            'Accounts': ['account1', 'account2']},
            {'SessionID': 'session2',
             'InitialRiskScore': 26,
             'LoginHost': 'host2',
             'Accounts': ['account1', 'account2']}],
            'users': [
            {'UserName': 'username2',
             'RiskScore': 313,
             'AverageRiskScore': 171.41,
             'FirstSeen': '2020-06-01T14:25:00',
             'LastSeen': '2020-07-03T23:52:00',
             'lastActivityType': 'Account is active',
             'Labels': [],
             'LastSessionID': 'session2',
             'EmployeeType': 'employee',
             'Department': 'department',
             'Title': 'title',
             'Location': 'us',
             'Email': 'test@.com'},
                {'UserName': 'username1',
                 'RiskScore': 110,
                 'AverageRiskScore': 52.25,
                 'FirstSeen': '2020-06-01T15:27:00',
                 'LastSeen': '2020-07-02T22:03:00',
                 'lastActivityType': 'Account is active',
                 'Labels': [],
                 'LastSessionID': 'session1',
                 'EmployeeType': 'employee',
                 'Department': 'department',
                 'Title': 'title',
                 'Location': 'us',
                 'Email': 'test@.com'}],
            'executiveUserFlags': [
              {'username1': False},
              {'username2': False}]}
}

EXPECTED_NOTABLE_SEQUENCE_DETAILS = {
    'Exabeam.Sequence(val.sequenceId && val.sequenceId === obj.sequenceId)':
        [{'sequenceId': 'ID',
          'isWhitelisted': False,
          'areAllTriggeredRulesWhiteListed': False,
          'hasBeenPartiallyWhiteListed': False,
          'riskScore': 150,
          'startTime': '2020-07-02T00:00:00',
          'endTime': '2020-07-02T23:59:59.999000',
          'numOfReasons': 8,
          'numOfEvents': 18,
          'numOfUsers': 4,
          'numOfSecurityEvents': 0,
          'numOfZones': 3,
          'numOfAssets': 8,
          'assetId': 'ID'}]
}

EXPECTED_NOTABLE_SEQUENCE_EVENTS = {
    'Exabeam.SequenceEventTypes(val.sequenceId && val.sequenceId === obj.sequenceId)':
        [{'eventType': 'type1', 'displayName': 'dn1', 'count': 1, 'sequenceId': None},
         {'eventType': 'type2', 'displayName': 'dn2', 'count': 1, 'sequenceId': None},
         {'eventType': 'type3', 'displayName': 'dn3', 'count': 1, 'sequenceId': None},
         {'eventType': 'type4', 'displayName': 'dn4', 'count': 1, 'sequenceId': None},
         {'eventType': 'type5', 'displayName': 'dn5', 'count': 2, 'sequenceId': None},
         {'eventType': 'type6', 'displayName': 'dn6', 'count': 2, 'sequenceId': None},
         {'eventType': 'type7', 'displayName': 'dn7', 'count': 8, 'sequenceId': None},
         {'eventType': 'type8', 'displayName': 'dn8', 'count': 1, 'sequenceId': None},
         {'eventType': 'type9', 'displayName': 'dn9', 'count': 1, 'sequenceId': None}]
}

EXPECTED_RESULT_AFTER_RECORD_DELETION = {'Exabeam.ContextTableUpdate(val.changeId && val.changeId === obj.changeId)': [
    {'contextTableName': 'test_table',
     'sessionId': '56a5b19a-4193-4616-9978-0bbabb1e2d60',
     'changeType': 'removed',
     'changeId': '4aad5392-20e7-4423-abcb-a9680c566215',
     'record': {'key': '', 'id': 'test_key'}
     }]
}

EXPECTED_INCIDENT_LIST = {'Exabeam.Incident(val.incidentId && val.incidentId === obj.incidentId)':
                          [{'incidentId': 'SOC-19', 'name': 'phil: Notable AA Session',
                            'fields': {'startedDate': '2020-12-15T02:31:10.130000', 'closedDate': None,
                                       'createdAt': '2020-12-15T08:19:19.194000', 'owner': 'unassigned',
                                       'status': 'new', 'incidentType': ['generic', 'ueba'],
                                       'source': 'Exabeam AA', 'priority': 'medium', 'queue': '1',
                                       'description': None}}]}
