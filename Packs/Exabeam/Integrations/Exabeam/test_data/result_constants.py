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
    'Exabeam.NotableAsset(val.ipAddress && val.ipAddress === obj.ipAddress)': [{
        'highestRiskScore': 150,
        'id': 'asset@lt-fweber-888-20200702',
        'entityName': 'asset',
        'entityValue': 'lt-fweber-888',
        'day': '2020-07-02T00:00:00',
        'triggeredRuleCountOpt': 15,
        'riskScoreOpt': 150.0,
        'commentId': '60195e5b130b3800075b8e27',
        'commentType': 'asset',
        'commentObjectId': 'lt-fweber-888',
        'text': 'test',
        'exaUser': 'siemplify',
        'createTime': '	2021-02-02T14:14:51.188000',
        'updateTime': '2021-02-02T14:14:51.188000',
        'edited': False,
        'HostName': 'lt-fweber-888',
        'IPAddress': '10.27.129.64',
        'AssetType': 'Windows',
        'FirstSeen': '2020-06-01T14:36:00',
        'LastSeen': '2020-07-03T23:52:00',
        'Labels': None,
        'exaUserFullname': '',
        'zone': None,
        'incidentIds': []
    }]
}
