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
