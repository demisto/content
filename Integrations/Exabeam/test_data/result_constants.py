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
