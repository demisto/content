
ASSIGNED_APPS = {'CustomFields': {
    'oktasyncedapps': """[
        {
            "ID": "0oa91f3lqpCt8Mt5u0h7",
            "Label": "pantest.local",
            "Name": "active_directory",
            "Status": "ACTIVE"
        },
        {
            "ID": "0oae6ioe81sQ64Aui0h7",
            "Label": "Smartsheet Test App",
            "Name": "paloaltonetworkstest_testapp_2",
            "Status": "ACTIVE"
        }
    ]"""
}}


def test_assigned_synced_apps():
    from AssignedAppsTableWidget import assigned_synced_apps
    args = {'indicator': ASSIGNED_APPS}
    results = assigned_synced_apps(args)
    assert results.readable_output
