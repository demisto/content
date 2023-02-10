import demistomock as demisto


def test_netwitness_im_list_incidents(mocker):
    """
    Given:
        - response mock.
    When:
        - running NetwitnessSAListIncidents script.
    Then:
        - Ensure that the results were built correctly.
    """
    from NetwitnessSAListIncidents import netwitness_im_list_incidents
    entry = [{"Type": 3, "Contents": {"incidents": {"lastUpdated": 0, "firstAlertTime": 0, "created": 0}}}]
    mocker.patch.object(demisto, 'executeCommand', return_value=entry)
    results_mock = mocker.patch.object(demisto, 'results')
    netwitness_im_list_incidents()
    expected = [{'created': '1970-01-01 00:00:00',
                 'firstAlertTime': '1970-01-01 00:00:00',
                 'lastUpdated': '1970-01-01 00:00:00'}]
    assert results_mock.call_args[0][0]['Contents'] == expected
