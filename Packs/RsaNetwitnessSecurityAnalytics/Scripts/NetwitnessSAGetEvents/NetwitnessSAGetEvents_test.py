import demistomock as demisto


def test_netwitness_im_get_events(mocker):
    """
    Given:
        - response mock.
    When:
        - running NetwitnessSAGetEvents script.
    Then:
        - Ensure that the results were built correctly.
    """
    from NetwitnessSAGetEvents import netwitness_im_get_events
    entry = [{"Type": 3, "Contents": {"events": {"time": 0, "meta": [{"name": "name", "value": "value"}]}}}]
    mocker.patch.object(demisto, 'executeCommand', return_value=entry)
    results_mock = mocker.patch.object(demisto, 'results')
    netwitness_im_get_events()
    assert results_mock.call_args[0][0]['Contents'] == [{'meta.name': 'value', 'time': '1970-01-01 00:00:00'}]
