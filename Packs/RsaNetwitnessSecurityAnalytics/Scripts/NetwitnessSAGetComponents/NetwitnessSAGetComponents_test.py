import demistomock as demisto


def test_netwitness_im_get_components(mocker):
    """
    Given:
        - response mock.
    When:
        - running NetwitnessSAGetComponents script.
    Then:
        - Ensure that the results were built correctly.
    """
    from NetwitnessSAGetComponents import netwitness_im_get_components
    entry = [{"Type": 3, "Contents": {"components": [{"some_info": {"info": "test"}}]}}]
    mocker.patch.object(demisto, 'executeCommand', return_value=entry)
    results_mock = mocker.patch.object(demisto, 'results')
    netwitness_im_get_components()
    assert results_mock.call_args[0][0]['Contents'] == [{'some_info': 'info: test'}]
