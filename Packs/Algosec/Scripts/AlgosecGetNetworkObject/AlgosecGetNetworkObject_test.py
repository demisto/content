import demistomock as demisto


def test_algosec_get_network_object(mocker):
    """
    Given:
        - response mock.
    When:
        - running AlgosecGetNetworkObject script.
    Then:
        - Ensure that the results were built correctly.
    """
    from AlgosecGetNetworkObject import algosec_get_network_object
    ticket = [{"Type": 3, "Contents": {"some_info": {"info": "test"}}}]
    mocker.patch.object(demisto, 'executeCommand', return_value=ticket)
    results_mock = mocker.patch.object(demisto, 'results')
    algosec_get_network_object()
    assert results_mock.call_args[0][0]['Contents'] == [{'some_info': 'info: test'}]
